use super::{exclusions::LocalExclusionStore, serve::serve};
use crate::{
    blocker::AdblockRequester, cert::CertCache, configuration::DohConfig, statistics::Statistics,
    Event,
};
use http::uri::{Authority, Scheme};
use hyper::{
    client::HttpConnector, http, server::conn::Http, service::service_fn, upgrade::Upgraded, Body,
    Method, Request, Response,
};
use hyper_rustls::HttpsConnector;
use std::{net::IpAddr, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::broadcast,
};
use tokio_rustls::TlsAcceptor;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve_mitm_session(
    adblock_requester: AdblockRequester,
    hyper_client: hyper::Client<HttpsConnector<HttpConnector>>,
    client: reqwest::Client,
    req: Request<Body>,
    cert_cache: CertCache,
    broadcast_tx: broadcast::Sender<Event>,
    statistics: Statistics,
    client_ip_address: IpAddr,
    local_exclusion_store: LocalExclusionStore,
    doh_config: DohConfig,
    scriptlet_debug_logging: bool,
) -> Result<Response<Body>, hyper::Error> {
    let authority = match req.uri().authority().cloned() {
        Some(authority) => authority,
        None => {
            let mut response = Response::new(Body::empty());
            *response.status_mut() = http::StatusCode::BAD_REQUEST;

            log::warn!("Received a request without proper authority, sending bad request");

            return Ok(response);
        }
    };

    if Method::CONNECT == req.method() {
        let server_configuration =
            Arc::new(cert_cache.get(authority.clone()).await.server_configuration);

        tokio::task::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(mut upgraded) => {
                    // Inclusion list logic:
                    // true  -> MITM + filtering
                    // false -> blind tunnel
                    let should_mitm = local_exclusion_store.contains(authority.host());

                    if !should_mitm {
                        let _result = tunnel(&mut upgraded, &authority).await;

                        return;
                    }

                    let http = Http::new();

                    match TlsAcceptor::from(server_configuration)
                        .accept(upgraded)
                        .await
                    {
                        Ok(tls_stream) => {
                            let _result = http
                                .serve_connection(
                                    tls_stream,
                                    service_fn(move |req| {
                                        serve(
                                            adblock_requester.clone(),
                                            req,
                                            hyper_client.clone(),
                                            client.clone(),
                                            authority.clone(),
                                            Scheme::HTTPS,
                                            broadcast_tx.clone(),
                                            statistics.clone(),
                                            client_ip_address,
                                            doh_config.clone(),
                                            scriptlet_debug_logging,
                                        )
                                    }),
                                )
                                .with_upgrades()
                                .await;
                        }
                        Err(error) => {
                            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                                log::warn!(
                                    "Unable to perform handshake for host: {}. \
                                     Consider removing it from the MITM inclusion list.",
                                    authority
                                );
                            }
                        }
                    }
                }
                Err(e) => log::error!("upgrade error: {}", e),
            }
        });

        Ok(Response::new(Body::empty()))
    } else if !local_exclusion_store.contains(authority.host())
        && req.headers().contains_key(http::header::UPGRADE)
    {
        // A host outside the MITM inclusion list performing a protocol upgrade
        // over plain HTTP. Blind tunnel it.
        tunnel_http_upgrade(req, authority).await
    } else {
        if is_opaque_upgrade(req.headers()) {
            log::warn!(
                "Proxying opaque protocol-upgrade traffic (MMTLS?) for {}; \
                 this is unlikely to work through the MITM proxy. \
                 Consider adding the host to the MITM inclusion list.",
                authority
            );
        }

        serve(
            adblock_requester,
            req,
            hyper_client.clone(),
            client.clone(),
            authority,
            Scheme::HTTP,
            broadcast_tx,
            statistics,
            client_ip_address,
            doh_config,
            scriptlet_debug_logging,
        )
        .await
    }
}
/// An HTTP `Upgrade` request whose target protocol is something other than
/// WebSocket (or h2c) — e.g. WeChat's MMTLS long-link. The proxy can't do
/// anything useful with such a protocol, and its hyper-based upgrade bridge
/// can't carry it; these are only handled correctly by blind-tunneling, which
/// requires the host to be outside the MITM inclusion list.
fn is_opaque_upgrade(headers: &http::HeaderMap) -> bool {
    headers
        .get(http::header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value.split(',').all(|token| {
                let name = token.trim().split('/').next().unwrap_or("").trim();
                !name.eq_ignore_ascii_case("websocket") && !name.eq_ignore_ascii_case("h2c")
            })
        })
        .unwrap_or(false)
}

/// Blind-tunnel a plain-HTTP protocol upgrade to a host outside the inclusion
/// list. The proxied request carries an absolute-form URI; we replay it to the
/// upstream in origin-form over a raw socket, return our own `101` to the
/// client, and pipe the opaque bytes both ways.
async fn tunnel_http_upgrade(
    req: Request<Body>,
    authority: Authority,
) -> Result<Response<Body>, hyper::Error> {
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let mut head = format!("{} {} HTTP/1.1\r\n", req.method(), path);

    for (name, value) in req.headers() {
        head.push_str(name.as_str());
        head.push_str(": ");
        head.push_str(&String::from_utf8_lossy(value.as_bytes()));
        head.push_str("\r\n");
    }

    head.push_str("\r\n");

    let upgrade_value = req.headers().get(http::header::UPGRADE).cloned();

    tokio::spawn(async move {
        match bridge_http_upgrade(req, head, &authority).await {
            Ok(()) => log::debug!("HTTP-upgrade tunnel closed for {}", authority),
            Err(e) => log::warn!("HTTP-upgrade tunnel for {} failed: {}", authority, e),
        }
    });

    let mut response = Response::new(Body::empty());

    *response.status_mut() = http::StatusCode::SWITCHING_PROTOCOLS;

    response.headers_mut().insert(
        http::header::CONNECTION,
        http::HeaderValue::from_static("upgrade"),
    );

    if let Some(upgrade) = upgrade_value {
        response
            .headers_mut()
            .insert(http::header::UPGRADE, upgrade);
    }

    Ok(response)
}

/// Upstream half of `tunnel_http_upgrade`.
async fn bridge_http_upgrade(
    req: Request<Body>,
    head: String,
    authority: &Authority,
) -> std::io::Result<()> {
    let host = authority.host();
    let port = authority.port_u16().unwrap_or(80);

    let mut client = hyper::upgrade::on(req)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    let mut upstream = TcpStream::connect((host, port)).await?;

    upstream.write_all(head.as_bytes()).await?;

    let leftover = read_past_response_headers(&mut upstream).await?;

    if !leftover.is_empty() {
        client.write_all(&leftover).await?;
    }

    pipe(&mut client, &mut upstream).await
}

/// Read until the end of the upstream HTTP response headers and return any
/// payload bytes that followed.
async fn read_past_response_headers(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    const HEADER_CAP: usize = 64 * 1024;

    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];

    loop {
        let n = stream.read(&mut chunk).await?;

        if n == 0 {
            return Ok(buf);
        }

        buf.extend_from_slice(&chunk[..n]);

        if let Some(pos) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
            return Ok(buf.split_off(pos + 4));
        }

        if buf.len() > HEADER_CAP {
            return Ok(buf);
        }
    }
}

async fn tunnel(upgraded: &mut Upgraded, authority: &Authority) -> std::io::Result<()> {
    let mut server = TcpStream::connect(authority.to_string()).await?;

    log::debug!("Started tunneling host: {}", authority);

    pipe(upgraded, &mut server).await
}

/// Pipe two duplex streams in both directions until either side closes.
async fn pipe<A, B>(a: &mut A, b: &mut B) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    tokio::io::copy_bidirectional(a, b).await?;

    Ok(())
}
