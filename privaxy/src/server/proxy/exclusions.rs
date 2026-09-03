use lazy_static::lazy_static;
use std::sync::{Arc, RwLock};
use wildmatch::WildMatch;

#[derive(Debug, Clone)]
struct WildMatchCollection(Vec<WildMatch>);

impl WildMatchCollection {
    fn new(patterns: Vec<String>) -> Self {
        Self(
            patterns
                .into_iter()
                .map(|pattern| {
                    let pattern_lowercase = pattern.to_lowercase();
                    WildMatch::new(&pattern_lowercase)
                })
                .collect(),
        )
    }

    fn is_match(&self, element: &str) -> bool {
        let lowercase_element = element.to_lowercase();

        self.0
            .iter()
            .any(|pattern| pattern.matches(&lowercase_element))
    }
}

lazy_static! {
    static ref DEFAULT_EXCLUSIONS: WildMatchCollection = {
        let mut exclusions = Vec::new();

        exclusions.push(String::from("*.apple.com"));
        exclusions.push(String::from("static.ips.apple.com"));
        exclusions.push(String::from("*.push.apple.com"));
        exclusions.push(String::from("setup.icloud.com"));
        exclusions.push(String::from("*.business.apple.com"));
        exclusions.push(String::from("*.school.apple.com"));
        exclusions.push(String::from("upload.appleschoolcontent.com"));
        exclusions.push(String::from("ws-ee-maidsvc.icloud.com"));
        exclusions.push(String::from("itunes.com"));
        exclusions.push(String::from("appldnld.apple.com.edgesuite.net"));
        exclusions.push(String::from("*.itunes.apple.com"));
        exclusions.push(String::from("updates-http.cdn-apple.com"));
        exclusions.push(String::from("updates.cdn-apple.com"));
        exclusions.push(String::from("*.apps.apple.com"));
        exclusions.push(String::from("*.mzstatic.com"));
        exclusions.push(String::from("*.appattest.apple.com"));
        exclusions.push(String::from("doh.dns.apple.com"));
        exclusions.push(String::from("appleid.cdn-apple.com"));
        exclusions.push(String::from("*.apple-cloudkit.com"));
        exclusions.push(String::from("*.apple-livephotoskit.com"));
        exclusions.push(String::from("*.apzones.com"));
        exclusions.push(String::from("*.cdn-apple.com"));
        exclusions.push(String::from("*.gc.apple.com"));
        exclusions.push(String::from("*.icloud.com"));
        exclusions.push(String::from("*.icloud.com.cn"));
        exclusions.push(String::from("*.icloud.apple.com"));
        exclusions.push(String::from("*.icloud-content.com"));
        exclusions.push(String::from("*.iwork.apple.com"));
        exclusions.push(String::from("mask.icloud.com"));
        exclusions.push(String::from("mask-h2.icloud.com"));
        exclusions.push(String::from("mask-api.icloud.com"));
        exclusions.push(String::from("devimages-cdn.apple.com"));
        exclusions.push(String::from("download.developer.apple.com"));

        WildMatchCollection::new(exclusions)
    };
}

pub fn recommended_exclusions() -> &'static [&'static str] {
    &[
        "openai.com",
        "*.openai.com",
        "chatgpt.com",
        "*.chatgpt.com",
        "claude.ai",
        "*.claude.ai",
        "openrouter.ai",
        "*.openrouter.ai",
        "awswaf.com",
        "*.awswaf.com",
        "check.ddos-guard.net",
        "okta.com",
        "*.okta.com",
        "capitalone.com",
        "*.capitalone.com",
        "americanexpress.com",
        "*.americanexpress.com",
        "experian.com",
        "*.experian.com",
        "marcus.com",
        "*.marcus.com",
        "fidelity.com",
        "*.fidelity.com",
        "fmr.com",
        "*.fmr.com",
        "robinhood.com",
        "*.robinhood.com",
        "webull.com",
        "*.webull.com",
        "webullfintech.com",
        "*.webullfintech.com",
        "tradingview.com",
        "*.tradingview.com",
        "stripecdn.com",
        "*.stripecdn.com",
        "squarecdn.com",
        "*.squarecdn.com",
        "cashappapi.com",
        "*.cashappapi.com",
        "mega.nz",
        "*.mega.nz",
        "mega.co.nz",
        "*.mega.co.nz",
        "homedepot.com",
        "*.homedepot.com",
        "pizzahut.com",
        "*.pizzahut.com",
        "amazon.com",
        "*.amazon.com",
        "amazonaws.com",
        "*.amazonaws.com",
        "amazontrust.com",
        "*.amazontrust.com",
        "instagram.com",
        "*.instagram.com",
        "facebook.com",
        "*.facebook.com",
        "snapchat.com",
        "*.snapchat.com",
        "signal.org",
        "*.signal.org",
        "proton.me",
        "*.proton.me",
        "protonmail.com",
        "*.protonmail.com",
        "twitter.com",
        "*.twitter.com",
        "x.com",
        "*.x.com",
        "discord.com",
        "*.discord.com",
        "discord.gg",
        "*.discord.gg",
        "discordapp.com",
        "*.discordapp.com",
        "t-mobile.com",
        "*.t-mobile.com",
        "fedex.com",
        "*.fedex.com",
        "ups.com",
        "*.ups.com",
        "privateinternetaccess.com",
        "*.privateinternetaccess.com",
        "microsoft.com",
        "*.microsoft.com",
        "microsoftonline.com",
        "*.microsoftonline.com",
        "live.com",
        "*.live.com",
        "xboxlive.com",
        "*.xboxlive.com",
        "xbox.com",
        "*.xbox.com",
        "clients1.google.com",
        "clients2.google.com",
        "clients3.google.com",
        "clients4.google.com",
        "clients5.google.com",
        "steam.com",
        "*.steam.com",
        "steamcommunity.com",
        "*.steamcommunity.com",
        "steampowered.com",
        "*.steampowered.com",
        "steamcontent.com",
        "*.steamcontent.com",
        "steamstatic.com",
        "*.steamstatic.com",
        "tidal.com",
        "*.tidal.com",
        "soundcloud.com",
        "*.soundcloud.com",
        "smsl-audio.com",
        "*.smsl-audio.com",
        "sourceforge.net",
        "*.sourceforge.net",
        "cdnjs.cloudflare.com",
        "challenges.cloudflare.com",
        "digicert.com",
        "*.digicert.com",
        "verisign.com",
        "*.verisign.com",
        "github.com",
        "*.github.com",
        "githubassets.com",
        "*.githubassets.com",
        "uber.com",
        "*.uber.com",
        "bitcoingold.org",
        "*.bitcoingold.org",
        "btcgpu.org",
        "*.btcgpu.org",
        "newsedge.net",
        "*.newsedge.net",
    ]
}

#[derive(Debug, Clone)]
pub struct LocalExclusionStore(Arc<RwLock<WildMatchCollection>>);

impl LocalExclusionStore {
    pub fn new(inclusions: Vec<String>) -> Self {
        let collection = WildMatchCollection::new(inclusions);
        Self(Arc::new(RwLock::new(collection)))
    }

    pub fn replace_exclusions(&mut self, inclusions: Vec<String>) {
        let new_store = LocalExclusionStore::new(inclusions);

        *self.0.write().unwrap() =
            new_store.0.read().unwrap().clone();
    }

    /// In this fork the old exclusion list becomes an inclusion list.
    ///
    /// true  -> MITM + filtering
    /// false -> blind tunnel
    pub fn contains(&self, host: &str) -> bool {
        self.0.read().unwrap().is_match(host)
    }
}
