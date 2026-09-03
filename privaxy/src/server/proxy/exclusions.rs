use crate::configuration::MitmMode;
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
                    WildMatch::new(&pattern.to_lowercase())
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
        // keep your existing list unchanged here
    ]
}

#[derive(Debug, Clone)]
pub struct LocalExclusionStore {
    patterns: Arc<RwLock<WildMatchCollection>>,
    mode: MitmMode,
}

impl LocalExclusionStore {
    pub fn new(patterns: Vec<String>, mode: MitmMode) -> Self {
        Self {
            patterns: Arc::new(RwLock::new(
                WildMatchCollection::new(patterns),
            )),
            mode,
        }
    }

    pub fn replace_exclusions(&mut self, patterns: Vec<String>) {
        *self.patterns.write().unwrap() =
            WildMatchCollection::new(patterns);
    }

    /// Returns true when this host should be MITM inspected.
    ///
    /// Inclusion mode:
    ///     match     -> MITM + filtering
    ///     no match  -> blind tunnel
    ///
    /// Exclusion mode:
    ///     match     -> blind tunnel
    ///     no match  -> MITM + filtering
    pub fn contains(&self, host: &str) -> bool {
        let matched = self.patterns.read().unwrap().is_match(host);

        match self.mode {
            MitmMode::Inclusion => matched,
            MitmMode::Exclusion => !matched,
        }
    }
}
