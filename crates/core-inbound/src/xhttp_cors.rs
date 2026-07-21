//! Explicit CORS policy for configured XHTTP listeners.

use std::collections::HashSet;

use core_outbound::proto::xhttp::{Config, config::PLACEMENT_COOKIE};
use http::{
    HeaderMap, HeaderValue, Method, Request,
    header::{
        ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS,
        ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_REQUEST_HEADERS,
        ACCESS_CONTROL_REQUEST_METHOD, ORIGIN, VARY,
    },
};

#[derive(Debug, Clone)]
pub(crate) enum CorsPolicy {
    /// Preserve pinned Xray's permissive behavior for the low-level protocol
    /// server API. Configured Raw listeners select this when `cors-origins` is
    /// omitted; an explicitly empty list still disables CORS.
    XrayCompatible,
    Disabled,
    Any,
    Origins(HashSet<String>),
}

impl CorsPolicy {
    pub(crate) fn configured(origins: &[String]) -> Self {
        match origins {
            [] => Self::Disabled,
            [origin] if origin == "*" => Self::Any,
            origins => Self::Origins(origins.iter().cloned().collect()),
        }
    }

    pub(crate) fn apply<B>(&self, config: &Config, request: &Request<B>, headers: &mut HeaderMap) {
        let credentials = uses_cookie_placement(config);
        let request_origin = request.headers().get(ORIGIN);
        let (allowed_origin, vary_origin) = match self {
            Self::Disabled => return,
            Self::XrayCompatible => (
                request_origin
                    .cloned()
                    .unwrap_or_else(|| HeaderValue::from_static("*")),
                request_origin.is_some(),
            ),
            Self::Any if !credentials => (HeaderValue::from_static("*"), false),
            Self::Any => {
                let Some(origin) = request_origin.and_then(canonical_origin_value) else {
                    return;
                };
                (origin, true)
            }
            Self::Origins(origins) => {
                let Some(origin) = request_origin.and_then(canonical_origin) else {
                    return;
                };
                if !origins.contains(&origin) {
                    return;
                }
                let Ok(origin) = HeaderValue::from_str(&origin) else {
                    return;
                };
                (origin, true)
            }
        };

        headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, allowed_origin);
        if credentials {
            headers.insert(
                ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
        }
        if vary_origin {
            headers.append(VARY, HeaderValue::from_static("Origin"));
        }
        if request.method() == Method::OPTIONS {
            headers.insert(
                ACCESS_CONTROL_ALLOW_METHODS,
                request
                    .headers()
                    .get(ACCESS_CONTROL_REQUEST_METHOD)
                    .cloned()
                    .unwrap_or_else(|| HeaderValue::from_static("*")),
            );
            headers.insert(
                ACCESS_CONTROL_ALLOW_HEADERS,
                request
                    .headers()
                    .get(ACCESS_CONTROL_REQUEST_HEADERS)
                    .cloned()
                    .unwrap_or_else(|| HeaderValue::from_static("*")),
            );
            headers.append(
                VARY,
                HeaderValue::from_static(
                    "Access-Control-Request-Method, Access-Control-Request-Headers",
                ),
            );
        }
    }
}

fn uses_cookie_placement(config: &Config) -> bool {
    config.normalized_session_placement() == PLACEMENT_COOKIE
        || config.normalized_seq_placement() == PLACEMENT_COOKIE
        || config.x_padding_placement == PLACEMENT_COOKIE
        || config.normalized_uplink_data_placement() == PLACEMENT_COOKIE
}

fn canonical_origin_value(value: &HeaderValue) -> Option<HeaderValue> {
    HeaderValue::from_str(&canonical_origin(value)?).ok()
}

fn canonical_origin(value: &HeaderValue) -> Option<String> {
    let value = value.to_str().ok()?;
    let parsed = url::Url::parse(value).ok()?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    Some(parsed.origin().ascii_serialization())
}

#[cfg(test)]
mod tests {
    use http::header::{ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_ORIGIN};

    use super::*;

    fn request(origin: Option<&str>, preflight: bool) -> Request<()> {
        let mut request = Request::builder()
            .method(if preflight {
                Method::OPTIONS
            } else {
                Method::GET
            })
            .uri("https://server.example/x")
            .body(())
            .unwrap();
        if let Some(origin) = origin {
            request
                .headers_mut()
                .insert(ORIGIN, HeaderValue::from_str(origin).unwrap());
        }
        if preflight {
            request.headers_mut().insert(
                ACCESS_CONTROL_REQUEST_METHOD,
                HeaderValue::from_static("POST"),
            );
            request.headers_mut().insert(
                ACCESS_CONTROL_REQUEST_HEADERS,
                HeaderValue::from_static("X-Session"),
            );
        }
        request
    }

    #[test]
    fn disabled_policy_emits_no_cors_headers() {
        let mut headers = HeaderMap::new();
        CorsPolicy::configured(&[]).apply(
            &Config::default(),
            &request(Some("https://app.example"), true),
            &mut headers,
        );
        assert!(!headers.contains_key(ACCESS_CONTROL_ALLOW_ORIGIN));
    }

    #[test]
    fn wildcard_without_cookies_stays_wildcard() {
        let mut headers = HeaderMap::new();
        CorsPolicy::configured(&["*".into()]).apply(
            &Config::default(),
            &request(Some("https://app.example"), true),
            &mut headers,
        );
        assert_eq!(headers[ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        assert!(!headers.contains_key(ACCESS_CONTROL_ALLOW_CREDENTIALS));
        assert_eq!(headers[ACCESS_CONTROL_ALLOW_METHODS], "POST");
        assert_eq!(headers[ACCESS_CONTROL_ALLOW_HEADERS], "X-Session");
    }

    #[test]
    fn wildcard_with_cookies_reflects_a_canonical_origin_and_varies() {
        let mut config = Config::default();
        config.session_placement = PLACEMENT_COOKIE.into();
        let mut headers = HeaderMap::new();
        CorsPolicy::configured(&["*".into()]).apply(
            &config,
            &request(Some("HTTPS://App.Example:443"), false),
            &mut headers,
        );
        assert_eq!(headers[ACCESS_CONTROL_ALLOW_ORIGIN], "https://app.example");
        assert_eq!(headers[ACCESS_CONTROL_ALLOW_CREDENTIALS], "true");
        assert_eq!(headers[VARY], "Origin");
    }

    #[test]
    fn allowlist_rejects_other_origins_and_matches_canonical_form() {
        let policy = CorsPolicy::configured(&["https://app.example".into()]);
        let mut rejected = HeaderMap::new();
        policy.apply(
            &Config::default(),
            &request(Some("https://other.example"), false),
            &mut rejected,
        );
        assert!(!rejected.contains_key(ACCESS_CONTROL_ALLOW_ORIGIN));

        let mut allowed = HeaderMap::new();
        policy.apply(
            &Config::default(),
            &request(Some("HTTPS://App.Example:443"), false),
            &mut allowed,
        );
        assert_eq!(allowed[ACCESS_CONTROL_ALLOW_ORIGIN], "https://app.example");
    }

    #[test]
    fn xray_compatible_mode_preserves_origin_reflection() {
        let mut headers = HeaderMap::new();
        CorsPolicy::XrayCompatible.apply(
            &Config::default(),
            &request(Some("https://legacy.example"), false),
            &mut headers,
        );
        assert_eq!(
            headers[ACCESS_CONTROL_ALLOW_ORIGIN],
            "https://legacy.example"
        );
    }

    #[test]
    fn xray_compatible_without_origin_uses_wildcard_and_cookie_credentials() {
        let mut config = Config::default();
        config.session_placement = PLACEMENT_COOKIE.into();
        let mut headers = HeaderMap::new();
        CorsPolicy::XrayCompatible.apply(&config, &request(None, true), &mut headers);
        assert_eq!(headers[ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        assert_eq!(headers[ACCESS_CONTROL_ALLOW_CREDENTIALS], "true");
        assert_eq!(headers[ACCESS_CONTROL_ALLOW_METHODS], "POST");
        assert_eq!(headers[ACCESS_CONTROL_ALLOW_HEADERS], "X-Session");
    }
}
