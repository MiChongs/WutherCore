/// Resolved Xray gRPC service and method paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcMethodPaths {
    pub service: String,
    pub tun: String,
    pub tun_multi: String,
}

impl GrpcMethodPaths {
    pub fn tun_path(&self) -> String {
        format!("/{}/{}", self.service, self.tun)
    }

    pub fn tun_multi_path(&self) -> String {
        format!("/{}/{}", self.service, self.tun_multi)
    }
}

/// Reproduce Xray's `getServiceName`, `getTunStreamName` and
/// `getTunMultiStreamName` behavior, including the custom `/service/method`
/// and `/service/tun|tun-multi` spellings.
pub fn grpc_method_paths(raw: &str) -> GrpcMethodPaths {
    if !raw.starts_with('/') {
        return GrpcMethodPaths {
            service: go_path_escape(raw),
            tun: "Tun".into(),
            tun_multi: "TunMulti".into(),
        };
    }

    let raw_last_slash = raw.rfind('/').unwrap_or(0);
    let service_last_slash = raw_last_slash.max(1);
    let service = raw[1..service_last_slash]
        .split('/')
        .map(go_path_escape)
        .collect::<Vec<_>>()
        .join("/");
    let ending = &raw[raw_last_slash + 1..];
    let mut methods = ending.split('|');
    let tun = go_path_escape(methods.next().unwrap_or_default());
    let tun_multi = methods
        .next()
        .map(go_path_escape)
        .unwrap_or_else(|| tun.clone());

    GrpcMethodPaths {
        service,
        tun,
        tun_multi,
    }
}

/// Equivalent to Go `net/url.PathEscape` in `encodePathSegment` mode.
fn go_path_escape(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        let allowed = byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_' | b'.' | b'~' | b'$' | b'&' | b'+' | b':' | b'=' | b'@'
            );
        if allowed {
            encoded.push(char::from(byte));
        } else {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            encoded.push('%');
            encoded.push(char::from(HEX[(byte >> 4) as usize]));
            encoded.push(char::from(HEX[(byte & 0x0f) as usize]));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_style_uses_default_methods() {
        assert_eq!(
            grpc_method_paths("Gun Service/一"),
            GrpcMethodPaths {
                service: "Gun%20Service%2F%E4%B8%80".into(),
                tun: "Tun".into(),
                tun_multi: "TunMulti".into(),
            }
        );
    }

    #[test]
    fn custom_path_matches_xray_server_and_client_forms() {
        let server = grpc_method_paths("/alpha/beta/Tun X|Multi X");
        assert_eq!(server.service, "alpha/beta");
        assert_eq!(server.tun, "Tun%20X");
        assert_eq!(server.tun_multi, "Multi%20X");
        assert_eq!(server.tun_path(), "/alpha/beta/Tun%20X");
        assert_eq!(server.tun_multi_path(), "/alpha/beta/Multi%20X");

        let client = grpc_method_paths("/alpha/beta/OnlyMulti");
        assert_eq!(client.tun, "OnlyMulti");
        assert_eq!(client.tun_multi, "OnlyMulti");
    }

    #[test]
    fn root_custom_path_follows_xray_empty_service_rule() {
        let paths = grpc_method_paths("/Tun");
        assert_eq!(paths.service, "");
        assert_eq!(paths.tun_path(), "//Tun");
    }
}
