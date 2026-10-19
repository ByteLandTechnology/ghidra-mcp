// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! The absolute upload URL for one HTTP request.

use axum::http::{header, uri::Authority, HeaderMap, Uri};

/// Returns the upload URL from proxy headers, an MCP Referer, or the request address.
pub fn request_url(uri: &Uri, headers: &HeaderMap) -> Option<String> {
    let forwarded = first_header(headers, "forwarded").and_then(forwarded_address);
    let proxy_host = forwarded
        .as_ref()
        .and_then(|address| address.0)
        .or_else(|| first_header(headers, "x-forwarded-host"));
    let proxy_scheme = forwarded
        .as_ref()
        .and_then(|address| address.1)
        .or_else(|| first_header(headers, "x-forwarded-proto"));
    let referer = single_header(headers, header::REFERER.as_str()).and_then(mcp_referer);
    let proxy_authority = match proxy_host {
        Some(host) => Some(valid_authority(host)?),
        None => None,
    };
    let authority = proxy_authority
        .or_else(|| referer.as_ref().and_then(Uri::authority).cloned())
        .or_else(|| uri.authority().cloned())
        .or_else(|| single_header(headers, "host").and_then(valid_authority))?;
    let referer = referer.filter(|referer| {
        referer
            .authority()
            .is_some_and(|value| value.as_str().eq_ignore_ascii_case(authority.as_str()))
    });
    let scheme = proxy_scheme
        .or_else(|| referer.as_ref().and_then(Uri::scheme_str))
        .or_else(|| uri.scheme_str())
        .unwrap_or("http");
    let scheme = http_scheme(scheme)?;
    let base = if let Some(prefix) = first_header(headers, "x-forwarded-prefix") {
        let prefix = prefix.trim_end_matches('/');
        if !prefix.is_empty() && !valid_prefix(prefix) {
            return None;
        }
        format!("{prefix}{}", mcp_parent(uri.path())?)
    } else {
        mcp_parent(referer.as_ref().map_or_else(|| uri.path(), Uri::path))?.to_string()
    };
    Some(format!("{scheme}://{authority}{base}/upload"))
}

/// Returns an HTTP scheme in lowercase letters.
fn http_scheme(value: &str) -> Option<&'static str> {
    if value.eq_ignore_ascii_case("http") {
        Some("http")
    } else if value.eq_ignore_ascii_case("https") {
        Some("https")
    } else {
        None
    }
}

/// Returns an authority without user information or an invalid port.
fn valid_authority(value: &str) -> Option<Authority> {
    let authority: Authority = value.parse().ok()?;
    if value.contains(['@', '\\', '%']) || authority.host().is_empty() {
        return None;
    }
    let port = value.strip_prefix(authority.host())?;
    if !port.is_empty() {
        port.strip_prefix(':')?.parse::<u16>().ok()?;
    }
    Some(authority)
}

/// Returns an absolute HTTP Referer only when its path names the MCP endpoint.
fn mcp_referer(value: &str) -> Option<Uri> {
    if value.contains('#') {
        return None;
    }
    let uri: Uri = value.parse().ok()?;
    http_scheme(uri.scheme_str()?)?;
    valid_authority(uri.authority()?.as_str())?;
    let prefix = mcp_parent(uri.path())?;
    if !prefix.is_empty() && !valid_prefix(prefix) {
        return None;
    }
    Some(uri)
}

/// Returns the path before the final MCP segment.
fn mcp_parent(path: &str) -> Option<&str> {
    path.trim_end_matches('/').strip_suffix("/mcp")
}

/// Returns `true` for a path prefix without a query, fragment, or parent segment.
fn valid_prefix(value: &str) -> bool {
    value.starts_with('/')
        && !value.contains(['?', '#', '\\'])
        && !value.contains("//")
        && !value.split('/').any(|part| {
            let part = part.to_ascii_lowercase().replace("%2e", ".");
            part == "." || part == ".."
        })
        && value.parse::<Uri>().is_ok_and(|uri| uri.path() == value)
}

/// Returns the host and protocol from the first Forwarded element.
fn forwarded_address(value: &str) -> Option<(Option<&str>, Option<&str>)> {
    let mut host = None;
    let mut proto = None;
    for field in value.split(';') {
        let (name, value) = field.trim().split_once('=')?;
        let value = value.trim();
        let value = if value.starts_with('"') {
            value.strip_prefix('"')?.strip_suffix('"')?
        } else {
            value
        };
        if name.eq_ignore_ascii_case("host") {
            if host.replace(value).is_some() {
                return None;
            }
        } else if name.eq_ignore_ascii_case("proto") && proto.replace(value).is_some() {
            return None;
        }
    }
    Some((host, proto))
}

/// Returns the first value from one proxy header.
fn first_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)?
        .to_str()
        .ok()?
        .split(',')
        .next()
        .map(str::trim)
}

/// Returns a header that occurs exactly one time.
fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Resolves a test request with the given headers.
    fn resolve(headers: &[(&str, &str)]) -> Option<String> {
        let mut values = HeaderMap::new();
        values.insert(header::HOST, "127.0.0.1:18489".parse().unwrap());
        for (name, value) in headers {
            values.append(
                name.parse::<header::HeaderName>().unwrap(),
                value.parse().unwrap(),
            );
        }
        request_url(&"/mcp?sessionId=test".parse().unwrap(), &values)
    }

    /// Checks direct requests, proxy addresses, path prefixes, and IPv6 addresses.
    #[test]
    fn resolves_request_and_proxy_addresses() {
        let cases: &[(&[(&str, &str)], &str)] = &[
            (&[], "http://127.0.0.1:18489/upload"),
            (
                &[("referer", "https://public.example/ghidra/mcp?secret=value")],
                "https://public.example/ghidra/upload",
            ),
            (
                &[
                    ("x-forwarded-host", "public.example:8443, internal.example"),
                    ("x-forwarded-proto", "https, http"),
                    ("x-forwarded-prefix", "/ghidra/"),
                    ("referer", "https://client.example/chat"),
                ],
                "https://public.example:8443/ghidra/upload",
            ),
            (
                &[
                    (
                        "forwarded",
                        "for=192.0.2.1;host=public.example;proto=https, proto=http",
                    ),
                    ("x-forwarded-host", "other.example"),
                    ("x-forwarded-proto", "http"),
                    ("referer", "https://public.example/prefix/mcp/"),
                ],
                "https://public.example/prefix/upload",
            ),
            (
                &[("forwarded", "host=\"[2001:db8::1]:8443\";proto=\"https\"")],
                "https://[2001:db8::1]:8443/upload",
            ),
            (
                &[
                    ("forwarded", "host=public.example;proto=https"),
                    ("forwarded", "host=internal.example;proto=http"),
                ],
                "https://public.example/upload",
            ),
        ];
        for (headers, expected) in cases {
            assert_eq!(resolve(headers).as_deref(), Some(*expected), "{headers:?}");
        }
    }

    /// Makes sure that an unrelated or invalid Referer does not set the upload address.
    #[test]
    fn ignores_non_mcp_referers() {
        for referer in [
            "https://client.example/",
            "https://client.example/chat",
            "/prefix/mcp",
            "ftp://public.example/mcp",
            "https://user:password@public.example/mcp",
            "https://public.example:65536/mcp",
            "https://public.example:invalid/mcp",
            "https://public.example/mcp#fragment",
            "not a URI",
        ] {
            assert_eq!(
                resolve(&[("referer", referer)]).as_deref(),
                Some("http://127.0.0.1:18489/upload"),
                "{referer}"
            );
        }
        assert_eq!(
            resolve(&[
                ("x-forwarded-host", "public.example"),
                ("x-forwarded-proto", "https"),
                ("referer", "https://other.example/wrong/mcp"),
            ])
            .as_deref(),
            Some("https://public.example/upload")
        );
        assert_eq!(
            resolve(&[
                ("referer", "https://first.example/mcp"),
                ("referer", "https://second.example/mcp"),
            ])
            .as_deref(),
            Some("http://127.0.0.1:18489/upload")
        );
    }

    /// Makes sure that invalid prefixes and protocols keep the relative URL.
    #[test]
    fn refuses_invalid_proxy_paths_and_protocols() {
        for prefix in [
            "relative",
            "//other.example",
            "/a/../b",
            "/%2e%2e",
            "/a?b",
            "/a#b",
        ] {
            assert_eq!(resolve(&[("x-forwarded-prefix", prefix)]), None, "{prefix}");
        }
        assert_eq!(resolve(&[("x-forwarded-proto", "javascript")]), None);
        assert_eq!(
            resolve(&[("x-forwarded-proto", "https://other.example")]),
            None
        );
        for host in [
            "user@public.example",
            "public.example:65536",
            "public.example:invalid",
        ] {
            assert_eq!(resolve(&[("x-forwarded-host", host)]), None, "{host}");
        }
    }
}
