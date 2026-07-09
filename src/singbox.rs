// Xray config to sing-box config conversion; a logical port of Happwner's SingBoxConverter.kt.

use crate::json::{parse_whole, Json};
use std::collections::{BTreeSet, HashMap, HashSet};

// .srs rule-set URL templates written into the sing-box config; sing-box fetches them at runtime.
const GEOSITE_URL_TEMPLATE: &str = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/{name}.srs";
const GEOIP_URL_TEMPLATE: &str = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/{name}.srs";

fn is_utls_fp(s: &str) -> bool {
    matches!(
        s,
        "chrome" | "firefox" | "edge" | "safari" | "360" | "qq" | "ios" | "android" | "random" | "randomized"
    )
}

fn is_xray_transport_ok(s: &str) -> bool {
    matches!(s, "tcp" | "raw" | "" | "ws" | "grpc" | "http" | "h2" | "httpupgrade" | "quic")
}

fn is_xray_security_ok(s: &str) -> bool {
    matches!(s, "" | "none" | "tls" | "reality")
}

fn is_xray_proxy_protocol(s: &str) -> bool {
    matches!(s, "vless" | "vmess" | "trojan" | "shadowsocks" | "socks" | "http" | "wireguard")
}

fn is_xray_aux_protocol(s: &str) -> bool {
    matches!(s, "freedom" | "blackhole" | "dns" | "loopback")
}

fn is_vless_flow_ok(s: &str) -> bool {
    matches!(s, "" | "xtls-rprx-vision")
}

fn is_vmess_security_ok(s: &str) -> bool {
    matches!(
        s,
        "auto" | "none" | "zero" | "aes-128-gcm" | "chacha20-poly1305" | "aes-128-ctr"
    )
}

fn is_ss_method_ok(s: &str) -> bool {
    matches!(
        s,
        "none"
            | "aes-128-gcm"
            | "aes-192-gcm"
            | "aes-256-gcm"
            | "chacha20-ietf-poly1305"
            | "xchacha20-ietf-poly1305"
            | "2022-blake3-aes-128-gcm"
            | "2022-blake3-aes-256-gcm"
            | "2022-blake3-chacha20-poly1305"
            | "aes-128-ctr"
            | "aes-192-ctr"
            | "aes-256-ctr"
            | "aes-128-cfb"
            | "aes-192-cfb"
            | "aes-256-cfb"
            | "rc4-md5"
            | "chacha20-ietf"
            | "xchacha20"
    )
}

fn ss_method_alias(s: &str) -> Option<&'static str> {
    Some(match s {
        "chacha20-poly1305" => "chacha20-ietf-poly1305",
        "xchacha20-poly1305" => "xchacha20-ietf-poly1305",
        "plain" => "none",
        _ => return None,
    })
}

fn is_ss_plugin_ok(s: &str) -> bool {
    matches!(s, "" | "obfs-local" | "v2ray-plugin")
}

fn vless_flow_map(s: &str) -> Option<&'static str> {
    match s {
        "xtls-rprx-vision-udp443" => Some("xtls-rprx-vision"),
        _ => None,
    }
}

fn query_strategy_map(s: &str) -> Option<&'static str> {
    Some(match s {
        "UseIPv4" => "ipv4_only",
        "UseIPv4v6" => "prefer_ipv4",
        "UseIPv6" => "ipv6_only",
        "UseIPv6v4" => "prefer_ipv6",
        "UseIP" => "prefer_ipv4",
        "UseSystem" => "prefer_ipv4",
        _ => return None,
    })
}

fn domain_strategy_map(s: &str) -> Option<&'static str> {
    Some(match s {
        "AsIs" => "",
        "UseIP" => "prefer_ipv4",
        "UseIPv4" => "ipv4_only",
        "UseIPv4v6" => "prefer_ipv4",
        "UseIPv6" => "ipv6_only",
        "UseIPv6v4" => "prefer_ipv6",
        "IPIfNonMatch" => "prefer_ipv4",
        "IPOnDemand" => "prefer_ipv4",
        _ => return None,
    })
}

fn freedom_strategy_map(s: &str) -> Option<&'static str> {
    Some(match s {
        "AsIs" => "",
        "UseIP" => "prefer_ipv4",
        "UseIPv4" => "ipv4_only",
        "UseIPv4v6" => "prefer_ipv4",
        "UseIPv6" => "ipv6_only",
        "UseIPv6v4" => "prefer_ipv6",
        "ForceIP" => "prefer_ipv4",
        "ForceIPv4" => "ipv4_only",
        "ForceIPv4v6" => "prefer_ipv4",
        "ForceIPv6" => "ipv6_only",
        "ForceIPv6v4" => "prefer_ipv6",
        _ => return None,
    })
}

fn is_remote_dns_type(s: &str) -> bool {
    matches!(s, "https" | "http3" | "tls" | "quic" | "tcp" | "udp")
}

fn is_encrypted_dns_type(s: &str) -> bool {
    matches!(s, "https" | "http3" | "tls" | "quic" | "tcp")
}

fn log_level_map(s: &str) -> &'static str {
    match s {
        "debug" => "debug",
        "info" => "info",
        "warning" => "warn",
        "warn" => "warn",
        "error" => "error",
        "none" => "fatal",
        _ => "warn",
    }
}

fn is_singbox_outbound_type(s: &str) -> bool {
    matches!(
        s,
        "vless"
            | "vmess"
            | "trojan"
            | "shadowsocks"
            | "hysteria"
            | "hysteria2"
            | "tuic"
            | "wireguard"
            | "anytls"
            | "ssh"
            | "naive"
            | "shadowtls"
            | "selector"
            | "urltest"
            | "direct"
            | "block"
            | "dns"
            | "socks"
            | "http"
    )
}

// ---- Result types ----

pub(crate) enum ConvertResult {
    Ok(Json),
    NotXray,
    Unsupported,
}

pub(crate) enum OutboundsResult {
    // Carries the converted outbounds; the internal pre-filter only needs the variant, so the payload is left unread.
    Ok(#[allow(dead_code)] Vec<Json>),
    NotXray,
    Unsupported,
}

// ---- small value helpers ----

// The raw value of a key, or an explicit null if the key is missing (mirrors `opt(k) ?: JSONObject.NULL`).
fn opt_or_null(o: &Json, key: &str) -> Json {
    o.opt(key).cloned().unwrap_or(Json::Null)
}

// optString(key, default) then ifEmpty { fallback }.
fn opt_str_or(o: &Json, key: &str, default: &str, fallback: &str) -> String {
    let s = o.opt_str(key, default);
    if s.is_empty() { fallback.to_string() } else { s }
}

// Kotlin `when (v) { is Number -> toInt(); is String -> toIntOrNull(); else -> null }`.
fn num_to_int(v: &Json) -> Option<i64> {
    match v {
        Json::Num(n) => Some(*n as i64),
        Json::Str(s) => s.parse::<i64>().ok(),
        _ => None,
    }
}

// isTruthy: false for null/absent, otherwise non-zero number / non-empty string / non-empty container / true.
fn is_truthy(v: Option<&Json>) -> bool {
    match v {
        None | Some(Json::Null) => false,
        Some(Json::Bool(b)) => *b,
        Some(Json::Num(n)) => *n != 0.0,
        Some(Json::Str(s)) => !s.is_empty(),
        Some(Json::Arr(a)) => !a.is_empty(),
        Some(Json::Obj(m)) => !m.is_empty(),
    }
}

// A recognized uTLS fingerprint, or "chrome".
fn utls_fp(fp: Option<&Json>) -> String {
    if let Some(Json::Str(s)) = fp
        && is_utls_fp(s) {
            return s.clone();
        }
    "chrome".to_string()
}

// A JSON value as a list of raw values: array elements, or a single-element list, or empty for null.
fn as_list(v: Option<&Json>) -> Vec<Json> {
    match v {
        None | Some(Json::Null) => Vec::new(),
        Some(Json::Arr(a)) => a.clone(),
        Some(other) => vec![other.clone()],
    }
}

// A JSON value as a list of strings (coercing non-string elements, dropping nulls).
fn as_string_list(v: Option<&Json>) -> Vec<String> {
    let mut out = Vec::new();
    for it in as_list(v) {
        match it {
            Json::Null => {}
            Json::Str(s) => out.push(s),
            other => out.push(other.to_string_value()),
        }
    }
    out
}

fn is_ip_literal(s: Option<&Json>) -> bool {
    match s {
        Some(Json::Str(s)) if !s.is_empty() => parse_inet4(s) || parse_inet6(s),
        _ => false,
    }
}

fn parse_inet4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    for p in parts {
        if p.is_empty() || p.len() > 3 {
            return false;
        }
        if !p.bytes().all(|c| c.is_ascii_digit()) {
            return false;
        }
        let n: i64 = match p.parse() {
            Ok(n) => n,
            Err(_) => return false,
        };
        if !(0..=255).contains(&n) {
            return false;
        }
        if p.len() > 1 && p.starts_with('0') {
            return false;
        }
    }
    true
}

// Rough IPv6 parsing (::, embedded IPv4, zone-id).
fn parse_inet6(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let core = s.split_once('%').map_or(s, |(a, _)| a);
    if core.is_empty() {
        return false;
    }
    if core == "::" {
        return true;
    }
    let has_double_colon = core.contains("::");
    let tail = core.rsplit_once(':').map_or(core, |(_, b)| b);
    let embedded4 = tail.contains('.');
    let groups_raw: Vec<String> = if has_double_colon {
        let (left, right) = core.split_once("::").unwrap_or((core, ""));
        let mut l: Vec<String> = if left.is_empty() {
            Vec::new()
        } else {
            left.split(':').map(|s| s.to_string()).collect()
        };
        let r: Vec<String> = if right.is_empty() {
            Vec::new()
        } else {
            right.split(':').map(|s| s.to_string()).collect()
        };
        l.extend(r);
        l
    } else {
        core.split(':').map(|s| s.to_string()).collect()
    };
    let mut groups = groups_raw;
    if embedded4 {
        let last = groups.pop().unwrap_or_default();
        if !parse_inet4(&last) {
            return false;
        }
        groups.push("0".to_string());
        groups.push("0".to_string());
    }
    let expected = 8;
    let count_without_dc = groups.len();
    if has_double_colon {
        if count_without_dc > expected {
            return false;
        }
    } else if count_without_dc != expected {
        return false;
    }
    for g in &groups {
        if g.is_empty() || g.len() > 4 {
            return false;
        }
        if !g.bytes().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
    }
    true
}

// ---- structured intermediate results ----

struct PortLists {
    ports: Vec<i64>,
    ranges: Vec<String>,
}

struct HostPort {
    host: String,
    port: Option<i64>,
}

struct WsPath {
    path: String,
    early_data: Option<i64>,
}

struct DomainSplit {
    domain: Vec<String>,
    domain_suffix: Vec<String>,
    domain_keyword: Vec<String>,
    domain_regex: Vec<String>,
    geosite: Vec<String>,
}

struct IpSplit {
    ip_cidr: Vec<String>,
    geoip: Vec<String>,
    ip_is_private: bool,
}

// ---- array construction helpers ----

fn str_arr(v: &[String]) -> Json {
    Json::Arr(v.iter().cloned().map(Json::str).collect())
}

fn int_arr(v: &[i64]) -> Json {
    Json::Arr(v.iter().map(|&n| Json::int(n)).collect())
}

// ---- parsing helpers ----

fn parse_port_list(value: Option<&Json>) -> PortLists {
    let mut ports = Vec::new();
    let mut ranges = Vec::new();
    let value = match value {
        None | Some(Json::Null) => return PortLists { ports, ranges },
        Some(v) => v,
    };
    let mut items: Vec<String> = Vec::new();
    match value {
        Json::Arr(a) => {
            for e in a {
                if matches!(e, Json::Null) {
                    continue;
                }
                for piece in e.to_string_value().split(',') {
                    items.push(piece.to_string());
                }
            }
        }
        other => {
            for piece in other.to_string_value().split(',') {
                items.push(piece.to_string());
            }
        }
    }
    for raw in items {
        let tok = raw.trim();
        if tok.is_empty() {
            continue;
        }
        if tok.contains('-') {
            ranges.push(tok.replace('-', ":"));
        } else if tok.bytes().all(|c| c.is_ascii_digit())
            && let Ok(n) = tok.parse::<i64>() {
                ports.push(n);
            }
    }
    PortLists { ports, ranges }
}

fn parse_listen_port(p: Option<&Json>) -> Option<i64> {
    match p {
        None | Some(Json::Null) => None,
        Some(Json::Bool(_)) => None,
        Some(Json::Num(n)) => Some(*n as i64),
        Some(Json::Str(s)) => {
            let s = s.trim();
            if s.is_empty() {
                None
            } else if s.bytes().all(|c| c.is_ascii_digit()) {
                s.parse::<i64>().ok()
            } else {
                None
            }
        }
        Some(Json::Arr(a)) => {
            if !a.is_empty() {
                parse_listen_port(a.first())
            } else {
                None
            }
        }
        Some(Json::Obj(_)) => None,
    }
}

fn to_duration(v: Option<&Json>) -> Option<String> {
    match v {
        None | Some(Json::Null) => None,
        Some(Json::Bool(_)) => None,
        Some(Json::Num(n)) => Some(format!("{}s", *n as i64)),
        Some(Json::Str(s)) => {
            let s = s.trim();
            if s.is_empty() {
                None
            } else if s.bytes().all(|c| c.is_ascii_digit()) {
                Some(format!("{}s", s))
            } else {
                Some(s.to_string())
            }
        }
        Some(Json::Obj(_)) | Some(Json::Arr(_)) => None,
    }
}

fn split_host_port(s: &str) -> HostPort {
    if s.is_empty() {
        return HostPort {
            host: String::new(),
            port: None,
        };
    }
    if s.starts_with('[') {
        let rb = match s.find(']') {
            Some(i) => i,
            None => {
                return HostPort {
                    host: s.to_string(),
                    port: None,
                }
            }
        };
        let host = &s[1..rb];
        let rest = &s[rb + 1..];
        if let Some(pd) = rest.strip_prefix(':')
            && !pd.is_empty() && pd.bytes().all(|c| c.is_ascii_digit()) {
                return HostPort {
                    host: host.to_string(),
                    port: pd.parse::<i64>().ok(),
                };
            }
        return HostPort {
            host: host.to_string(),
            port: None,
        };
    }
    if s.bytes().filter(|&c| c == b':').count() == 1 {
        let idx = s.find(':').unwrap();
        let host = &s[..idx];
        let port = &s[idx + 1..];
        if !port.is_empty() && port.bytes().all(|c| c.is_ascii_digit()) {
            return HostPort {
                host: host.to_string(),
                port: port.parse::<i64>().ok(),
            };
        }
    }
    HostPort {
        host: s.to_string(),
        port: None,
    }
}

pub(crate) fn normalize_flow(flow: &str) -> String {
    if flow.is_empty() {
        return String::new();
    }
    vless_flow_map(flow)
        .map(|s| s.to_string())
        .unwrap_or_else(|| flow.to_string())
}

fn parse_ws_path(path: &str) -> WsPath {
    if !path.contains('?') || !path.contains("ed=") {
        return WsPath {
            path: path.to_string(),
            early_data: None,
        };
    }
    let q_idx = path.find('?').unwrap();
    let base = &path[..q_idx];
    let query = &path[q_idx + 1..];
    let mut kept: Vec<&str> = Vec::new();
    let mut ed_value: Option<i64> = None;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        if let Some(num) = pair.strip_prefix("ed=") {
            match num.parse::<i64>() {
                Ok(n) => ed_value = Some(n),
                Err(_) => kept.push(pair),
            }
        } else {
            kept.push(pair);
        }
    }
    let new_query = kept.join("&");
    let new_path = if new_query.is_empty() {
        base.to_string()
    } else {
        format!("{}?{}", base, new_query)
    };
    WsPath {
        path: new_path,
        early_data: ed_value,
    }
}

// Normalize v2ray-style header maps to sing-box form: single string values, or arrays of strings.
fn normalize_headers_v2ray(headers: Option<&Json>, single_value: bool) -> Json {
    let mut out = Json::obj();
    let headers = match headers {
        Some(h @ Json::Obj(_)) => h,
        _ => return out,
    };
    for k in headers.keys() {
        let v = match headers.opt(&k) {
            Some(v) => v,
            None => continue,
        };
        if matches!(v, Json::Null) {
            continue;
        }
        if single_value {
            match v {
                Json::Arr(a) => {
                    if !a.is_empty() {
                        let s0 = a.first().map(|e| e.to_string_value()).unwrap_or_default();
                        out.set(k.clone(), Json::str(s0));
                    } else {
                        out.set(k.clone(), Json::str(""));
                    }
                }
                other => out.set(k.clone(), Json::str(other.to_string_value())),
            }
        } else {
            match v {
                Json::Arr(_) => out.set(k.clone(), v.clone()),
                other => out.set(k.clone(), Json::Arr(vec![Json::str(other.to_string_value())])),
            }
        }
    }
    out
}

fn serialize_plugin_opts(opts: Option<&Json>) -> String {
    match opts {
        None | Some(Json::Null) => String::new(),
        Some(Json::Str(s)) => s.clone(),
        Some(o @ Json::Obj(_)) => {
            let mut parts = Vec::new();
            for k in o.keys() {
                match o.opt(&k) {
                    Some(Json::Bool(b)) => {
                        parts.push(if *b { k.clone() } else { format!("{}=0", k) })
                    }
                    Some(v) => parts.push(format!("{}={}", k, v.to_string_value())),
                    None => {}
                }
            }
            parts.join(";")
        }
        _ => String::new(),
    }
}

fn get_tcp_http_request(stream: &Json) -> Option<Json> {
    let net = opt_str_or(stream, "network", "tcp", "tcp");
    if !matches!(net.as_str(), "tcp" | "raw" | "") {
        return None;
    }
    let ts = stream
        .opt_obj("tcpSettings")
        .or_else(|| stream.opt_obj("rawSettings"))?;
    let hdr = ts.opt_obj("header")?;
    let t = opt_str_or(hdr, "type", "none", "none");
    if t != "http" {
        return None;
    }
    Some(hdr.opt_obj("request").cloned().unwrap_or_else(Json::obj))
}

// ---- detection ----

fn is_singbox(d: &Json) -> bool {
    if !d.has("route") || !d.has("outbounds") {
        return false;
    }
    let outs = match d.opt_arr("outbounds") {
        Some(o) => o,
        None => return false,
    };
    if outs.len() == 0 {
        return false;
    }
    let first = match outs.arr_obj(0) {
        Some(f) => f,
        None => return false,
    };
    is_singbox_outbound_type(&first.opt_str("type", ""))
}

fn looks_like_xray(d: &Json) -> bool {
    let outs = match d.opt_arr("outbounds") {
        Some(o) => o,
        None => return false,
    };
    if outs.len() == 0 {
        return false;
    }
    for i in 0..outs.len() {
        let o = match outs.arr_obj(i) {
            Some(o) => o,
            None => continue,
        };
        if o.has("protocol") {
            return true;
        }
    }
    false
}

fn first_user(o: &Json) -> Option<&Json> {
    let settings = o.opt_obj("settings")?;
    let vnext = settings.opt_arr("vnext")?;
    let first = vnext.arr_obj(0)?;
    let users = first.opt_arr("users")?;
    users.arr_obj(0)
}

fn first_server(o: &Json) -> Option<&Json> {
    let settings = o.opt_obj("settings")?;
    let servers = settings.opt_arr("servers")?;
    servers.arr_obj(0)
}

fn is_outbound_supported(o: &Json) -> bool {
    let proto = o.opt_str("protocol", "");
    if !is_xray_proxy_protocol(&proto) && !is_xray_aux_protocol(&proto) {
        return false;
    }
    if is_xray_aux_protocol(&proto) || proto == "wireguard" {
        return true;
    }
    let empty = Json::obj();
    let stream = o.opt_obj("streamSettings").unwrap_or(&empty);
    let net = opt_str_or(stream, "network", "tcp", "tcp");
    if !is_xray_transport_ok(&net) {
        return false;
    }
    if net == "tcp" || net == "raw" {
        let ts = stream
            .opt_obj("tcpSettings")
            .or_else(|| stream.opt_obj("rawSettings"));
        if let Some(ts) = ts
            && let Some(hdr) = ts.opt_obj("header") {
                let hdr_type = opt_str_or(hdr, "type", "none", "none");
                if hdr_type != "none" && hdr_type != "http" {
                    return false;
                }
            }
    }
    if net == "quic" {
        let qs = stream.opt_obj("quicSettings").unwrap_or(&empty);
        let qsec = opt_str_or(qs, "security", "none", "none").to_ascii_lowercase();
        if qsec != "none" && !qsec.is_empty() {
            return false;
        }
        let qhdr = match qs.opt_obj("header") {
            Some(h) => opt_str_or(h, "type", "none", "none"),
            None => "none".to_string(),
        }
        .to_ascii_lowercase();
        if qhdr != "none" && !qhdr.is_empty() {
            return false;
        }
    }
    let sec = stream.opt_str("security", "");
    if !is_xray_security_ok(&sec) {
        return false;
    }
    if proto == "vless" {
        let user = first_user(o);
        let flow_raw = user.map(|u| u.opt_str("flow", "")).unwrap_or_default();
        let flow = normalize_flow(&flow_raw);
        if !is_vless_flow_ok(&flow) {
            return false;
        }
        let enc = user
            .map(|u| u.opt_str("encryption", "none"))
            .unwrap_or_else(|| "none".to_string());
        let enc = enc.trim();
        if !enc.is_empty() && enc != "none" {
            return false;
        }
    }
    if proto == "vmess" {
        let user = first_user(o);
        let vsec = match user {
            Some(u) => opt_str_or(u, "security", "auto", "auto"),
            None => "auto".to_string(),
        };
        if !is_vmess_security_ok(&vsec) {
            return false;
        }
    }
    if proto == "shadowsocks" {
        let srv = first_server(o);
        let raw_method = srv
            .map(|s| s.opt_str("method", "aes-256-gcm"))
            .unwrap_or_else(|| "aes-256-gcm".to_string());
        let method = ss_method_alias(&raw_method)
            .map(|s| s.to_string())
            .unwrap_or(raw_method);
        if !is_ss_method_ok(&method) {
            return false;
        }
        let plugin = srv.map(|s| s.opt_str("plugin", "")).unwrap_or_default();
        if !plugin.is_empty() && !is_ss_plugin_ok(&plugin) {
            return false;
        }
    }
    true
}

fn split_domains(domains: &[Json]) -> DomainSplit {
    let mut full = Vec::new();
    let mut suffix = Vec::new();
    let mut keyword = Vec::new();
    let mut regex = Vec::new();
    let mut geosite = Vec::new();
    for raw in domains {
        let d = match raw {
            Json::Str(s) => s.as_str(),
            _ => continue,
        };
        if d.starts_with('!') {
            continue;
        }
        if let Some(x) = d.strip_prefix("geosite:") {
            geosite.push(x.to_string());
        } else if let Some(x) = d.strip_prefix("domain:") {
            suffix.push(x.to_string());
        } else if let Some(x) = d.strip_prefix("full:") {
            full.push(x.to_string());
        } else if let Some(x) = d.strip_prefix("regexp:") {
            regex.push(x.to_string());
        } else if let Some(x) = d.strip_prefix("keyword:") {
            keyword.push(x.to_string());
        } else if d.starts_with("ext:") || d.starts_with("ext-domain:") {
            // external rule files are not supported
        } else {
            suffix.push(d.to_string());
        }
    }
    DomainSplit {
        domain: full,
        domain_suffix: suffix,
        domain_keyword: keyword,
        domain_regex: regex,
        geosite,
    }
}

fn split_ips(ips: &[Json]) -> IpSplit {
    let mut cidr = Vec::new();
    let mut geoip = Vec::new();
    let mut is_private = false;
    for raw in ips {
        let i = match raw {
            Json::Str(s) => s.as_str(),
            _ => continue,
        };
        if i.starts_with('!') {
            continue;
        }
        if i == "geoip:private" {
            is_private = true;
        } else if let Some(x) = i.strip_prefix("geoip:") {
            geoip.push(x.to_string());
        } else if i.starts_with("ext:") || i.starts_with("ext-ip:") {
            // external rule files are not supported
        } else {
            cidr.push(i.to_string());
        }
    }
    IpSplit {
        ip_cidr: cidr,
        geoip,
        ip_is_private: is_private,
    }
}

fn add_rule_set_tags(rule: &mut Json, tags: &[String]) {
    if tags.is_empty() {
        return;
    }
    let mut existing: Vec<String> = Vec::new();
    if let Some(arr) = rule.opt_arr("rule_set") {
        for i in 0..arr.len() {
            existing.push(arr.arr_opt_str(i));
        }
    }
    for t in tags {
        if !existing.contains(t) {
            existing.push(t.clone());
        }
    }
    rule.set("rule_set", str_arr(&existing));
}

fn apply_domain_split(rule: &mut Json, split: &DomainSplit, rule_sets: &mut BTreeSet<String>) {
    if !split.domain.is_empty() {
        rule.set("domain", str_arr(&split.domain));
    }
    if !split.domain_suffix.is_empty() {
        rule.set("domain_suffix", str_arr(&split.domain_suffix));
    }
    if !split.domain_keyword.is_empty() {
        rule.set("domain_keyword", str_arr(&split.domain_keyword));
    }
    if !split.domain_regex.is_empty() {
        rule.set("domain_regex", str_arr(&split.domain_regex));
    }
    if !split.geosite.is_empty() {
        let tags: Vec<String> = split
            .geosite
            .iter()
            .map(|g| format!("geosite-{}", g.to_ascii_lowercase()))
            .collect();
        for t in &tags {
            rule_sets.insert(t.clone());
        }
        add_rule_set_tags(rule, &tags);
    }
}

fn apply_geoip_to_rule_set(rule: &mut Json, geoip: &[String], rule_sets: &mut BTreeSet<String>) {
    if geoip.is_empty() {
        return;
    }
    let tags: Vec<String> = geoip
        .iter()
        .map(|g| format!("geoip-{}", g.to_ascii_lowercase()))
        .collect();
    for t in &tags {
        rule_sets.insert(t.clone());
    }
    add_rule_set_tags(rule, &tags);
}

// ---- TLS ----

// streamSettings.security -> the sing-box tls block (tls or reality), or None.
fn conv_tls(stream: &Json) -> Option<Json> {
    let sec = stream.opt_str("security", "");
    if sec != "tls" && sec != "reality" {
        return None;
    }
    let mut tls = Json::obj();
    tls.set("enabled", Json::bool(true));

    if sec == "reality" {
        let rs_empty = Json::obj();
        let rs = stream.opt_obj("realitySettings").unwrap_or(&rs_empty);
        let sn = rs.opt_str("serverName", "");
        if !sn.is_empty() {
            tls.set("server_name", Json::str(sn));
        }
        let mut utls = Json::obj();
        utls.set("enabled", Json::bool(true));
        utls.set("fingerprint", Json::str(utls_fp(rs.opt("fingerprint"))));
        tls.set("utls", utls);
        let mut reality = Json::obj();
        reality.set("enabled", Json::bool(true));
        reality.set("public_key", Json::str(rs.opt_str("publicKey", "")));
        reality.set("short_id", Json::str(rs.opt_str("shortId", "")));
        tls.set("reality", reality);
        return Some(tls);
    }

    let ts_empty = Json::obj();
    let ts = stream.opt_obj("tlsSettings").unwrap_or(&ts_empty);
    let sn = ts.opt_str("serverName", "");
    if !sn.is_empty() {
        tls.set("server_name", Json::str(sn));
    }
    if ts.opt_bool("allowInsecure", false) {
        tls.set("insecure", Json::bool(true));
    }
    match ts.opt("alpn") {
        None | Some(Json::Null) => {}
        Some(a @ Json::Arr(arr)) => {
            if !arr.is_empty() {
                tls.set("alpn", a.clone());
            }
        }
        Some(other) => {
            tls.set("alpn", Json::Arr(vec![Json::str(other.to_string_value())]));
        }
    }
    if ts.has("minVersion") && !ts.is_null("minVersion") {
        let v = ts.opt_str("minVersion", "");
        if !v.is_empty() {
            tls.set("min_version", Json::str(v));
        }
    }
    if ts.has("maxVersion") && !ts.is_null("maxVersion") {
        let v = ts.opt_str("maxVersion", "");
        if !v.is_empty() {
            tls.set("max_version", Json::str(v));
        }
    }
    let fp = ts.opt_str("fingerprint", "");
    if !fp.is_empty() {
        let mut utls = Json::obj();
        utls.set("enabled", Json::bool(true));
        utls.set("fingerprint", Json::str(utls_fp(Some(&Json::str(fp)))));
        tls.set("utls", utls);
    }
    if let Some(certs) = ts.opt_arr("certificates")
        && certs.len() > 0 {
            let cert_empty = Json::obj();
            let cert = certs.arr_obj(0).unwrap_or(&cert_empty);
            let cert_file = cert.opt_str("certificateFile", "");
            if !cert_file.is_empty() {
                tls.set("certificate_path", Json::str(cert_file));
            } else if cert.has("certificate") && !cert.is_null("certificate") {
                match cert.opt("certificate") {
                    Some(cval @ Json::Arr(arr)) => {
                        let mut parts: Vec<String> = Vec::new();
                        for i in 0..arr.len() {
                            parts.push(cval.arr_opt(i).map(|v| v.to_string_value()).unwrap_or_default());
                        }
                        tls.set("certificate", Json::str(parts.join("\n")));
                    }
                    Some(Json::Str(s)) => {
                        tls.set("certificate", Json::str(s.clone()));
                    }
                    _ => {}
                }
            }
        }
    let is_empty_ech = |e: &Option<Json>| -> bool {
        match e {
            None | Some(Json::Null) => true,
            Some(Json::Arr(a)) => a.is_empty(),
            Some(Json::Str(s)) => s.is_empty(),
            _ => false,
        }
    };
    let mut ech: Option<Json> = ts.opt("echConfigList").cloned();
    if is_empty_ech(&ech) {
        ech = ts.opt("ech").cloned();
    }
    if !is_empty_ech(&ech) {
        let mut ech_obj = Json::obj();
        ech_obj.set("enabled", Json::bool(true));
        match ech.as_ref().unwrap() {
            Json::Arr(_) => ech_obj.set("config", ech.clone().unwrap()),
            Json::Str(_) => ech_obj.set("config_path", ech.clone().unwrap()),
            _ => {}
        }
        tls.set("ech", ech_obj);
    }
    Some(tls)
}

// ---- transport ----

// streamSettings -> the sing-box transport block (ws/grpc/http/httpupgrade/quic/tcp-http), or None.
fn conv_transport(stream: &Json) -> Option<Json> {
    let mut net = opt_str_or(stream, "network", "tcp", "tcp");
    if net == "raw" {
        net = "tcp".to_string();
    }

    if net == "tcp" {
        let req = get_tcp_http_request(stream)?;
        let mut tr = Json::obj();
        tr.set("type", Json::str("http"));
        match req.opt("path") {
            Some(Json::Arr(a)) => {
                if !a.is_empty() {
                    tr.set("path", a.first().cloned().unwrap_or(Json::Null));
                }
            }
            Some(Json::Str(s))
                if !s.is_empty() => {
                    tr.set("path", Json::str(s.clone()));
                }
            _ => {}
        }
        let method = req.opt_str("method", "");
        if !method.is_empty() {
            tr.set("method", Json::str(method));
        }
        let mut working_headers: Option<Json> = None;
        if let Some(hin) = req.opt_obj("headers") {
            let mut copy = Json::obj();
            for k in hin.keys() {
                copy.set(k.clone(), hin.opt(&k).cloned().unwrap_or(Json::Null));
            }
            working_headers = Some(copy);
        }
        let mut host_vals: Option<Json> = None;
        if let Some(wh) = working_headers.as_mut() {
            if wh.has("Host") {
                host_vals = wh.opt("Host").cloned();
                wh.remove("Host");
            } else if wh.has("host") {
                host_vals = wh.opt("host").cloned();
                wh.remove("host");
            }
        }
        if let Some(hv) = host_vals
            && !matches!(hv, Json::Null) {
                match hv {
                    Json::Arr(_) => tr.set("host", hv),
                    other => tr.set("host", Json::Arr(vec![Json::str(other.to_string_value())])),
                }
            }
        if let Some(wh) = working_headers
            && wh.len() > 0 {
                tr.set("headers", normalize_headers_v2ray(Some(&wh), false));
            }
        return Some(tr);
    }

    if net == "ws" {
        let ws_empty = Json::obj();
        let ws = stream.opt_obj("wsSettings").unwrap_or(&ws_empty);
        let mut tr = Json::obj();
        tr.set("type", Json::str("ws"));
        let raw_path = ws.opt_str("path", "");
        let parsed = parse_ws_path(&raw_path);
        if !parsed.path.is_empty() {
            tr.set("path", Json::str(parsed.path.clone()));
        }
        let headers = normalize_headers_v2ray(ws.opt_obj("headers"), true);
        if headers.len() > 0 {
            tr.set("headers", headers);
        }
        let mut early_data = parsed.early_data;
        if early_data.is_none() && ws.has("maxEarlyData") && !ws.is_null("maxEarlyData")
            && let Some(v) = ws.opt("maxEarlyData") {
                early_data = num_to_int(v);
            }
        match early_data {
            Some(ed) if ed != 0 => {
                tr.set("max_early_data", Json::int(ed));
                let edh = opt_str_or(ws, "earlyDataHeaderName", "", "Sec-WebSocket-Protocol");
                tr.set("early_data_header_name", Json::str(edh));
            }
            _ => {
                let edh = ws.opt_str("earlyDataHeaderName", "");
                if !edh.is_empty() {
                    tr.set("early_data_header_name", Json::str(edh));
                }
            }
        }
        return Some(tr);
    }

    if net == "grpc" {
        let g_empty = Json::obj();
        let g = stream.opt_obj("grpcSettings").unwrap_or(&g_empty);
        let mut sn = g.opt_str("serviceName", "");
        if sn.starts_with('/') {
            sn = sn.trim_start_matches('/').to_string();
        }
        let mut tr = Json::obj();
        tr.set("type", Json::str("grpc"));
        tr.set("service_name", Json::str(sn));
        if let Some(idle) = to_duration(g.opt("idle_timeout")) {
            tr.set("idle_timeout", Json::str(idle));
        }
        if let Some(hct) = to_duration(g.opt("health_check_timeout")) {
            tr.set("ping_timeout", Json::str(hct));
        }
        if g.opt_bool("permit_without_stream", false) {
            tr.set("permit_without_stream", Json::bool(true));
        }
        return Some(tr);
    }

    if net == "http" || net == "h2" {
        let h_empty = Json::obj();
        let h = stream.opt_obj("httpSettings").unwrap_or(&h_empty);
        let mut tr = Json::obj();
        tr.set("type", Json::str("http"));
        let path = h.opt_str("path", "");
        if !path.is_empty() {
            tr.set("path", Json::str(path));
        }
        match h.opt("host") {
            None | Some(Json::Null) => {}
            Some(host @ Json::Arr(a)) => {
                if !a.is_empty() {
                    tr.set("host", host.clone());
                }
            }
            Some(Json::Str(s)) => {
                if !s.is_empty() {
                    tr.set("host", Json::Arr(vec![Json::str(s.clone())]));
                }
            }
            Some(other) => {
                let hs = other.to_string_value();
                if !hs.is_empty() {
                    tr.set("host", Json::Arr(vec![Json::str(hs)]));
                }
            }
        }
        let method = h.opt_str("method", "");
        if !method.is_empty() {
            tr.set("method", Json::str(method));
        }
        if let Some(headers) = h.opt_obj("headers")
            && headers.len() > 0 {
                tr.set("headers", normalize_headers_v2ray(Some(headers), false));
            }
        if let Some(idle) = to_duration(h.opt("read_idle_timeout")) {
            tr.set("idle_timeout", Json::str(idle));
        }
        if let Some(hct) = to_duration(h.opt("health_check_timeout")) {
            tr.set("ping_timeout", Json::str(hct));
        }
        return Some(tr);
    }

    if net == "httpupgrade" {
        let hu_empty = Json::obj();
        let hu = stream.opt_obj("httpupgradeSettings").unwrap_or(&hu_empty);
        let mut tr = Json::obj();
        tr.set("type", Json::str("httpupgrade"));
        let path = hu.opt_str("path", "");
        if !path.is_empty() {
            tr.set("path", Json::str(path));
        }
        let mut host_top = hu.opt_str("host", "");
        let mut headers = normalize_headers_v2ray(hu.opt_obj("headers"), true);
        let mut host_from_headers: Option<String> = None;
        let mut to_remove: Vec<String> = Vec::new();
        for k in headers.keys() {
            if k.eq_ignore_ascii_case("host") {
                host_from_headers = headers.opt(&k).map(|v| v.to_string_value());
                to_remove.push(k);
            }
        }
        for k in &to_remove {
            headers.remove(k);
        }
        if host_top.is_empty()
            && let Some(hfh) = &host_from_headers
                && !hfh.is_empty() {
                    host_top = hfh.clone();
                }
        if !host_top.is_empty() {
            tr.set("host", Json::str(host_top));
        }
        if headers.len() > 0 {
            tr.set("headers", headers);
        }
        return Some(tr);
    }

    if net == "quic" {
        let mut tr = Json::obj();
        tr.set("type", Json::str("quic"));
        return Some(tr);
    }

    None
}

// ---- outbound ----

// packetEncoding (xudp/packetaddr), protocol-aware.
fn conv_packet_encoding(o: &Json, proto: &str) -> Option<String> {
    let empty = Json::obj();
    let settings = o.opt_obj("settings").unwrap_or(&empty);
    let mut v: Option<&Json> = settings.opt("packetEncoding");
    if v.is_none() || matches!(v, Some(Json::Null)) {
        v = settings
            .opt_arr("vnext")
            .and_then(|a| a.arr_obj(0))
            .and_then(|vn| vn.opt_arr("users"))
            .and_then(|u| u.arr_obj(0))
            .and_then(|user| user.opt("packetEncoding"));
    }
    let v = match v {
        Some(v) if !matches!(v, Json::Null) => v,
        _ => return None,
    };
    let s = v.to_string_value().to_ascii_lowercase();
    match s.as_str() {
        "packet" => Some("packetaddr".to_string()),
        "xudp" => {
            if proto == "vless" {
                None
            } else {
                Some("xudp".to_string())
            }
        }
        "none" | "" => {
            if proto == "vless" {
                Some(String::new())
            } else {
                None
            }
        }
        _ => None,
    }
}

fn apply_proxy_settings(sb: &mut Json, o: &Json) {
    let mut chain_tag = o
        .opt_obj("proxySettings")
        .map(|ps| ps.opt_str("tag", ""))
        .unwrap_or_default();
    if chain_tag.is_empty() {
        let ss_empty = Json::obj();
        let ss = o.opt_obj("streamSettings").unwrap_or(&ss_empty);
        chain_tag = ss.opt_str("dialerProxy", "");
        if chain_tag.is_empty() {
            chain_tag = ss
                .opt_obj("sockopt")
                .map(|s| s.opt_str("dialerProxy", ""))
                .unwrap_or_default();
        }
    }
    if !chain_tag.is_empty() {
        sb.set("detour", Json::str(chain_tag));
    }
}

fn apply_sockopt(sb: &mut Json, stream: Option<&Json>) {
    let sock = match stream.and_then(|s| s.opt_obj("sockopt")) {
        Some(s) => s,
        None => return,
    };
    let ds = sock.opt_str("domainStrategy", "");
    let strat = freedom_strategy_map(ds.trim()).unwrap_or("");
    if !strat.is_empty() && !sb.has("domain_strategy") {
        sb.set("domain_strategy", Json::str(strat));
    }
    if let Some(Json::Bool(b)) = sock.opt("tcpFastOpen") {
        sb.set("tcp_fast_open", Json::bool(*b));
    }
    if let Some(Json::Num(n)) = sock.opt("tcpKeepAliveInterval") {
        let kai = *n as i64;
        if kai > 0 {
            sb.set("tcp_keep_alive_interval", Json::str(format!("{}s", kai)));
        }
    }
}

struct OutboundResult {
    sb: Option<Json>,
    kind: Option<&'static str>,
}

// One Xray outbound to one sing-box outbound.
fn conv_outbound(o: &Json) -> OutboundResult {
    let proto = o.opt_str("protocol", "");
    let tag = o.opt_str("tag", &proto);

    if proto == "freedom" {
        let mut sb = Json::obj();
        sb.set("type", Json::str("direct"));
        sb.set("tag", Json::str(tag));
        let settings_empty = Json::obj();
        let settings = o.opt_obj("settings").unwrap_or(&settings_empty);
        let ds = settings.opt_str("domainStrategy", "");
        let strat = freedom_strategy_map(ds.trim()).unwrap_or("");
        if !strat.is_empty() {
            sb.set("domain_strategy", Json::str(strat));
        }
        apply_proxy_settings(&mut sb, o);
        return OutboundResult {
            sb: Some(sb),
            kind: Some("aux"),
        };
    }

    if proto == "blackhole" || proto == "dns" {
        return OutboundResult {
            sb: None,
            kind: Some("aux"),
        };
    }
    if proto == "loopback" {
        return OutboundResult {
            sb: None,
            kind: Some("aux"),
        };
    }

    let stream_empty = Json::obj();
    let stream = o.opt_obj("streamSettings").unwrap_or(&stream_empty);
    let settings_empty = Json::obj();
    let settings = o.opt_obj("settings").unwrap_or(&settings_empty);

    if proto == "wireguard" {
        return OutboundResult {
            sb: Some(conv_wireguard(o, settings, &tag)),
            kind: Some("wireguard"),
        };
    }

    if proto == "vless" || proto == "vmess" {
        let vnext_empty = Json::obj();
        let vnext = settings
            .opt_arr("vnext")
            .and_then(|a| a.arr_obj(0))
            .unwrap_or(&vnext_empty);
        let user_empty = Json::obj();
        let user = vnext
            .opt_arr("users")
            .and_then(|a| a.arr_obj(0))
            .unwrap_or(&user_empty);
        let mut sb = Json::obj();
        sb.set("type", Json::str(proto.clone()));
        sb.set("tag", Json::str(tag));
        sb.set("server", opt_or_null(vnext, "address"));
        sb.set("server_port", opt_or_null(vnext, "port"));
        sb.set("uuid", opt_or_null(user, "id"));
        if proto == "vless" {
            let flow_raw = user.opt_str("flow", "");
            let flow = normalize_flow(&flow_raw);
            if !flow.is_empty() {
                sb.set("flow", Json::str(flow));
            }
        } else {
            sb.set("security", Json::str(user.opt_str("security", "auto")));
            match user.opt("alterId") {
                None | Some(Json::Null) => sb.set("alter_id", Json::int(0)),
                Some(v) => sb.set("alter_id", v.clone()),
            }
            let mut gp = user.opt("global_padding");
            if gp.is_none() || matches!(gp, Some(Json::Null)) {
                gp = user.opt("globalPadding");
            }
            match gp {
                None | Some(Json::Null) => sb.set("global_padding", Json::bool(true)),
                Some(Json::Bool(b)) => sb.set("global_padding", Json::bool(*b)),
                Some(other) => sb.set(
                    "global_padding",
                    Json::bool(other.to_string_value().eq_ignore_ascii_case("true")),
                ),
            }
            let mut al = user.opt("authenticated_length");
            if al.is_none() || matches!(al, Some(Json::Null)) {
                al = user.opt("authenticatedLength");
            }
            if let Some(Json::Bool(false)) = al {
                sb.set("authenticated_length", Json::bool(false));
            }
        }
        if let Some(pe) = conv_packet_encoding(o, &proto) {
            sb.set("packet_encoding", Json::str(pe));
        }
        if let Some(tls) = conv_tls(stream) {
            sb.set("tls", tls);
        }
        if let Some(tr) = conv_transport(stream) {
            sb.set("transport", tr);
        }
        apply_proxy_settings(&mut sb, o);
        apply_sockopt(&mut sb, Some(stream));
        return OutboundResult {
            sb: Some(sb),
            kind: Some("proxy"),
        };
    }

    if proto == "trojan" {
        let srv_empty = Json::obj();
        let srv = settings
            .opt_arr("servers")
            .and_then(|a| a.arr_obj(0))
            .unwrap_or(&srv_empty);
        let mut sb = Json::obj();
        sb.set("type", Json::str("trojan"));
        sb.set("tag", Json::str(tag));
        sb.set("server", opt_or_null(srv, "address"));
        sb.set("server_port", opt_or_null(srv, "port"));
        sb.set("password", opt_or_null(srv, "password"));
        if let Some(tls) = conv_tls(stream) {
            sb.set("tls", tls);
        }
        if let Some(tr) = conv_transport(stream) {
            sb.set("transport", tr);
        }
        apply_proxy_settings(&mut sb, o);
        apply_sockopt(&mut sb, Some(stream));
        return OutboundResult {
            sb: Some(sb),
            kind: Some("proxy"),
        };
    }

    if proto == "shadowsocks" {
        let srv_empty = Json::obj();
        let srv = settings
            .opt_arr("servers")
            .and_then(|a| a.arr_obj(0))
            .unwrap_or(&srv_empty);
        let raw_method = opt_str_or(srv, "method", "aes-256-gcm", "aes-256-gcm");
        let method = ss_method_alias(&raw_method)
            .map(|s| s.to_string())
            .unwrap_or(raw_method);
        let mut sb = Json::obj();
        sb.set("type", Json::str("shadowsocks"));
        sb.set("tag", Json::str(tag));
        sb.set("server", opt_or_null(srv, "address"));
        sb.set("server_port", opt_or_null(srv, "port"));
        sb.set("method", Json::str(method));
        sb.set("password", opt_or_null(srv, "password"));
        let plugin = srv.opt_str("plugin", "");
        if !plugin.is_empty() {
            sb.set("plugin", Json::str(plugin));
        }
        let mut po = srv.opt("plugin_opts");
        if po.is_none() || matches!(po, Some(Json::Null)) {
            po = srv.opt("pluginOpts");
        }
        if let Some(p) = po
            && !matches!(p, Json::Null) {
                let ser = serialize_plugin_opts(Some(p));
                if !ser.is_empty() {
                    sb.set("plugin_opts", Json::str(ser));
                }
            }
        if srv.opt_bool("uot", false) {
            let ver = match srv.opt("UoTVersion") {
                None | Some(Json::Null) => 1i64,
                Some(Json::Num(n)) => *n as i64,
                Some(Json::Str(s)) => s.parse::<i64>().unwrap_or(1),
                Some(_) => 1,
            };
            let mut uot = Json::obj();
            uot.set("enabled", Json::bool(true));
            uot.set("version", Json::int(ver));
            sb.set("udp_over_tcp", uot);
        }
        apply_proxy_settings(&mut sb, o);
        apply_sockopt(&mut sb, Some(stream));
        return OutboundResult {
            sb: Some(sb),
            kind: Some("proxy"),
        };
    }

    if proto == "socks" {
        let srv_empty = Json::obj();
        let srv = settings
            .opt_arr("servers")
            .and_then(|a| a.arr_obj(0))
            .unwrap_or(&srv_empty);
        let mut sb = Json::obj();
        sb.set("type", Json::str("socks"));
        sb.set("tag", Json::str(tag));
        sb.set("server", opt_or_null(srv, "address"));
        sb.set("server_port", opt_or_null(srv, "port"));
        if let Some(users) = srv.opt_arr("users")
            && users.len() > 0 {
                let u0_empty = Json::obj();
                let u0 = users.arr_obj(0).unwrap_or(&u0_empty);
                sb.set("username", Json::str(u0.opt_str("user", "")));
                sb.set("password", Json::str(u0.opt_str("pass", "")));
            }
        match srv.opt("version") {
            None | Some(Json::Null) => {}
            Some(ver) => {
                let v = ver.to_string_value().replace("socks", "");
                if v == "4" || v == "4a" || v == "5" {
                    sb.set("version", Json::str(v));
                }
            }
        }
        if srv.opt_bool("uot", false) {
            let mut uot = Json::obj();
            uot.set("enabled", Json::bool(true));
            sb.set("udp_over_tcp", uot);
        }
        apply_proxy_settings(&mut sb, o);
        apply_sockopt(&mut sb, Some(stream));
        return OutboundResult {
            sb: Some(sb),
            kind: Some("proxy"),
        };
    }

    if proto == "http" {
        let srv_empty = Json::obj();
        let srv = settings
            .opt_arr("servers")
            .and_then(|a| a.arr_obj(0))
            .unwrap_or(&srv_empty);
        let mut sb = Json::obj();
        sb.set("type", Json::str("http"));
        sb.set("tag", Json::str(tag));
        sb.set("server", opt_or_null(srv, "address"));
        sb.set("server_port", opt_or_null(srv, "port"));
        if let Some(users) = srv.opt_arr("users")
            && users.len() > 0 {
                let u0_empty = Json::obj();
                let u0 = users.arr_obj(0).unwrap_or(&u0_empty);
                sb.set("username", Json::str(u0.opt_str("user", "")));
                sb.set("password", Json::str(u0.opt_str("pass", "")));
            }
        if let Some(tls) = conv_tls(stream) {
            sb.set("tls", tls);
        }
        apply_proxy_settings(&mut sb, o);
        apply_sockopt(&mut sb, Some(stream));
        return OutboundResult {
            sb: Some(sb),
            kind: Some("proxy"),
        };
    }

    OutboundResult {
        sb: None,
        kind: None,
    }
}

// ---- inbound ----

struct InboundResult {
    sb: Option<Json>,
    sniff_resolves: bool,
}

fn conv_inbound(inb: &Json) -> InboundResult {
    let proto = inb.opt_str("protocol", "");
    let sniff_empty = Json::obj();
    let sniff = inb.opt_obj("sniffing").unwrap_or(&sniff_empty);
    let sniff_enabled = sniff.opt_bool("enabled", false);
    let has_dest_override = match sniff.opt_arr("destOverride") {
        Some(d) => d.len() > 0,
        None => false,
    };
    let route_only = sniff.opt_bool("routeOnly", false);
    let sniff_resolves = sniff_enabled && has_dest_override && !route_only;

    let listen_port = parse_listen_port(inb.opt("port"));

    if proto == "dokodemo-door" {
        let ds_empty = Json::obj();
        let ds = inb.opt_obj("settings").unwrap_or(&ds_empty);
        let mut sb = Json::obj();
        sb.set("type", Json::str("direct"));
        sb.set("tag", Json::str(inb.opt_str("tag", "direct-in")));
        sb.set("listen", Json::str(inb.opt_str("listen", "0.0.0.0")));
        match listen_port {
            Some(p) => sb.set("listen_port", Json::int(p)),
            None => sb.set("listen_port", Json::Null),
        }
        let net = ds.opt_str("network", "tcp");
        if net == "tcp" || net == "udp" {
            sb.set("network", Json::str(net));
        }
        let addr = ds.opt("address");
        if is_truthy(addr) {
            sb.set("override_address", addr.cloned().unwrap());
        }
        let port = ds.opt("port");
        if is_truthy(port) {
            sb.set("override_port", port.cloned().unwrap());
        }
        return InboundResult {
            sb: Some(sb),
            sniff_resolves,
        };
    }

    if matches!(proto.as_str(), "vmess" | "vless" | "trojan" | "shadowsocks") {
        return InboundResult {
            sb: None,
            sniff_resolves: false,
        };
    }
    if !matches!(proto.as_str(), "socks" | "http" | "mixed") {
        return InboundResult {
            sb: None,
            sniff_resolves: false,
        };
    }
    let listen_port = match listen_port {
        Some(p) => p,
        None => {
            return InboundResult {
                sb: None,
                sniff_resolves: false,
            }
        }
    };

    let mut sb = Json::obj();
    sb.set("type", Json::str(proto.clone()));
    sb.set("tag", Json::str(inb.opt_str("tag", &proto)));
    sb.set("listen", Json::str(inb.opt_str("listen", "127.0.0.1")));
    sb.set("listen_port", Json::int(listen_port));
    if let Some(settings) = inb.opt_obj("settings")
        && let Some(accounts) = settings.opt_arr("accounts")
            && accounts.len() > 0 {
                let mut users: Vec<Json> = Vec::new();
                for i in 0..accounts.len() {
                    let a = match accounts.arr_obj(i) {
                        Some(a) => a,
                        None => continue,
                    };
                    let mut u = Json::obj();
                    u.set("username", Json::str(a.opt_str("user", "")));
                    u.set("password", Json::str(a.opt_str("pass", "")));
                    users.push(u);
                }
                sb.set("users", Json::Arr(users));
            }
    InboundResult {
        sb: Some(sb),
        sniff_resolves,
    }
}

// ---- wireguard endpoint ----

fn conv_wireguard(o: &Json, settings: &Json, tag: &str) -> Json {
    let mut addresses: Vec<Json> = Vec::new();
    match settings.opt("address") {
        Some(Json::Arr(a)) => {
            for e in a {
                if !matches!(e, Json::Null) {
                    addresses.push(e.clone());
                }
            }
        }
        Some(Json::Str(s))
            if !s.is_empty() => {
                addresses.push(Json::str(s.clone()));
            }
        _ => {}
    }
    let mut ep = Json::obj();
    ep.set("type", Json::str("wireguard"));
    ep.set("tag", Json::str(tag));
    if !addresses.is_empty() {
        ep.set("address", Json::Arr(addresses));
    } else {
        ep.set("address", Json::Arr(vec![Json::str("10.0.0.2/32")]));
    }
    ep.set("private_key", Json::str(settings.opt_str("secretKey", "")));
    let mtu_val = settings.opt("mtu");
    if is_truthy(mtu_val)
        && let Some(mtu) = mtu_val.and_then(num_to_int) {
            ep.set("mtu", Json::int(mtu));
        }
    let workers_val = settings.opt("workers");
    if is_truthy(workers_val)
        && let Some(w) = workers_val.and_then(num_to_int) {
            ep.set("workers", Json::int(w));
        }
    let reserved_val = settings.opt("reserved");
    if is_truthy(reserved_val) {
        ep.set("reserved", reserved_val.cloned().unwrap());
    }
    let mut peers: Vec<Json> = Vec::new();
    if let Some(peer_arr) = settings.opt_arr("peers") {
        for i in 0..peer_arr.len() {
            let p = match peer_arr.arr_obj(i) {
                Some(p) => p,
                None => continue,
            };
            let endpoint = p.opt_str("endpoint", "");
            let hp = split_host_port(&endpoint);
            let mut peer = Json::obj();
            peer.set("address", Json::str(hp.host));
            peer.set("port", Json::int(hp.port.unwrap_or(0)));
            peer.set("public_key", Json::str(p.opt_str("publicKey", "")));
            match p.opt_arr("allowedIPs") {
                Some(allowed) if allowed.len() > 0 => peer.set("allowed_ips", allowed.clone()),
                _ => peer.set(
                    "allowed_ips",
                    Json::Arr(vec![Json::str("0.0.0.0/0"), Json::str("::/0")]),
                ),
            }
            let psk = p.opt_str("preSharedKey", "");
            if !psk.is_empty() {
                peer.set("pre_shared_key", Json::str(psk));
            }
            let ka = p.opt("keepAlive");
            if is_truthy(ka)
                && let Some(v) = ka.and_then(num_to_int) {
                    peer.set("persistent_keepalive_interval", Json::int(v));
                }
            let peer_reserved = p.opt("reserved");
            if is_truthy(peer_reserved) {
                peer.set("reserved", peer_reserved.cloned().unwrap());
            }
            peers.push(peer);
        }
    }
    if !peers.is_empty() {
        ep.set("peers", Json::Arr(peers));
    }
    apply_proxy_settings(&mut ep, o);
    apply_sockopt(&mut ep, o.opt_obj("streamSettings"));
    ep
}

// ---- routing rules ----

fn conv_route_rules(
    routing: &Json,
    balancer_map: &HashMap<String, String>,
    special_remap: &HashMap<String, (String, Option<Json>)>,
    special_tag_drop: &HashSet<String>,
    rule_sets: &mut BTreeSet<String>,
) -> Vec<Json> {
    let mut out: Vec<Json> = Vec::new();
    let rules = match routing.opt_arr("rules") {
        Some(r) => r,
        None => return out,
    };
    for i in 0..rules.len() {
        let r = match rules.arr_obj(i) {
            Some(r) => r,
            None => continue,
        };
        let type_field = r.opt_str("type", "");
        if !type_field.is_empty() && type_field != "field" {
            continue;
        }
        let mut sb = Json::obj();
        if r.has("balancerTag") {
            let bt = r.opt_str("balancerTag", "");
            if special_tag_drop.contains(&bt) {
                continue;
            }
            sb.set(
                "outbound",
                Json::str(balancer_map.get(&bt).cloned().unwrap_or(bt)),
            );
        } else if r.has("outboundTag") {
            let tgt = r.opt_str("outboundTag", "");
            if special_tag_drop.contains(&tgt) {
                continue;
            }
            match special_remap.get(&tgt) {
                Some((action, extra)) => {
                    sb.set("action", Json::str(action.clone()));
                    if let Some(extra) = extra {
                        for k in extra.keys() {
                            sb.set(k.clone(), extra.opt(&k).cloned().unwrap_or(Json::Null));
                        }
                    }
                }
                None => {
                    sb.set("outbound", Json::str(tgt));
                }
            }
        } else {
            continue;
        }

        let in_tags = as_string_list(r.opt("inboundTag"));
        if !in_tags.is_empty() {
            sb.set("inbound", str_arr(&in_tags));
        }
        if r.has("protocol") {
            let protos = as_string_list(r.opt("protocol"));
            sb.set("protocol", str_arr(&protos));
        }
        if r.has("network") {
            let net_raw = r.opt("network");
            let mut nets: Vec<String> = Vec::new();
            let src: Vec<String> = match net_raw {
                Some(Json::Str(s)) => s.split(',').map(|x| x.to_string()).collect(),
                other => as_string_list(other),
            };
            for nx in src {
                let t = nx.trim();
                if t == "tcp" || t == "udp" {
                    nets.push(t.to_string());
                }
            }
            if !nets.is_empty() {
                sb.set("network", str_arr(&nets));
            }
        }
        if r.has("port") {
            let pl = parse_port_list(r.opt("port"));
            if !pl.ports.is_empty() {
                sb.set("port", int_arr(&pl.ports));
            }
            if !pl.ranges.is_empty() {
                sb.set("port_range", str_arr(&pl.ranges));
            }
        }
        if r.has("sourcePort") {
            let sp = parse_port_list(r.opt("sourcePort"));
            if !sp.ports.is_empty() {
                sb.set("source_port", int_arr(&sp.ports));
            }
            if !sp.ranges.is_empty() {
                sb.set("source_port_range", str_arr(&sp.ranges));
            }
        }
        if r.has("source") {
            let ip_split = split_ips(&as_list(r.opt("source")));
            if !ip_split.ip_cidr.is_empty() {
                sb.set("source_ip_cidr", str_arr(&ip_split.ip_cidr));
            }
            if ip_split.ip_is_private {
                sb.set("source_ip_is_private", Json::bool(true));
            }
        }
        if r.has("domain") {
            let d = split_domains(&as_list(r.opt("domain")));
            apply_domain_split(&mut sb, &d, rule_sets);
        }
        if r.has("ip") {
            let ip_split = split_ips(&as_list(r.opt("ip")));
            if !ip_split.ip_cidr.is_empty() {
                sb.set("ip_cidr", str_arr(&ip_split.ip_cidr));
            }
            if ip_split.ip_is_private {
                sb.set("ip_is_private", Json::bool(true));
            }
            apply_geoip_to_rule_set(&mut sb, &ip_split.geoip, rule_sets);
        }
        if r.has("user") {
            sb.set("auth_user", str_arr(&as_string_list(r.opt("user"))));
        }
        if r.has("process") {
            sb.set("process_name", str_arr(&as_string_list(r.opt("process"))));
        }

        out.push(sb);
    }
    out
}

// ---- DNS ----

struct DnsAddr {
    typ: Option<String>,
    fields: Json,
}

fn parse_dns_address(addr_raw: &str) -> DnsAddr {
    if addr_raw.is_empty() {
        return DnsAddr {
            typ: None,
            fields: Json::obj(),
        };
    }
    let s = addr_raw.trim();

    if s == "fakedns" {
        return DnsAddr {
            typ: Some("fakeip".to_string()),
            fields: Json::obj(),
        };
    }
    if s == "localhost" {
        return DnsAddr {
            typ: Some("local".to_string()),
            fields: Json::obj(),
        };
    }
    if s.starts_with("rcode://") {
        return DnsAddr {
            typ: None,
            fields: Json::obj(),
        };
    }

    if s.contains("://") {
        let (scheme_raw, rest) = s.split_once("://").unwrap();
        let scheme = scheme_raw
            .to_ascii_lowercase()
            .replace("+local", "")
            .replace("+udp", "");
        if scheme == "https" {
            let (host_port, path) = match rest.find('/') {
                Some(idx) => (&rest[..idx], &rest[idx + 1..]),
                None => (rest, ""),
            };
            let hp = split_host_port(host_port);
            let mut f = Json::obj();
            f.set("server", Json::str(hp.host));
            if let Some(p) = hp.port {
                f.set("server_port", Json::int(p));
            }
            if !path.is_empty() {
                f.set("path", Json::str(format!("/{}", path)));
            }
            return DnsAddr {
                typ: Some("https".to_string()),
                fields: f,
            };
        }
        if matches!(scheme.as_str(), "h3" | "https+h3" | "https3" | "http3") {
            let (host_port, path) = match rest.find('/') {
                Some(idx) => (&rest[..idx], &rest[idx + 1..]),
                None => (rest, ""),
            };
            let hp = split_host_port(host_port);
            let mut f = Json::obj();
            f.set("server", Json::str(hp.host));
            if let Some(p) = hp.port {
                f.set("server_port", Json::int(p));
            }
            if !path.is_empty() {
                f.set("path", Json::str(format!("/{}", path)));
            }
            return DnsAddr {
                typ: Some("http3".to_string()),
                fields: f,
            };
        }
        if matches!(scheme.as_str(), "tls" | "quic" | "tcp" | "udp") {
            let hp = split_host_port(rest);
            let mut f = Json::obj();
            f.set("server", Json::str(hp.host));
            if let Some(p) = hp.port {
                f.set("server_port", Json::int(p));
            }
            return DnsAddr {
                typ: Some(scheme),
                fields: f,
            };
        }
        if scheme == "dhcp" {
            let mut f = Json::obj();
            if !rest.is_empty() && rest != "auto" {
                f.set("interface", Json::str(rest));
            }
            return DnsAddr {
                typ: Some("dhcp".to_string()),
                fields: f,
            };
        }
        return DnsAddr {
            typ: None,
            fields: Json::obj(),
        };
    }

    let hp = split_host_port(s);
    let mut f = Json::obj();
    f.set("server", Json::str(hp.host));
    if let Some(p) = hp.port {
        f.set("server_port", Json::int(p));
    }
    DnsAddr {
        typ: Some("udp".to_string()),
        fields: f,
    }
}

fn make_dns_rule(obj: &Json, server_tag: &str, rule_sets: &mut BTreeSet<String>) -> Option<Json> {
    let domains = as_list(obj.opt("domains"));
    if domains.is_empty() {
        return None;
    }
    let mut rule = Json::obj();
    rule.set("server", Json::str(server_tag));
    let ds = split_domains(&domains);
    apply_domain_split(&mut rule, &ds, rule_sets);
    Some(rule)
}

fn fakeip_ranges(fakedns_obj: Option<&Json>) -> (String, String) {
    let pools: Vec<&Json> = match fakedns_obj {
        None | Some(Json::Null) => {
            return ("198.18.0.0/15".to_string(), "fc00::/18".to_string());
        }
        Some(Json::Arr(a)) => {
            let mut v = Vec::new();
            for e in a {
                if matches!(e, Json::Obj(_)) {
                    v.push(e);
                }
            }
            v
        }
        Some(o @ Json::Obj(_)) => vec![o],
        Some(_) => Vec::new(),
    };
    let mut v4 = "198.18.0.0/15".to_string();
    let mut v6 = "fc00::/18".to_string();
    for p in pools {
        let pool = p.opt_str("ipPool", "");
        if pool.contains('.') && !pool.contains(':') {
            v4 = pool;
        } else if pool.contains(':') {
            v6 = pool;
        }
    }
    (v4, v6)
}

fn conv_dns(
    xray_dns: Option<&Json>,
    fakedns_obj: Option<&Json>,
    dns_detour: Option<&str>,
    rule_sets: &mut BTreeSet<String>,
) -> Json {
    let mut out_servers: Vec<Json> = Vec::new();
    let mut out_rules: Vec<Json> = Vec::new();
    let cs = xray_dns.map(|d| d.opt_str("clientIp", "")).unwrap_or_default();

    let mut seen_tags: HashSet<String> = HashSet::new();
    let mut has_local = false;
    let mut has_fakeip = false;
    let mut fakeip_tag: Option<String> = None;
    let mut n = 0i64;

    let servers_empty = Json::arr();
    let servers_arr = xray_dns
        .and_then(|d| d.opt_arr("servers"))
        .unwrap_or(&servers_empty);
    let empty_obj = Json::obj();

    for i in 0..servers_arr.len() {
        let (addr_raw, obj): (String, &Json) = match servers_arr.arr_opt(i) {
            Some(Json::Str(s)) => (s.clone(), &empty_obj),
            Some(o @ Json::Obj(_)) => (o.opt_str("address", ""), o),
            _ => continue,
        };

        let parsed = parse_dns_address(&addr_raw);
        let st = match parsed.typ {
            Some(t) => t,
            None => continue,
        };

        let mut srv = Json::obj();
        srv.set("type", Json::str(st.clone()));
        let mut tag = obj.opt_str("tag", "");
        if st == "local" {
            tag = "local".to_string();
        }
        if tag.is_empty() {
            tag = format!("dns-{}", n);
            n += 1;
        }
        while seen_tags.contains(&tag) {
            tag = format!("{}-{}", tag, n);
            n += 1;
        }
        seen_tags.insert(tag.clone());
        srv.set("tag", Json::str(tag.clone()));

        for k in parsed.fields.keys() {
            srv.set(k.clone(), parsed.fields.opt(&k).cloned().unwrap_or(Json::Null));
        }
        if !srv.has("server_port") {
            let v = obj.opt("port");
            if is_truthy(v)
                && let Some(p) = v.and_then(num_to_int) {
                    srv.set("server_port", Json::int(p));
                }
        }

        let sqs = obj.opt_str("queryStrategy", "");
        if !sqs.is_empty()
            && let Some(mapped) = query_strategy_map(&sqs) {
                srv.set("strategy", Json::str(mapped));
            }
        let sci = obj.opt_str("clientIP", "");
        if !sci.is_empty() {
            srv.set("client_subnet", Json::str(sci));
        }

        if is_encrypted_dns_type(&st) {
            if let Some(det) = dns_detour {
                srv.set("detour", Json::str(det));
            }
            srv.set("domain_resolver", Json::str("local"));
        } else if st == "udp" {
            if let Some(det) = dns_detour {
                srv.set("detour", Json::str(det));
            }
        } else if st == "local" {
            has_local = true;
        } else if st == "fakeip" {
            let (r4, r6) = fakeip_ranges(fakedns_obj);
            srv.set("inet4_range", Json::str(r4));
            srv.set("inet6_range", Json::str(r6));
            has_fakeip = true;
            fakeip_tag = Some(tag.clone());
        }
        out_servers.push(srv);

        if let Some(mut rule) = make_dns_rule(obj, &tag, rule_sets) {
            if st == "fakeip" && !rule.has("query_type") {
                rule.set("query_type", Json::Arr(vec![Json::str("A"), Json::str("AAAA")]));
            }
            out_rules.push(rule);
        }
    }

    if let Some(hosts) = xray_dns.and_then(|d| d.opt_obj("hosts"))
        && hosts.len() > 0 {
            let mut predefined = Json::obj();
            for host in hosts.keys() {
                let v = hosts.opt(&host);
                let ips_list: Vec<Json> = match v {
                    Some(Json::Str(_)) => vec![v.cloned().unwrap()],
                    Some(Json::Arr(a)) => a.clone(),
                    _ => Vec::new(),
                };
                let mut ips_only: Vec<String> = Vec::new();
                for it in &ips_list {
                    if is_ip_literal(Some(it)) {
                        ips_only.push(match it {
                            Json::Str(s) => s.clone(),
                            other => other.to_string_value(),
                        });
                    }
                }
                if !ips_only.is_empty() {
                    predefined.set(host.clone(), str_arr(&ips_only));
                }
            }
            if predefined.len() > 0 {
                let mut hosts_srv = Json::obj();
                hosts_srv.set("type", Json::str("hosts"));
                hosts_srv.set("tag", Json::str("hosts"));
                hosts_srv.set("predefined", predefined.clone());
                let mut new_servers = vec![hosts_srv];
                new_servers.append(&mut out_servers);
                out_servers = new_servers;

                let host_keys: Vec<String> = predefined.keys();
                let mut rule = Json::obj();
                rule.set("domain", str_arr(&host_keys));
                rule.set("server", Json::str("hosts"));
                let mut new_rules = vec![rule];
                new_rules.append(&mut out_rules);
                out_rules = new_rules;
            }
        }

    if !has_local {
        let mut local = Json::obj();
        local.set("type", Json::str("local"));
        local.set("tag", Json::str("local"));
        out_servers.push(local);
    }

    if has_fakeip
        && let Some(ft) = &fakeip_tag {
            let mut has_fakeip_rule = false;
            for r in &out_rules {
                if r.opt_str("server", "") == *ft {
                    has_fakeip_rule = true;
                    break;
                }
            }
            if !has_fakeip_rule {
                let mut rule = Json::obj();
                rule.set("query_type", Json::Arr(vec![Json::str("A"), Json::str("AAAA")]));
                rule.set("server", Json::str(ft.clone()));
                out_rules.push(rule);
            }
        }

    let mut final_tag: Option<String> = None;
    for s in &out_servers {
        if !is_remote_dns_type(&s.opt_str("type", "")) {
            continue;
        }
        match dns_detour {
            None => {
                final_tag = Some(s.opt_str("tag", ""));
                break;
            }
            Some(det) => {
                if s.opt_str("detour", "") == det {
                    final_tag = Some(s.opt_str("tag", ""));
                    break;
                }
            }
        }
    }
    if final_tag.is_none() {
        for s in &out_servers {
            if is_remote_dns_type(&s.opt_str("type", "")) {
                final_tag = Some(s.opt_str("tag", ""));
                break;
            }
        }
    }
    if final_tag.is_none() && !out_servers.is_empty() {
        final_tag = out_servers.first().map(|s| s.opt_str("tag", ""));
    }

    let mut out = Json::obj();
    out.set("servers", Json::Arr(out_servers));
    out.set("rules", Json::Arr(out_rules));
    if !cs.is_empty() {
        out.set("client_subnet", Json::str(cs));
    }
    if let Some(ft) = final_tag
        && !ft.is_empty() {
            out.set("final", Json::str(ft));
        }
    out
}

// ---- tag uniqueness ----

fn make_unique_tag(base: &str, used: &HashSet<String>) -> String {
    if !used.contains(base) {
        return base.to_string();
    }
    let mut i = 2;
    loop {
        let cand = format!("{} ({})", base, i);
        if !used.contains(&cand) {
            return cand;
        }
        i += 1;
    }
}

fn dedupe_by_tag(items: Vec<Json>, used: &mut HashSet<String>) -> Vec<Json> {
    let mut out = Vec::new();
    for it in items {
        let t = it.opt_str("tag", "");
        if t.is_empty() || used.contains(&t) {
            continue;
        }
        used.insert(t);
        out.push(it);
    }
    out
}

// ---- main assembly ----

fn convert_object(xray: &Json, name_fallback: &str) -> Option<Json> {
    let mut inbounds: Vec<Json> = Vec::new();
    let mut used_inb_tags: HashSet<String> = HashSet::new();
    let mut resolve_inbounds: Vec<String> = Vec::new();

    if let Some(xray_inbounds) = xray.opt_arr("inbounds") {
        for i in 0..xray_inbounds.len() {
            let inb = match xray_inbounds.arr_obj(i) {
                Some(v) => v,
                None => continue,
            };
            let result = conv_inbound(inb);
            let mut sb_inb = match result.sb {
                Some(s) => s,
                None => continue,
            };
            let t = sb_inb.opt_str("tag", "");
            let base = if t.is_empty() {
                sb_inb.opt_str("type", "in")
            } else {
                t
            };
            let tag = make_unique_tag(&base, &used_inb_tags);
            sb_inb.set("tag", Json::str(tag.clone()));
            used_inb_tags.insert(tag.clone());
            inbounds.push(sb_inb);
            if result.sniff_resolves {
                resolve_inbounds.push(tag);
            }
        }
    }

    let remarks = {
        let mut r = xray.opt_str("remarks", "");
        if r.is_empty() {
            r = xray.opt_str("name", "");
            if r.is_empty() {
                r = name_fallback.to_string();
            }
        }
        r.trim().to_string()
    };

    let outs_raw = xray.opt_arr("outbounds");

    let mut xray_proxies: Vec<&Json> = Vec::new();
    if let Some(outs) = outs_raw {
        for i in 0..outs.len() {
            let o = match outs.arr_obj(i) {
                Some(v) => v,
                None => continue,
            };
            if is_xray_proxy_protocol(&o.opt_str("protocol", "")) && is_outbound_supported(o) {
                xray_proxies.push(o);
            }
        }
    }

    let mut rename: HashMap<String, String> = HashMap::new();
    if !remarks.is_empty() {
        if xray_proxies.len() == 1 {
            let only_tag = xray_proxies[0].opt_str("tag", "").trim().to_string();
            rename.insert(only_tag, remarks.clone());
        } else if xray_proxies.len() > 1 {
            for p in &xray_proxies {
                let orig_tag = p.opt_str("tag", "").trim().to_string();
                let new_tag = if orig_tag.is_empty() {
                    remarks.clone()
                } else {
                    format!("{} #{}", remarks, orig_tag)
                };
                rename.insert(orig_tag, new_tag);
            }
        }
    }

    let mut proxy_outs: Vec<Json> = Vec::new();
    let mut proxy_tags: Vec<String> = Vec::new();
    let mut aux_outs: Vec<Json> = Vec::new();
    let mut endpoints: Vec<Json> = Vec::new();
    let mut special_remap: HashMap<String, (String, Option<Json>)> = HashMap::new();
    let mut special_tag_drop: HashSet<String> = HashSet::new();

    if let Some(outs) = outs_raw {
        for i in 0..outs.len() {
            let o = match outs.arr_obj(i) {
                Some(v) => v,
                None => continue,
            };
            let otag = o.opt_str("tag", "");
            let proto = o.opt_str("protocol", "");
            match proto.as_str() {
                "blackhole" => {
                    special_remap.insert(otag, ("reject".to_string(), None));
                    continue;
                }
                "dns" => {
                    special_remap.insert(otag, ("hijack-dns".to_string(), None));
                    continue;
                }
                "loopback" => {
                    special_tag_drop.insert(otag);
                    continue;
                }
                _ => {}
            }
            if is_xray_proxy_protocol(&proto) && !is_outbound_supported(o) {
                special_tag_drop.insert(otag);
                continue;
            }
            let r = conv_outbound(o);
            let mut c = match r.sb {
                Some(c) => c,
                None => continue,
            };
            match r.kind {
                Some("wireguard") => {
                    let c_tag = c.opt_str("tag", "");
                    let new_tag = rename.get(&c_tag).cloned().unwrap_or(c_tag);
                    c.set("tag", Json::str(new_tag.clone()));
                    endpoints.push(c);
                    proxy_tags.push(new_tag);
                }
                Some("aux") => {
                    aux_outs.push(c);
                }
                _ => {
                    let c_tag = c.opt_str("tag", "");
                    let new_tag = rename.get(&c_tag).cloned().unwrap_or(c_tag);
                    c.set("tag", Json::str(new_tag.clone()));
                    proxy_outs.push(c);
                    proxy_tags.push(new_tag);
                }
            }
        }
    }

    if proxy_outs.is_empty() && endpoints.is_empty() {
        return None;
    }

    let has_direct = aux_outs
        .iter()
        .any(|it| it.opt_str("type", "") == "direct" && it.opt_str("tag", "") == "direct");
    if !has_direct {
        let mut direct = Json::obj();
        direct.set("type", Json::str("direct"));
        direct.set("tag", Json::str("direct"));
        aux_outs.push(direct);
    }

    for o in proxy_outs
        .iter_mut()
        .chain(endpoints.iter_mut())
        .chain(aux_outs.iter_mut())
    {
        let d = o.opt_str("detour", "");
        if !d.is_empty() {
            if special_tag_drop.contains(&d) || special_remap.contains_key(&d) {
                o.remove("detour");
            } else if let Some(mapped) = rename.get(&d) {
                o.set("detour", Json::str(mapped.clone()));
            }
        }
    }

    let routing_empty = Json::obj();
    let routing = xray.opt_obj("routing").unwrap_or(&routing_empty);
    let obs_empty = Json::obj();
    let obs = xray
        .opt_obj("burstObservatory")
        .or_else(|| xray.opt_obj("observatory"))
        .unwrap_or(&obs_empty);
    let ping_empty = Json::obj();
    let ping_cfg = obs.opt_obj("pingConfig").unwrap_or(&ping_empty);
    let test_url = ping_cfg.opt_str("destination", "");
    let test_interval = ping_cfg.opt_str("interval", "");

    let mut balancer_outs: Vec<Json> = Vec::new();
    let mut balancer_map: HashMap<String, String> = HashMap::new();
    let mut primary_balancer: Option<String> = None;
    if let Some(balancers) = routing.opt_arr("balancers") {
        for i in 0..balancers.len() {
            let b = match balancers.arr_obj(i) {
                Some(b) => b,
                None => continue,
            };
            let btag = b.opt_str("tag", "");
            if btag.is_empty() {
                continue;
            }
            let mut prefixes: Vec<String> = Vec::new();
            if let Some(prefixes_arr) = b.opt_arr("selector") {
                for j in 0..prefixes_arr.len() {
                    if let Some(Json::Str(s)) = prefixes_arr.arr_opt(j) {
                        prefixes.push(s.clone());
                    }
                }
            }
            let orig_match: Vec<String> = if !prefixes.is_empty() {
                xray_proxies
                    .iter()
                    .filter_map(|p| {
                        let t = p.opt_str("tag", "");
                        if !t.is_empty() && prefixes.iter().any(|pf| t.starts_with(pf)) {
                            Some(t)
                        } else {
                            None
                        }
                    })
                    .collect()
            } else {
                xray_proxies
                    .iter()
                    .filter_map(|p| {
                        let t = p.opt_str("tag", "");
                        if !t.is_empty() {
                            Some(t)
                        } else {
                            None
                        }
                    })
                    .collect()
            };
            let mut members: Vec<String> = orig_match
                .iter()
                .map(|it| rename.get(it).cloned().unwrap_or_else(|| it.clone()))
                .collect();
            if members.is_empty() {
                members = proxy_tags.clone();
            }
            if members.is_empty() {
                special_tag_drop.insert(btag);
                continue;
            }

            let mut bb = Json::obj();
            bb.set("type", Json::str("urltest"));
            bb.set("tag", Json::str(btag.clone()));
            bb.set("outbounds", str_arr(&members));
            if !test_url.is_empty() {
                bb.set("url", Json::str(test_url.clone()));
            }
            if !test_interval.is_empty() {
                bb.set("interval", Json::str(test_interval.clone()));
            }
            balancer_outs.push(bb);
            balancer_map.insert(btag.clone(), btag.clone());
            if primary_balancer.is_none() {
                primary_balancer = Some(btag.clone());
            }
        }
    }

    let mut selector_tag = if !remarks.is_empty() {
        remarks.clone()
    } else {
        "select".to_string()
    };
    let mut existing_tags: HashSet<String> = proxy_tags.iter().cloned().collect();
    for b in &balancer_outs {
        existing_tags.insert(b.opt_str("tag", ""));
    }
    for a in &aux_outs {
        existing_tags.insert(a.opt_str("tag", ""));
    }
    while existing_tags.contains(&selector_tag) {
        selector_tag.push_str(" \u{2299}");
    }

    let mut selector: Option<Json> = None;
    let need_selector = proxy_tags.len() > 1 || !balancer_outs.is_empty();
    if !proxy_tags.is_empty() && need_selector {
        let mut sel = Json::obj();
        sel.set("type", Json::str("selector"));
        sel.set("tag", Json::str(selector_tag.clone()));
        let mut outs_arr: Vec<Json> = Vec::new();
        for b in &balancer_outs {
            outs_arr.push(Json::str(b.opt_str("tag", "")));
        }
        for t in &proxy_tags {
            outs_arr.push(Json::str(t.clone()));
        }
        sel.set("outbounds", Json::Arr(outs_arr));
        let default = if !balancer_outs.is_empty() {
            balancer_outs[0].opt_str("tag", "")
        } else {
            proxy_tags[0].clone()
        };
        sel.set("default", Json::str(default));
        selector = Some(sel);
    }

    let selector_present = selector.is_some();
    let mut sb_outbounds: Vec<Json> = Vec::new();
    if let Some(sel) = selector {
        sb_outbounds.push(sel);
    }
    sb_outbounds.extend(balancer_outs);
    sb_outbounds.extend(proxy_outs);
    sb_outbounds.extend(aux_outs);

    let mut used_out_tags: HashSet<String> = HashSet::new();
    let sb_outbounds = dedupe_by_tag(sb_outbounds, &mut used_out_tags);
    let endpoints_dedup = dedupe_by_tag(endpoints, &mut used_out_tags);

    let final_tag: String = if selector_present {
        selector_tag.clone()
    } else if let Some(pb) = &primary_balancer {
        pb.clone()
    } else {
        proxy_tags
            .iter()
            .find(|t| !t.is_empty())
            .cloned()
            .unwrap_or_else(|| "direct".to_string())
    };

    let dns_detour: Option<String> = proxy_tags.iter().find(|t| !t.is_empty()).cloned();
    let rule_set_download_detour = "direct";
    let mut required_rule_sets: BTreeSet<String> = BTreeSet::new();

    let mut route_rules = conv_route_rules(
        routing,
        &balancer_map,
        &special_remap,
        &special_tag_drop,
        &mut required_rule_sets,
    );
    for r in route_rules.iter_mut() {
        let ob = r.opt_str("outbound", "");
        if !ob.is_empty()
            && let Some(mapped) = rename.get(&ob) {
                r.set("outbound", Json::str(mapped.clone()));
            }
    }

    let mut pre_rules: Vec<Json> = Vec::new();
    {
        let mut r = Json::obj();
        r.set("action", Json::str("sniff"));
        pre_rules.push(r);
    }
    {
        let mut r = Json::obj();
        r.set("protocol", Json::str("dns"));
        r.set("action", Json::str("hijack-dns"));
        pre_rules.push(r);
    }
    {
        let mut r = Json::obj();
        r.set("port", Json::Arr(vec![Json::int(53)]));
        r.set("action", Json::str("hijack-dns"));
        pre_rules.push(r);
    }
    if !resolve_inbounds.is_empty() {
        let mut r = Json::obj();
        r.set("inbound", str_arr(&resolve_inbounds));
        r.set("action", Json::str("resolve"));
        pre_rules.push(r);
    }

    let mut route = Json::obj();
    let mut all_rules: Vec<Json> = Vec::new();
    for r in pre_rules {
        all_rules.push(r);
    }
    for r in route_rules {
        all_rules.push(r);
    }
    route.set("rules", Json::Arr(all_rules));
    route.set("auto_detect_interface", Json::bool(true));
    route.set("final", Json::str(final_tag.clone()));
    let mut ddr = Json::obj();
    ddr.set("server", Json::str("local"));
    let ds = routing.opt_str("domainStrategy", "");
    let ds_mapped = domain_strategy_map(ds.trim()).unwrap_or("");
    if !ds_mapped.is_empty() {
        ddr.set("strategy", Json::str(ds_mapped));
    } else if let Some(xray_dns_obj) = xray.opt_obj("dns") {
        let qs = xray_dns_obj.opt_str("queryStrategy", "");
        if !qs.is_empty()
            && let Some(mapped) = query_strategy_map(&qs) {
                ddr.set("strategy", Json::str(mapped));
            }
    }
    route.set("default_domain_resolver", ddr);

    let mut fakedns_obj: Option<Json> = xray.opt("fakedns").cloned();
    if fakedns_obj.is_none() || matches!(fakedns_obj, Some(Json::Null)) {
        fakedns_obj = xray.opt_obj("dns").and_then(|d| d.opt("fakedns")).cloned();
    }
    let sb_dns = conv_dns(
        xray.opt_obj("dns"),
        fakedns_obj.as_ref(),
        dns_detour.as_deref(),
        &mut required_rule_sets,
    );

    if !required_rule_sets.is_empty() {
        let mut rs_arr: Vec<Json> = Vec::new();
        for tag in required_rule_sets.iter() {
            let mut rs = Json::obj();
            rs.set("type", Json::str("remote"));
            rs.set("tag", Json::str(tag.clone()));
            rs.set("format", Json::str("binary"));
            let url = if tag.starts_with("geosite-") {
                GEOSITE_URL_TEMPLATE.replace("{name}", tag)
            } else if tag.starts_with("geoip-") {
                GEOIP_URL_TEMPLATE.replace("{name}", tag)
            } else {
                continue;
            };
            rs.set("url", Json::str(url));
            rs.set("download_detour", Json::str(rule_set_download_detour));
            rs.set("update_interval", Json::str("1d"));
            rs_arr.push(rs);
        }
        route.set("rule_set", Json::Arr(rs_arr));
    }

    let xlog = xray
        .opt_obj("log")
        .map(|l| l.opt_str("loglevel", "warning"))
        .unwrap_or_else(|| "warning".to_string());
    let sb_log_level = log_level_map(&xlog);

    let mut config = Json::obj();
    let mut log_obj = Json::obj();
    log_obj.set("level", Json::str(sb_log_level));
    log_obj.set("timestamp", Json::bool(true));
    config.set("log", log_obj);
    config.set("dns", sb_dns);
    config.set("inbounds", Json::Arr(inbounds));
    config.set("outbounds", Json::Arr(sb_outbounds));
    config.set("route", route);
    let mut experimental = Json::obj();
    let mut cache_file = Json::obj();
    cache_file.set("enabled", Json::bool(true));
    experimental.set("cache_file", cache_file);
    config.set("experimental", experimental);
    if !endpoints_dedup.is_empty() {
        config.set("endpoints", Json::Arr(endpoints_dedup));
    }
    Some(config)
}

// ---- outbounds-only extraction ----

fn extract_proxy_outbounds(xray: &Json, name_fallback: &str) -> Option<Vec<Json>> {
    let remarks = {
        let mut r = xray.opt_str("remarks", "");
        if r.is_empty() {
            r = xray.opt_str("name", "");
            if r.is_empty() {
                r = name_fallback.to_string();
            }
        }
        r.trim().to_string()
    };

    let outs_raw = xray.opt_arr("outbounds")?;

    let mut supported_proxies: Vec<&Json> = Vec::new();
    for i in 0..outs_raw.len() {
        let o = match outs_raw.arr_obj(i) {
            Some(v) => v,
            None => continue,
        };
        let proto = o.opt_str("protocol", "");
        if !is_xray_proxy_protocol(&proto) {
            continue;
        }
        if !is_outbound_supported(o) {
            continue;
        }
        supported_proxies.push(o);
    }

    if supported_proxies.is_empty() {
        return None;
    }

    let mut results: Vec<Json> = Vec::new();
    let single_proxy = supported_proxies.len() == 1;

    for o in &supported_proxies {
        let r = conv_outbound(o);
        let mut sb = match r.sb {
            Some(s) => s,
            None => continue,
        };
        if r.kind == Some("aux") {
            continue;
        }
        sb.remove("detour");
        let original_tag = o.opt_str("tag", "").trim().to_string();
        let new_tag = if remarks.is_empty() {
            if original_tag.is_empty() {
                "proxy".to_string()
            } else {
                original_tag
            }
        } else if single_proxy || original_tag.is_empty() {
            remarks.clone()
        } else {
            format!("{} #{}", remarks, original_tag)
        };
        sb.set("tag", Json::str(new_tag));
        results.push(sb);
    }

    if results.is_empty() {
        None
    } else {
        Some(results)
    }
}

// ---- merge helpers ----

fn strip_fork_only_fields(cfg: &mut Json) {
    let mut exp = match cfg.opt_obj("experimental") {
        Some(e) => e.clone(),
        None => return,
    };
    if !matches!(exp.opt("cache_file"), Some(Json::Obj(_))) {
        return;
    }
    let mut cf = exp.opt_obj("cache_file").unwrap().clone();
    cf.remove("store_dns");
    exp.set("cache_file", cf);
    cfg.set("experimental", exp);
}

fn is_pre_rule(r: &Json) -> bool {
    let action = r.opt_str("action", "");
    if action == "sniff" && r.len() == 1 {
        return true;
    }
    if action == "hijack-dns" && (r.has("protocol") || r.has("port")) {
        return true;
    }
    if action == "resolve" && r.has("inbound") {
        return true;
    }
    false
}

fn rename_string(obj: &mut Json, key: &str, rename: &HashMap<String, String>) {
    let v = match obj.opt(key) {
        Some(Json::Str(s)) if !s.is_empty() => s.clone(),
        _ => return,
    };
    let mapped = match rename.get(&v) {
        Some(m) => m.clone(),
        None => return,
    };
    if mapped != v {
        obj.set(key, Json::str(mapped));
    }
}

fn rename_string_array(obj: &mut Json, key: &str, rename: &HashMap<String, String>) {
    let items: Vec<Json> = match obj.opt_arr(key) {
        Some(a) => (0..a.len())
            .map(|i| a.arr_opt(i).cloned().unwrap_or(Json::Null))
            .collect(),
        None => return,
    };
    let mut changed = false;
    let mut new_arr: Vec<Json> = Vec::with_capacity(items.len());
    for item in items {
        if let Json::Str(s) = &item
            && let Some(mapped) = rename.get(s)
                && mapped != s {
                    new_arr.push(Json::str(mapped.clone()));
                    changed = true;
                    continue;
                }
        new_arr.push(item);
    }
    if changed {
        obj.set(key, Json::Arr(new_arr));
    }
}

fn rewrite_domain_resolver(o: &mut Json, dns_rename: &HashMap<String, String>) {
    match o.opt("domain_resolver").cloned() {
        Some(Json::Str(v)) if !v.is_empty() => {
            if let Some(mapped) = dns_rename.get(&v)
                && *mapped != v {
                    o.set("domain_resolver", Json::str(mapped.clone()));
                }
        }
        Some(v) if matches!(v, Json::Obj(_)) => {
            let mut dr = v;
            rename_string(&mut dr, "server", dns_rename);
            o.set("domain_resolver", dr);
        }
        _ => {}
    }
}

fn rewrite_outbound(
    o: &mut Json,
    out_rename: &HashMap<String, String>,
    dns_rename: &HashMap<String, String>,
) {
    rename_string(o, "tag", out_rename);
    rename_string(o, "detour", out_rename);
    rename_string_array(o, "outbounds", out_rename);
    rename_string(o, "default", out_rename);
    rewrite_domain_resolver(o, dns_rename);
}

fn rewrite_dns_server(
    s: &mut Json,
    out_rename: &HashMap<String, String>,
    dns_rename: &HashMap<String, String>,
) {
    rename_string(s, "tag", dns_rename);
    rename_string(s, "detour", out_rename);
    rewrite_domain_resolver(s, dns_rename);
}

fn rewrite_dns_rule(
    r: &mut Json,
    out_rename: &HashMap<String, String>,
    dns_rename: &HashMap<String, String>,
) {
    rename_string(r, "server", dns_rename);
    rename_string(r, "outbound", out_rename);
}

fn rewrite_route_rule(
    r: &mut Json,
    out_rename: &HashMap<String, String>,
    dns_rename: &HashMap<String, String>,
) {
    rename_string(r, "outbound", out_rename);
    rename_string(r, "server", dns_rename);
}

// Merge several sing-box configs into one: rename tags, shared selector/urltest.
pub(crate) fn merge_unified(full_configs: &[Json]) -> Option<Json> {
    if full_configs.is_empty() {
        return None;
    }
    if full_configs.len() == 1 {
        let mut single = full_configs[0].clone();
        strip_fork_only_fields(&mut single);
        return Some(single);
    }

    let mut used_out_tags: HashSet<String> = HashSet::new();
    let mut used_dns_tags: HashSet<String> = HashSet::new();
    let mut used_rule_set_tags: HashSet<String> = HashSet::new();
    for t in ["proxy", "auto", "direct", "mixed-in"] {
        used_out_tags.insert(t.to_string());
    }
    used_dns_tags.insert("local".to_string());

    let mut out_renames: Vec<HashMap<String, String>> = Vec::new();
    let mut dns_renames: Vec<HashMap<String, String>> = Vec::new();

    for cfg in full_configs {
        let mut out_rename: HashMap<String, String> = HashMap::new();
        let mut dns_rename: HashMap<String, String> = HashMap::new();

        if let Some(outbounds) = cfg.opt_arr("outbounds") {
            for i in 0..outbounds.len() {
                let o = match outbounds.arr_obj(i) {
                    Some(o) => o,
                    None => continue,
                };
                let orig_tag = o.opt_str("tag", "");
                let typ = o.opt_str("type", "");
                if orig_tag.is_empty() {
                    continue;
                }
                if typ == "selector" || typ == "urltest" {
                    out_rename.insert(orig_tag, "proxy".to_string());
                    continue;
                }
                if typ == "direct" {
                    out_rename.insert(orig_tag, "direct".to_string());
                    continue;
                }
                let new_tag = make_unique_tag(&orig_tag, &used_out_tags);
                used_out_tags.insert(new_tag.clone());
                out_rename.insert(orig_tag, new_tag);
            }
        }
        if let Some(endpoints) = cfg.opt_arr("endpoints") {
            for i in 0..endpoints.len() {
                let o = match endpoints.arr_obj(i) {
                    Some(o) => o,
                    None => continue,
                };
                let orig_tag = o.opt_str("tag", "");
                if orig_tag.is_empty() {
                    continue;
                }
                let new_tag = make_unique_tag(&orig_tag, &used_out_tags);
                used_out_tags.insert(new_tag.clone());
                out_rename.insert(orig_tag, new_tag);
            }
        }
        if let Some(dns) = cfg.opt_obj("dns")
            && let Some(dns_servers) = dns.opt_arr("servers") {
                for i in 0..dns_servers.len() {
                    let s = match dns_servers.arr_obj(i) {
                        Some(s) => s,
                        None => continue,
                    };
                    let orig_tag = s.opt_str("tag", "");
                    if orig_tag.is_empty() {
                        continue;
                    }
                    if orig_tag == "local" && s.opt_str("type", "") == "local" {
                        dns_rename.insert(orig_tag, "local".to_string());
                        continue;
                    }
                    let new_tag = make_unique_tag(&orig_tag, &used_dns_tags);
                    used_dns_tags.insert(new_tag.clone());
                    dns_rename.insert(orig_tag, new_tag);
                }
            }
        out_renames.push(out_rename);
        dns_renames.push(dns_rename);
    }

    let mut leaf_outbounds: Vec<Json> = Vec::new();
    let mut leaf_outbound_tags: Vec<String> = Vec::new();
    let mut merged_endpoints: Vec<Json> = Vec::new();
    let mut merged_endpoint_tags: Vec<String> = Vec::new();
    let mut merged_dns_servers: Vec<Json> = Vec::new();
    let mut merged_dns_rules: Vec<Json> = Vec::new();
    let mut merged_route_rules: Vec<Json> = Vec::new();
    let mut merged_rule_set: Vec<Json> = Vec::new();
    let mut has_direct = false;
    let mut has_local = false;

    for (idx, cfg) in full_configs.iter().enumerate() {
        let out_r = &out_renames[idx];
        let dns_r = &dns_renames[idx];

        if let Some(obs) = cfg.opt_arr("outbounds") {
            for i in 0..obs.len() {
                let o = match obs.arr_obj(i) {
                    Some(o) => o,
                    None => continue,
                };
                let typ = o.opt_str("type", "");
                if typ == "selector" || typ == "urltest" {
                    continue;
                }
                let mut ob_copy = o.clone();
                rewrite_outbound(&mut ob_copy, out_r, dns_r);
                if ob_copy.opt_str("type", "") == "direct" && ob_copy.opt_str("tag", "") == "direct" {
                    if has_direct {
                        continue;
                    }
                    has_direct = true;
                    leaf_outbounds.push(ob_copy);
                    continue;
                }
                let t = ob_copy.opt_str("tag", "");
                leaf_outbound_tags.push(t);
                leaf_outbounds.push(ob_copy);
            }
        }
        if let Some(eps) = cfg.opt_arr("endpoints") {
            for i in 0..eps.len() {
                let o = match eps.arr_obj(i) {
                    Some(o) => o,
                    None => continue,
                };
                let mut ob_copy = o.clone();
                rewrite_outbound(&mut ob_copy, out_r, dns_r);
                let t = ob_copy.opt_str("tag", "");
                merged_endpoints.push(ob_copy);
                merged_endpoint_tags.push(t);
            }
        }

        if let Some(dns) = cfg.opt_obj("dns") {
            if let Some(servers) = dns.opt_arr("servers") {
                for i in 0..servers.len() {
                    let s = match servers.arr_obj(i) {
                        Some(s) => s,
                        None => continue,
                    };
                    let mut s_copy = s.clone();
                    rewrite_dns_server(&mut s_copy, out_r, dns_r);
                    if s_copy.opt_str("type", "") == "local" && s_copy.opt_str("tag", "") == "local"
                    {
                        if has_local {
                            continue;
                        }
                        has_local = true;
                    }
                    merged_dns_servers.push(s_copy);
                }
            }
            if let Some(drules) = dns.opt_arr("rules") {
                for i in 0..drules.len() {
                    let r = match drules.arr_obj(i) {
                        Some(r) => r,
                        None => continue,
                    };
                    let mut r_copy = r.clone();
                    rewrite_dns_rule(&mut r_copy, out_r, dns_r);
                    merged_dns_rules.push(r_copy);
                }
            }
        }

        if let Some(route) = cfg.opt_obj("route") {
            if let Some(rules) = route.opt_arr("rules") {
                for i in 0..rules.len() {
                    let r = match rules.arr_obj(i) {
                        Some(r) => r,
                        None => continue,
                    };
                    if idx > 0 && is_pre_rule(r) {
                        continue;
                    }
                    let mut r_copy = r.clone();
                    rewrite_route_rule(&mut r_copy, out_r, dns_r);
                    merged_route_rules.push(r_copy);
                }
            }
            if let Some(rule_set) = route.opt_arr("rule_set") {
                for i in 0..rule_set.len() {
                    let rs = match rule_set.arr_obj(i) {
                        Some(rs) => rs,
                        None => continue,
                    };
                    let tag = rs.opt_str("tag", "");
                    if tag.is_empty() || used_rule_set_tags.contains(&tag) {
                        continue;
                    }
                    used_rule_set_tags.insert(tag);
                    merged_rule_set.push(rs.clone());
                }
            }
        }
    }

    let mut all_leaf_tags: Vec<String> = leaf_outbound_tags.clone();
    all_leaf_tags.extend(merged_endpoint_tags.clone());
    if all_leaf_tags.is_empty() {
        return None;
    }

    if !has_local {
        let mut local_srv = Json::obj();
        local_srv.set("type", Json::str("local"));
        local_srv.set("tag", Json::str("local"));
        merged_dns_servers.insert(0, local_srv);
    }
    if !has_direct {
        let mut direct = Json::obj();
        direct.set("type", Json::str("direct"));
        direct.set("tag", Json::str("direct"));
        leaf_outbounds.push(direct);
    }

    let mut selector = Json::obj();
    selector.set("type", Json::str("selector"));
    selector.set("tag", Json::str("proxy"));
    let mut selector_outs: Vec<Json> = Vec::new();
    selector_outs.push(Json::str("auto"));
    for t in &all_leaf_tags {
        selector_outs.push(Json::str(t.clone()));
    }
    selector_outs.push(Json::str("direct"));
    selector.set("outbounds", Json::Arr(selector_outs));
    selector.set("default", Json::str("auto"));

    let mut urltest = Json::obj();
    urltest.set("type", Json::str("urltest"));
    urltest.set("tag", Json::str("auto"));
    let mut urltest_outs: Vec<Json> = Vec::new();
    for t in &all_leaf_tags {
        urltest_outs.push(Json::str(t.clone()));
    }
    urltest.set("outbounds", Json::Arr(urltest_outs));
    urltest.set("url", Json::str("https://www.gstatic.com/generate_204"));
    urltest.set("interval", Json::str("5m"));

    let mut merged = Json::obj();
    if let Some(first_log) = full_configs[0].opt_obj("log") {
        merged.set("log", first_log.clone());
    }

    let mut dns_obj = Json::obj();
    dns_obj.set("servers", Json::Arr(merged_dns_servers));
    if !merged_dns_rules.is_empty() {
        dns_obj.set("rules", Json::Arr(merged_dns_rules));
    }
    if let Some(first_dns) = full_configs[0].opt_obj("dns") {
        let cs = first_dns.opt_str("client_subnet", "");
        if !cs.is_empty() {
            dns_obj.set("client_subnet", Json::str(cs));
        }
        let df = first_dns.opt_str("final", "");
        if !df.is_empty() {
            let mapped = dns_renames[0].get(&df).cloned().unwrap_or(df);
            dns_obj.set("final", Json::str(mapped));
        }
    }
    merged.set("dns", dns_obj);

    match full_configs[0].opt_arr("inbounds") {
        Some(first_inbounds) if first_inbounds.len() > 0 => {
            merged.set("inbounds", first_inbounds.clone());
        }
        _ => {
            let mut mixed_in = Json::obj();
            mixed_in.set("type", Json::str("mixed"));
            mixed_in.set("tag", Json::str("mixed-in"));
            mixed_in.set("listen", Json::str("127.0.0.1"));
            mixed_in.set("listen_port", Json::int(2080));
            merged.set("inbounds", Json::Arr(vec![mixed_in]));
        }
    }

    let mut out_arr: Vec<Json> = Vec::new();
    out_arr.push(selector);
    out_arr.push(urltest);
    for o in leaf_outbounds {
        out_arr.push(o);
    }
    merged.set("outbounds", Json::Arr(out_arr));

    if !merged_endpoints.is_empty() {
        merged.set("endpoints", Json::Arr(merged_endpoints));
    }

    let mut route_obj = Json::obj();
    if !merged_route_rules.is_empty() {
        route_obj.set("rules", Json::Arr(merged_route_rules));
    }
    if !merged_rule_set.is_empty() {
        route_obj.set("rule_set", Json::Arr(merged_rule_set));
    }
    route_obj.set("auto_detect_interface", Json::bool(true));
    route_obj.set("final", Json::str("proxy"));
    let mut ddr = Json::obj();
    ddr.set("server", Json::str("local"));
    route_obj.set("default_domain_resolver", ddr);
    merged.set("route", route_obj);

    if let Some(first_exp) = full_configs[0].opt_obj("experimental") {
        let mut exp_copy = first_exp.clone();
        strip_fork_only_fields(&mut exp_copy);
        merged.set("experimental", exp_copy);
    }

    Some(merged)
}

// ---- public entry points ----

// Full Xray config -> full sing-box config.
pub(crate) fn convert(input: &str, name_fallback: &str) -> ConvertResult {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return ConvertResult::NotXray;
    }
    if !trimmed.starts_with('{') {
        return ConvertResult::NotXray;
    }
    let xray = match parse_whole(trimmed) {
        Some(v @ Json::Obj(_)) => v,
        _ => return ConvertResult::NotXray,
    };
    if is_singbox(&xray) {
        return ConvertResult::NotXray;
    }
    if !looks_like_xray(&xray) {
        return ConvertResult::NotXray;
    }
    match convert_object(&xray, name_fallback) {
        Some(sb) => ConvertResult::Ok(sb),
        None => ConvertResult::Unsupported,
    }
}

// Xray config -> just the list of sing-box proxy outbounds.
pub(crate) fn convert_to_outbounds(input: &str, name_fallback: &str) -> OutboundsResult {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return OutboundsResult::NotXray;
    }
    if !trimmed.starts_with('{') {
        return OutboundsResult::NotXray;
    }
    let xray = match parse_whole(trimmed) {
        Some(v @ Json::Obj(_)) => v,
        _ => return OutboundsResult::NotXray,
    };
    if is_singbox(&xray) {
        return OutboundsResult::NotXray;
    }
    if !looks_like_xray(&xray) {
        return OutboundsResult::NotXray;
    }
    match extract_proxy_outbounds(&xray, name_fallback) {
        Some(list) => {
            if list.is_empty() {
                OutboundsResult::Unsupported
            } else {
                OutboundsResult::Ok(list)
            }
        }
        None => OutboundsResult::Unsupported,
    }
}
