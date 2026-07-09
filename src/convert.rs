use crate::json::{parse_whole, stringify_compact, Json};
use base64::{engine::general_purpose::STANDARD, Engine};

const PROXY_SCHEMES: [&str; 13] = [
    "vless://", "vmess://", "trojan://", "ss://", "ssr://", "hysteria://", "hysteria2://",
    "hy2://", "tuic://", "socks://", "http://", "https://", "happ://",
];

/// A set of convert operations, combined with `|`.
///
/// # Examples
///
/// ```
/// use hpwnr::ConvertOps;
///
/// let ops = ConvertOps::SINGBOX | ConvertOps::BASE64;
/// assert!(ops.contains(ConvertOps::SINGBOX));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConvertOps(u8);

impl ConvertOps {
    /// Convert JSON outbounds into proxy links.
    pub const LINKS: ConvertOps = ConvertOps(0b01);
    /// Unwrap a base64-encoded body.
    pub const BASE64: ConvertOps = ConvertOps(0b10);
    /// `LINKS` and `BASE64` combined (does not include `SINGBOX`).
    pub const ALL: ConvertOps = ConvertOps(0b11);
    /// Convert Xray configs into a merged sing-box config.
    pub const SINGBOX: ConvertOps = ConvertOps(0b100);

    /// Returns true when every operation in `op` is enabled in `self`.
    pub fn contains(self, op: ConvertOps) -> bool {
        (self.0 & op.0) == op.0
    }
}

impl std::ops::BitOr for ConvertOps {
    type Output = ConvertOps;
    fn bitor(self, rhs: ConvertOps) -> ConvertOps {
        ConvertOps(self.0 | rhs.0)
    }
}

/// Normalizes subscription text per `ops`: link conversion (JSON outbounds to URIs), base64
/// unwrap, and Xray-to-sing-box conversion.
///
/// # Examples
///
/// ```
/// use hpwnr::{convert, ConvertOps};
///
/// // An Xray outbound converts to a proxy URI.
/// let xray = r#"{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"11111111-2222-3333-4444-555555555555"}]}]}}]}"#;
/// let uri = convert(xray, ConvertOps::LINKS);
/// assert!(uri.starts_with("vless://11111111-2222-3333-4444-555555555555@example.com:443"));
/// ```
pub fn convert(input: &str, ops: ConvertOps) -> String {
    convert_with_stats(
        input,
        ops.contains(ConvertOps::LINKS),
        ops.contains(ConvertOps::BASE64),
        ops.contains(ConvertOps::SINGBOX),
    )
    .0
}

// Emit a parsed JSON value as proxy URIs: an object as one config line, an array element by element
fn emit_json_value(v: &Json, fallback: &str, res: &mut Vec<String>) {
    match v {
        Json::Arr(items) => {
            for el in items {
                match el {
                    Json::Obj(_) => {
                        res.push(process_json(el).unwrap_or_else(|| stringify_compact(el)));
                    }
                    Json::Null => {}
                    Json::Str(s) => {
                        let st = s.trim();
                        if !st.is_empty() {
                            res.push(st.to_string());
                        }
                    }
                    other => {
                        let st = stringify_compact(other);
                        let trimmed = st.trim();
                        if !trimmed.is_empty() {
                            res.push(trimmed.to_string());
                        }
                    }
                }
            }
        }
        Json::Obj(_) => match process_json(v) {
            Some(c) => res.push(c),
            None => res.push(fallback.to_string()),
        },
        _ => res.push(fallback.to_string()),
    }
}

fn convert_depth(input: &str, json_to_uri: bool, try_base64: bool, depth: usize) -> String {
    if !json_to_uri && !try_base64 {
        return input.trim().to_string();
    }
    // Guard against pathological nested base64
    if depth > 8 {
        return input.trim().to_string();
    }

    // Whole body is base64: decode and recurse.
    if try_base64
        && let Some(decoded) = try_decode_base64(input) {
            return convert_depth(&decoded, json_to_uri, try_base64, depth + 1);
        }

    // Whole body is one JSON value (e.g. a multi-line Xray config): convert as a unit, like the sing-box path
    if json_to_uri {
        let whole = input.trim();
        if (whole.starts_with('{') || whole.starts_with('['))
            && let Some(v) = parse_whole(whole) {
                let mut res: Vec<String> = Vec::new();
                emit_json_value(&v, whole, &mut res);
                return res.join("\n").trim().to_string();
            }
    }

    let mut res: Vec<String> = Vec::new();
    for line in input.split('\n') {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }

        if try_base64
            && let Some(decoded) = try_decode_base64(t) {
                res.push(convert_depth(&decoded, json_to_uri, try_base64, depth + 1));
                continue;
            }

        if json_to_uri && (t.starts_with('{') || t.starts_with('['))
            && let Some(v) = parse_whole(t) {
                emit_json_value(&v, t, &mut res);
                continue;
            }

        res.push(t.to_string());
    }

    res.join("\n").trim().to_string()
}

// Decode as base64 only if the result is real UTF-8 text that looks like configs or a proxy list
fn try_decode_base64(input: &str) -> Option<String> {
    if input.len() < 10 {
        return None;
    }
    let cleaned = input.trim();
    if cleaned.is_empty() {
        return None;
    }

    let mut has_std = false;
    let mut has_url = false;
    for c in cleaned.bytes() {
        match c {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b' ' | b'\t' => {}
            b'=' => {}
            b'\r' | b'\n' => {}
            b'+' | b'/' => has_std = true,
            b'-' | b'_' => has_url = true,
            _ => return None,
        }
    }
    if has_std && has_url {
        return None;
    }

    // Normalize to padded standard base64: map url-safe alphabet, drop whitespace/padding, re-pad.
    let mut norm = String::with_capacity(cleaned.len());
    for c in cleaned.bytes() {
        match c {
            b'-' => norm.push('+'),
            b'_' => norm.push('/'),
            b' ' | b'\t' | b'\r' | b'\n' | b'=' => {}
            other => norm.push(other as char),
        }
    }
    let pad = (4 - norm.len() % 4) % 4;
    for _ in 0..pad {
        norm.push('=');
    }

    let data = STANDARD.decode(norm.as_bytes()).ok()?;
    if data.is_empty() {
        return None;
    }
    // Strict UTF-8: binary/garbage is rejected.
    let decoded_raw = std::str::from_utf8(&data).ok()?;
    // Control characters (except tab/newline/CR) and DEL indicate binary.
    for ch in decoded_raw.chars() {
        let cc = ch as u32;
        if cc == 0x7f || (cc < 0x20 && cc != 0x09 && cc != 0x0a && cc != 0x0d) {
            return None;
        }
    }

    let decoded = decoded_raw.trim_start();
    let first_line = decoded.lines().find(|l| !l.trim().is_empty())?.trim_start();
    let looks_json = first_line.starts_with('{') || first_line.starts_with('[');
    let looks_proxy = PROXY_SCHEMES.iter().any(|s| starts_with_ci(first_line, s));
    if looks_json || looks_proxy {
        Some(decoded.to_string())
    } else {
        None
    }
}

// JSON outbound to a proxy URI
fn process_json(root: &Json) -> Option<String> {
    if is_shadowsocks(root) {
        return build_shadowsocks(root, &root.opt_str("remarks", ""));
    }

    let protocol = root.opt_str("protocol", &root.opt_str("type", ""));
    match protocol.as_str() {
        "vmess" => return build_vmess(root, &root.opt_str("tag", &root.opt_str("remarks", ""))),
        "tuic" => return build_tuic(root, &root.opt_str("tag", &root.opt_str("remarks", ""))),
        _ => {}
    }

    if let Some(obs) = root.opt_arr("outbounds") {
        let rem = root.opt_str("remarks", "");
        for ob in obs.arr_items() {
            if !ob.is_obj() {
                continue;
            }
            let p = ob.opt_str("protocol", &ob.opt_str("type", ""));
            let c = match p.as_str() {
                "vless" => build_vless(ob, &rem),
                "vmess" => build_vmess(ob, &rem),
                "shadowsocks" => build_shadowsocks(ob, &rem),
                "trojan" => build_trojan(ob, &rem),
                "hysteria2" => build_hysteria2(ob, &rem),
                "tuic" => build_tuic(ob, &rem),
                _ => {
                    if is_shadowsocks(ob) {
                        build_shadowsocks(ob, &rem)
                    } else {
                        None
                    }
                }
            };
            if let Some(link) = c {
                return Some(link);
            }
        }
    }
    None
}

fn is_shadowsocks(obj: &Json) -> bool {
    if obj.has("server") && obj.has("server_port") && obj.has("password") && obj.has("method") {
        return true;
    }
    if let Some(settings) = obj.opt_obj("settings")
        && let Some(servers) = settings.opt_arr("servers")
            && let Some(s) = servers.arr_items().first()
                && s.has("address") && s.has("port") && s.has("password") && s.has("method") {
                    return true;
                }
    false
}

// VLESS: vnext/users plus reality/stream params.
fn build_vless(ob: &Json, rem: &str) -> Option<String> {
    let s = ob.opt_obj("settings")?;
    let vnext = s.opt_arr("vnext")?;
    let vn = vnext.arr_items().first()?;
    if !vn.is_obj() {
        return None;
    }
    let users = vn.opt_arr("users")?;
    let u = users.arr_items().first()?;
    if !u.is_obj() {
        return None;
    }
    let ss = ob.opt_obj("streamSettings");
    let rs = ss.and_then(|x| x.opt_obj("realitySettings"));

    let id = u.get_str("id")?;
    let address = vn.get_str("address")?;
    let port = vn.get_int("port")?;

    let fp = rs.map(|r| r.opt_str("fingerprint", "chrome")).unwrap_or_else(|| "chrome".to_string());
    let pbk = rs.map(|r| r.opt_str("publicKey", "")).unwrap_or_default();
    let sid = rs.map(|r| r.opt_str("shortId", "")).unwrap_or_default();
    let sni = rs.map(|r| r.opt_str("serverName", "")).unwrap_or_default();
    let security = ss.map(|x| x.opt_str("security", "none")).unwrap_or_else(|| "none".to_string());
    let typ = ss.map(|x| x.opt_str("network", "tcp")).unwrap_or_else(|| "tcp".to_string());

    Some(format!(
        "vless://{}@{}:{}?encryption={}&flow={}&fp={}&pbk={}&security={}&sid={}&sni={}&type={}#{}",
        id,
        address,
        port,
        u.opt_str("encryption", "none"),
        u.opt_str("flow", ""),
        fp,
        pbk,
        security,
        sid,
        sni,
        typ,
        url_encode_remarks(rem),
    ))
}

// VMess: build the legacy JSON blob and base64 it.
fn build_vmess(ob: &Json, rem: &str) -> Option<String> {
    let settings = ob.opt_obj("settings");
    let vnext = settings
        .and_then(|s| s.opt_arr("vnext"))
        .and_then(|a| a.arr_items().first())
        .filter(|v| v.is_obj());

    let addr = ob.opt_str(
        "server",
        &vnext.map(|v| v.opt_str("address", "")).unwrap_or_default(),
    );
    let port: i64 = if ob.has("server_port") {
        ob.get_int("server_port")?
    } else {
        vnext.map(|v| v.opt_int("port", 0)).unwrap_or(0)
    };
    let default_uuid = vnext
        .and_then(|v| v.opt_arr("users"))
        .and_then(|a| a.arr_items().first())
        .filter(|x| x.is_obj())
        .map(|x| x.opt_str("id", ""))
        .unwrap_or_default();
    let uuid = ob.opt_str("uuid", &default_uuid);

    let transport = ob.opt_obj("transport");
    let stream = ob.opt_obj("streamSettings");
    let net = if let Some(tr) = transport {
        tr.opt_str("type", "")
    } else if let Some(st) = stream {
        st.opt_str("network", "")
    } else {
        "tcp".to_string()
    };

    let is_tls = if let Some(tls) = ob.opt_obj("tls") {
        tls.opt_bool("enabled", false)
    } else {
        stream.map(|s| s.opt_str("security", "") == "tls").unwrap_or(false)
    };

    let mut obj: Vec<(String, Json)> = Vec::new();
    obj.push(("v".to_string(), Json::Str("2".to_string())));
    obj.push(("add".to_string(), Json::Str(addr)));
    obj.push(("port".to_string(), Json::Str(port.to_string())));
    obj.push(("id".to_string(), Json::Str(uuid)));
    obj.push(("aid".to_string(), Json::Str("0".to_string())));
    obj.push(("scy".to_string(), Json::Str("auto".to_string())));
    obj.push(("net".to_string(), Json::Str(net.clone())));
    obj.push(("tls".to_string(), Json::Str((if is_tls { "tls" } else { "" }).to_string())));

    if net == "ws" {
        let ws = if transport.is_some() {
            transport
        } else {
            stream.and_then(|s| s.opt_obj("wsSettings"))
        };
        if let Some(ws) = ws {
            obj.push(("path".to_string(), Json::Str(ws.opt_str("path", ""))));
            let host = if let Some(hd) = ws.opt_obj("headers") {
                hd.opt_str("Host", "")
            } else {
                ws.opt_str("headers", "")
            };
            obj.push(("host".to_string(), Json::Str(host)));
        }
    }

    let final_rem = if ob.has("tag") {
        ob.get_str("tag")?
    } else if ob.has("remarks") {
        ob.get_str("remarks")?
    } else {
        rem.to_string()
    };
    obj.push(("ps".to_string(), Json::Str(final_rem)));

    let raw = stringify_compact(&Json::Obj(obj));
    Some(format!("vmess://{}", STANDARD.encode(raw.as_bytes())))
}

// Shadowsocks: base64(method:password)@host:port.
fn build_shadowsocks(ob: &Json, rem: &str) -> Option<String> {
    let (address, port, method, password) = if ob.has("server") {
        (
            ob.get_str("server")?,
            ob.get_int("server_port")?,
            ob.get_str("method")?,
            ob.get_str("password")?,
        )
    } else {
        let settings = ob.opt_obj("settings")?;
        let servers = settings.opt_arr("servers")?;
        let s = servers.arr_items().first()?;
        if !s.is_obj() {
            return None;
        }
        (
            s.get_str("address")?,
            s.get_int("port")?,
            s.get_str("method")?,
            s.get_str("password")?,
        )
    };
    let cred = format!("{}:{}", method, password);
    let ui = STANDARD.encode(cred.as_bytes());
    let final_rem = if ob.has("remarks") {
        ob.get_str("remarks")?
    } else {
        rem.to_string()
    };
    Some(format!("ss://{}@{}:{}#{}", ui, address, port, url_encode_remarks(&final_rem)))
}

// Trojan: password@host:port with a tls/ws query.
fn build_trojan(ob: &Json, rem: &str) -> Option<String> {
    let settings = ob.opt_obj("settings")?;
    let servers = settings.opt_arr("servers")?;
    let server = servers.arr_items().first().filter(|v| v.is_obj())?;

    let address = server.opt_str("address", "");
    let port = server.opt_int("port", 0);
    let password = server.opt_str("password", "");

    let ss = ob.opt_obj("streamSettings");
    let network = ss.map(|s| s.opt_str("network", "")).unwrap_or_default();
    let security = ss.map(|s| s.opt_str("security", "")).unwrap_or_default();

    let mut query: Vec<(String, String)> = Vec::new();
    if !network.is_empty() {
        set_kv(&mut query, "type", network.clone());
    }
    if security == "tls" || security == "reality" {
        let tls = ss.and_then(|s| s.opt_obj("tlsSettings").or_else(|| s.opt_obj("realitySettings")));
        let sni = tls.map(|t| t.opt_str("serverName", "")).unwrap_or_default();
        if !sni.is_empty() {
            set_kv(&mut query, "sni", sni.clone());
            set_kv(&mut query, "host", sni);
        }
    }
    if network == "ws" {
        let ws = ss.and_then(|s| s.opt_obj("wsSettings"));
        let path = ws.map(|w| w.opt_str("path", "")).unwrap_or_default();
        let host = ws
            .and_then(|w| w.opt_obj("headers"))
            .map(|h| h.opt_str("Host", ""))
            .unwrap_or_default();
        if !path.is_empty() {
            set_kv(&mut query, "path", path);
        }
        if !host.is_empty() {
            set_kv(&mut query, "host", host);
        }
    }

    query.sort_by(|a, b| a.0.cmp(&b.0));
    let qs: Vec<String> = query.iter().map(|(k, v)| format!("{}={}", k, url_encode(v))).collect();
    let query_string = if qs.is_empty() {
        String::new()
    } else {
        format!("?{}", qs.join("&"))
    };

    let final_rem = if ob.has("remarks") {
        ob.get_str("remarks")?
    } else {
        rem.to_string()
    };
    Some(format!(
        "trojan://{}@{}:{}{}#{}",
        url_encode(&password),
        address,
        port,
        query_string,
        url_encode_remarks(&final_rem),
    ))
}

// Hysteria2: password@host:port with an obfs/sni query.
fn build_hysteria2(ob: &Json, rem: &str) -> Option<String> {
    let settings = ob.opt_obj("settings")?;
    let servers = settings.opt_arr("servers")?;
    let server = servers.arr_items().first().filter(|v| v.is_obj())?;

    let address = server.opt_str("address", "");
    let port = server.opt_int("port", 0);

    let ss = ob.opt_obj("streamSettings");
    let hy2 = ss.and_then(|s| s.opt_obj("hy2Settings"));
    let password = hy2.map(|h| h.opt_str("password", "")).unwrap_or_default();
    let obfs = hy2.and_then(|h| h.opt_obj("obfs"));
    let obfs_type = obfs.map(|o| o.opt_str("type", "")).unwrap_or_default();
    let obfs_password = obfs.map(|o| o.opt_str("password", "")).unwrap_or_default();
    let tls = ss.and_then(|s| s.opt_obj("tlsSettings"));
    let sni = tls.map(|t| t.opt_str("serverName", "")).unwrap_or_default();

    let mut query = String::new();
    if !obfs_type.is_empty() {
        query.push_str("&obfs=");
        query.push_str(&url_encode(&obfs_type));
    }
    if !obfs_password.is_empty() {
        query.push_str("&obfs-password=");
        query.push_str(&url_encode(&obfs_password));
    }
    if !sni.is_empty() {
        query.push_str("&sni=");
        query.push_str(&url_encode(&sni));
    }
    let query_string = if query.is_empty() {
        String::new()
    } else {
        format!("?{}", &query[1..])
    };

    Some(format!(
        "hysteria2://{}@{}:{}/{}#{}",
        password,
        address,
        port,
        query_string,
        url_encode_remarks(rem),
    ))
}

// TUIC: uuid:password@host:port with a congestion/tls query.
fn build_tuic(ob: &Json, rem: &str) -> Option<String> {
    let address = ob.opt_str("server", "");
    let port = ob.opt_int("server_port", 0);
    let uuid = ob.opt_str("uuid", "");
    let password = ob.opt_str("password", "");

    let mut query: Vec<(String, String)> = Vec::new();
    let cc = ob.opt_str("congestion_control", "");
    if !cc.is_empty() {
        set_kv(&mut query, "congestion_control", cc);
    }
    let mode = ob.opt_str("udp_relay_mode", "");
    if !mode.is_empty() {
        set_kv(&mut query, "udp_relay_mode", mode);
    }
    if let Some(tls) = ob.opt_obj("tls")
        && tls.opt_bool("enabled", false) {
            let sni = tls.opt_str("server_name", "");
            if !sni.is_empty() {
                set_kv(&mut query, "sni", sni);
            }
            if let Some(alpn) = tls.opt_arr("alpn")
                && let Some(first) = alpn.arr_items().first() {
                    match first {
                        Json::Str(s) => set_kv(&mut query, "alpn", s.clone()),
                        // getString(0) on a non-string throws in the app -> the whole link fails.
                        _ => return None,
                    }
                }
            if tls.opt_bool("insecure", false) {
                set_kv(&mut query, "allow_insecure", "1".to_string());
            }
        }

    query.sort_by(|a, b| a.0.cmp(&b.0));
    let qs: Vec<String> = query.iter().map(|(k, v)| format!("{}={}", k, url_encode(v))).collect();
    let query_string = if qs.is_empty() {
        String::new()
    } else {
        format!("?{}", qs.join("&"))
    };

    let final_rem = if ob.has("tag") {
        ob.get_str("tag")?
    } else if ob.has("remarks") {
        ob.get_str("remarks")?
    } else {
        rem.to_string()
    };
    Some(format!(
        "tuic://{}:{}@{}:{}{}#{}",
        uuid,
        password,
        address,
        port,
        query_string,
        url_encode_remarks(&final_rem),
    ))
}

// Java URLEncoder UTF-8: keep [A-Za-z0-9.*_-], space to '+', else uppercase %XX of the UTF-8 bytes
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'*' | b'_' => out.push(b as char),
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push_str(&format!("{:02X}", b));
            }
        }
    }
    out
}

// Remarks/fragment encoding: URLEncoder then '+' -> "%20" (so spaces become %20, not '+').
fn url_encode_remarks(s: &str) -> String {
    url_encode(s).replace('+', "%20")
}

// ASCII case-insensitive prefix test.
fn starts_with_ci(s: &str, prefix: &str) -> bool {
    let sb = s.as_bytes();
    let pb = prefix.as_bytes();
    sb.len() >= pb.len() && sb[..pb.len()].eq_ignore_ascii_case(pb)
}

// Map-like insert, last-write-wins (mirrors Kotlin mutableMapOf so a later ws Host overwrites sni host)
fn set_kv(q: &mut Vec<(String, String)>, key: &str, val: String) {
    if let Some(slot) = q.iter_mut().find(|(k, _)| k == key) {
        slot.1 = val;
    } else {
        q.push((key.to_string(), val));
    }
}

// ---- Xray-to-sing-box conversion (mirrors LinkConverter's xrayToSb path) ----

// true if the first 1024 chars contain no CR/LF (compact one-line JSON)
fn is_compact_json(s: &str) -> bool {
    for (i, c) in s.chars().enumerate() {
        if i >= 1024 {
            break;
        }
        if c == '\n' || c == '\r' {
            return false;
        }
    }
    true
}

// true if the whole string is one valid JSON value (no trailing junk)
fn is_whole_json_value(s: &str) -> bool {
    parse_whole(s).is_some()
}

// org.json-style serialization: compact toString() or indented toString(2)
fn format_json(v: &Json, compact: bool) -> String {
    if compact {
        v.to_compact()
    } else {
        v.to_pretty(2)
    }
}

struct Base64Result {
    decoded: String,
    url_safe: bool,
    had_newlines: bool,
    had_crlf: bool,
    had_padding: bool,
    had_trailing_newline: bool,
    had_trailing_crlf: bool,
}

// Like try_decode_base64, but also records the input's shape (alphabet/newlines/padding) for re-encoding.
fn try_decode_base64_with_flag(input: &str) -> Option<Base64Result> {
    if input.len() < 10 {
        return None;
    }
    let cleaned = input.trim();
    if cleaned.is_empty() {
        return None;
    }
    let mut has_std = false;
    let mut has_url = false;
    let mut had_newlines = false;
    let mut had_padding = false;
    for c in cleaned.bytes() {
        match c {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b' ' | b'\t' => {}
            b'=' => had_padding = true,
            b'\r' | b'\n' => had_newlines = true,
            b'+' | b'/' => has_std = true,
            b'-' | b'_' => has_url = true,
            _ => return None,
        }
    }
    if has_std && has_url {
        return None;
    }
    let rstripped = input.trim_end_matches([' ', '\t']);
    let had_trailing_crlf = rstripped.ends_with("\r\n");
    let had_trailing_newline =
        had_trailing_crlf || rstripped.ends_with('\n') || rstripped.ends_with('\r');
    let had_crlf = (had_newlines && cleaned.contains("\r\n")) || had_trailing_crlf;
    let url_safe = has_url;

    let mut norm = String::with_capacity(cleaned.len());
    for c in cleaned.bytes() {
        match c {
            b'-' => norm.push('+'),
            b'_' => norm.push('/'),
            b' ' | b'\t' | b'\r' | b'\n' | b'=' => {}
            other => norm.push(other as char),
        }
    }
    let pad = (4 - norm.len() % 4) % 4;
    for _ in 0..pad {
        norm.push('=');
    }
    let data = STANDARD.decode(norm.as_bytes()).ok()?;
    if data.is_empty() {
        return None;
    }
    let decoded_raw = std::str::from_utf8(&data).ok()?;
    for ch in decoded_raw.chars() {
        let cc = ch as u32;
        if cc == 0x7f || (cc < 0x20 && cc != 0x09 && cc != 0x0a && cc != 0x0d) {
            return None;
        }
    }
    let decoded = decoded_raw.trim_start();
    let first_line = decoded.lines().find(|l| !l.trim().is_empty())?.trim_start();
    let looks_json = first_line.starts_with('{') || first_line.starts_with('[');
    let looks_proxy = PROXY_SCHEMES.iter().any(|s| starts_with_ci(first_line, s));
    if looks_json || looks_proxy {
        Some(Base64Result {
            decoded: decoded.to_string(),
            url_safe,
            had_newlines,
            had_crlf,
            had_padding,
            had_trailing_newline,
            had_trailing_crlf,
        })
    } else {
        None
    }
}

// Re-pack text into base64 in the same shape as the original input (alphabet/wrapping/padding/trailing).
fn encode_base64_like(text: &str, b64: &Base64Result) -> String {
    use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let raw = match (b64.url_safe, b64.had_padding) {
        (false, true) => STANDARD.encode(text.as_bytes()),
        (false, false) => STANDARD_NO_PAD.encode(text.as_bytes()),
        (true, true) => URL_SAFE.encode(text.as_bytes()),
        (true, false) => URL_SAFE_NO_PAD.encode(text.as_bytes()),
    };
    let wrapped = if !b64.had_newlines {
        raw
    } else {
        let sep = if b64.had_crlf { "\r\n" } else { "\n" };
        let chars: Vec<char> = raw.chars().collect();
        let mut out = String::new();
        let mut i = 0;
        while i < chars.len() {
            let end = (i + 76).min(chars.len());
            out.extend(chars[i..end].iter());
            out.push_str(sep);
            i = end;
        }
        out
    };
    let body = wrapped.trim_end_matches(['\n', '\r']);
    if b64.had_trailing_crlf {
        format!("{}\r\n", body)
    } else if b64.had_trailing_newline {
        format!("{}\n", body)
    } else {
        body.to_string()
    }
}

// Convert each Xray config inside a JSON array to sing-box; pass non-Xray entries through.
fn try_convert_xray_array(text: &str, compact: bool) -> Option<(String, i64)> {
    let arr = match parse_whole(text) {
        Some(Json::Arr(a)) => a,
        _ => return None,
    };
    if arr.is_empty() {
        return None;
    }
    let mut any_xray = false;
    for el in &arr {
        if let Json::Obj(_) = el
            && let Some(outs) = el.opt_arr("outbounds") {
                for j in 0..outs.len() {
                    if let Some(o) = outs.arr_obj(j)
                        && o.has("protocol") {
                            any_xray = true;
                            break;
                        }
                }
            }
        if any_xray {
            break;
        }
    }
    if !any_xray {
        return None;
    }
    let mut out_arr: Vec<Json> = Vec::new();
    let mut skipped: i64 = 0;
    for el in &arr {
        match el {
            Json::Obj(_) => match crate::singbox::convert(&el.to_compact(), "") {
                crate::singbox::ConvertResult::Ok(cfg) => out_arr.push(cfg),
                crate::singbox::ConvertResult::Unsupported => skipped += 1,
                crate::singbox::ConvertResult::NotXray => out_arr.push(el.clone()),
            },
            Json::Null => {}
            other => out_arr.push(other.clone()),
        }
    }
    Some((format_json(&Json::Arr(out_arr), compact), skipped))
}

// In the combined sb+uri mode, normalize vless flow to its sing-box-valid form (no-op on valid flows)
fn sb_normalize_vnext_flow(mut vn: Json) -> (Json, bool) {
    let users = match vn.opt_arr("users").cloned() {
        Some(Json::Arr(v)) => v,
        _ => return (vn, false),
    };
    let mut new_users = Vec::with_capacity(users.len());
    let mut changed = false;
    for mut user in users {
        let flow = user.opt_str("flow", "");
        if !flow.is_empty() {
            let norm = crate::singbox::normalize_flow(&flow);
            if norm != flow {
                user.set("flow", Json::str(norm));
                changed = true;
            }
        }
        new_users.push(user);
    }
    if !changed {
        return (vn, false);
    }
    vn.set("users", Json::Arr(new_users));
    (vn, true)
}

fn sb_normalize_outbound_flow(mut ob: Json) -> (Json, bool) {
    if ob.opt_str("protocol", "") != "vless" {
        return (ob, false);
    }
    let mut settings = match ob.opt_obj("settings").cloned() {
        Some(s) => s,
        None => return (ob, false),
    };
    let vnext = match settings.opt_arr("vnext").cloned() {
        Some(Json::Arr(v)) => v,
        _ => return (ob, false),
    };
    let mut new_vnext = Vec::with_capacity(vnext.len());
    let mut changed = false;
    for vn in vnext {
        let (nvn, ch) = sb_normalize_vnext_flow(vn);
        changed |= ch;
        new_vnext.push(nvn);
    }
    if !changed {
        return (ob, false);
    }
    settings.set("vnext", Json::Arr(new_vnext));
    ob.set("settings", settings);
    (ob, true)
}

fn sb_normalize_config_flows(cfg: &Json) -> (Json, bool) {
    let outs = match cfg.opt_arr("outbounds").cloned() {
        Some(Json::Arr(v)) => v,
        _ => return (cfg.clone(), false),
    };
    let mut new_outs = Vec::with_capacity(outs.len());
    let mut changed = false;
    for ob in outs {
        let (nob, ch) = sb_normalize_outbound_flow(ob);
        changed |= ch;
        new_outs.push(nob);
    }
    if !changed {
        return (cfg.clone(), false);
    }
    let mut c = cfg.clone();
    c.set("outbounds", Json::Arr(new_outs));
    (c, true)
}

// Supported single config: normalize its vless flows, reserializing only if something changed.
fn sb_normalize_config_flows_str(t: &str) -> String {
    let cfg = match parse_whole(t) {
        Some(c) => c,
        None => return t.to_string(),
    };
    let (normalized, changed) = sb_normalize_config_flows(&cfg);
    if changed {
        normalized.to_compact()
    } else {
        t.to_string()
    }
}

// Keep one Xray config/array, dropping unsupported outbounds; None if the input isn't Xray.
fn pre_filter_unsupported_xray_one(t: &str) -> Option<(String, i64)> {
    if t.is_empty() {
        return None;
    }
    if !is_whole_json_value(t) {
        return None;
    }
    if t.starts_with('{') {
        return match crate::singbox::convert_to_outbounds(t, "") {
            crate::singbox::OutboundsResult::Ok(_) => Some((sb_normalize_config_flows_str(t), 0)),
            crate::singbox::OutboundsResult::Unsupported => Some((String::new(), 1)),
            crate::singbox::OutboundsResult::NotXray => None,
        };
    }
    if t.starts_with('[') {
        let arr = match parse_whole(t) {
            Some(Json::Arr(a)) => a,
            _ => return None,
        };
        let mut out: Vec<Json> = Vec::new();
        let mut any_xray = false;
        let mut skipped: i64 = 0;
        for el in &arr {
            match el {
                Json::Obj(_) => match crate::singbox::convert_to_outbounds(&el.to_compact(), "") {
                    crate::singbox::OutboundsResult::Ok(_) => {
                        out.push(sb_normalize_config_flows(el).0);
                        any_xray = true;
                    }
                    crate::singbox::OutboundsResult::Unsupported => {
                        skipped += 1;
                        any_xray = true;
                    }
                    crate::singbox::OutboundsResult::NotXray => out.push(el.clone()),
                },
                Json::Null => {}
                other => out.push(other.clone()),
            }
        }
        if !any_xray {
            return None;
        }
        return Some((format_json(&Json::Arr(out), is_compact_json(t)), skipped));
    }
    None
}

// Drop unsupported Xray configs across the whole body or line by line; returns (text, skipped).
fn pre_filter_unsupported_xray(input: &str) -> (String, i64) {
    let trimmed = input.trim();
    if (trimmed.starts_with('{') || trimmed.starts_with('[')) && is_whole_json_value(trimmed)
        && let Some(single) = pre_filter_unsupported_xray_one(trimmed) {
            return single;
        }
    let mut res = String::new();
    let mut total_skipped: i64 = 0;
    let mut any_filtered = false;
    for line in input.split('\n') {
        let tt = line.trim();
        if tt.is_empty() {
            continue;
        }
        match pre_filter_unsupported_xray_one(tt) {
            Some((text, skipped)) => {
                any_filtered = true;
                if !text.is_empty() {
                    res.push_str(&text);
                    res.push('\n');
                }
                total_skipped += skipped;
            }
            None => {
                res.push_str(tt);
                res.push('\n');
            }
        }
    }
    if !any_filtered {
        return (input.to_string(), 0);
    }
    (res.trim_end_matches('\n').to_string(), total_skipped)
}

fn cxs_ingest_object(
    s: &str,
    configs: &mut Vec<Json>,
    skipped: &mut i64,
    had_xray: &mut bool,
) -> bool {
    match crate::singbox::convert(s, "") {
        crate::singbox::ConvertResult::Ok(cfg) => {
            configs.push(cfg);
            *had_xray = true;
            true
        }
        crate::singbox::ConvertResult::Unsupported => {
            *skipped += 1;
            *had_xray = true;
            true
        }
        crate::singbox::ConvertResult::NotXray => false,
    }
}

fn cxs_ingest_array(
    s: &str,
    configs: &mut Vec<Json>,
    skipped: &mut i64,
    had_xray: &mut bool,
) -> bool {
    let arr = match parse_whole(s) {
        Some(Json::Arr(a)) => a,
        _ => return false,
    };
    let mut any = false;
    for el in &arr {
        if let Json::Obj(_) = el {
            match crate::singbox::convert(&el.to_compact(), "") {
                crate::singbox::ConvertResult::Ok(cfg) => {
                    configs.push(cfg);
                    any = true;
                }
                crate::singbox::ConvertResult::Unsupported => {
                    *skipped += 1;
                    any = true;
                }
                crate::singbox::ConvertResult::NotXray => {}
            }
        }
    }
    if any {
        *had_xray = true;
    }
    any
}

// Merge every Xray config in the body into a single sing-box config; other lines pass through.
fn convert_xray_to_singbox(input: &str, trimmed: &str, compact: bool) -> Option<(String, i64)> {
    let mut configs: Vec<Json> = Vec::new();
    let mut skipped: i64 = 0;
    let mut had_xray = false;
    let mut passthrough: Vec<String> = Vec::new();

    let consumed_whole = if trimmed.starts_with('{') && is_whole_json_value(trimmed) {
        cxs_ingest_object(trimmed, &mut configs, &mut skipped, &mut had_xray)
    } else if trimmed.starts_with('[') && is_whole_json_value(trimmed) {
        cxs_ingest_array(trimmed, &mut configs, &mut skipped, &mut had_xray)
    } else {
        false
    };

    if !consumed_whole {
        for line in input.split('\n') {
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            let consumed = if t.starts_with('{') && is_whole_json_value(t) {
                cxs_ingest_object(t, &mut configs, &mut skipped, &mut had_xray)
            } else if t.starts_with('[') && is_whole_json_value(t) {
                cxs_ingest_array(t, &mut configs, &mut skipped, &mut had_xray)
            } else {
                false
            };
            if !consumed {
                passthrough.push(t.to_string());
            }
        }
    }

    if !had_xray {
        return None;
    }
    if configs.is_empty() && passthrough.is_empty() {
        return None;
    }

    let mut builder = String::new();
    if !configs.is_empty()
        && let Some(merged) = crate::singbox::merge_unified(&configs) {
            builder.push_str(&format_json(&merged, compact));
        }
    for l in &passthrough {
        if !builder.is_empty() {
            builder.push('\n');
        }
        builder.push_str(l);
    }
    Some((builder, skipped))
}

// Full converter with skip count. Order: base64 -> xray-to-sing-box -> JSON-to-URI.
fn convert_with_stats(
    input: &str,
    json_to_uri: bool,
    try_base64: bool,
    xray_to_sb: bool,
) -> (String, i64) {
    if !json_to_uri && !try_base64 && !xray_to_sb {
        return (input.trim().to_string(), 0);
    }
    // JSON-to-URI / base64 unwrap (no sing-box) reuses the existing line converter.
    if !xray_to_sb {
        return (convert_depth(input, json_to_uri, try_base64, 0), 0);
    }

    let trimmed = input.trim();
    let compact = is_compact_json(trimmed);

    // Whole body is base64: decode and recurse (re-encode when not unwrapping).
    if (try_base64 || xray_to_sb)
        && let Some(b64) = try_decode_base64_with_flag(input) {
            let inner = convert_with_stats(&b64.decoded, json_to_uri, try_base64, xray_to_sb);
            return if try_base64 {
                inner
            } else {
                (encode_base64_like(&inner.0, &b64), inner.1)
            };
        }

    // xray-to-sing-box only: merge into a single config.
    if xray_to_sb && !json_to_uri
        && let Some(merged) = convert_xray_to_singbox(input, trimmed, compact) {
            return merged;
        }

    // Both modes: drop unsupported Xray outbounds, then run JSON-to-URI.
    if xray_to_sb && json_to_uri {
        let filtered = pre_filter_unsupported_xray(input);
        let inner_text = convert_depth(&filtered.0, true, try_base64, 0);
        return (inner_text, filtered.1);
    }

    // Whole body is a single Xray config / array -> sing-box.
    if xray_to_sb && trimmed.starts_with('{') && is_whole_json_value(trimmed)
        && let crate::singbox::ConvertResult::Ok(cfg) = crate::singbox::convert(trimmed, "") {
            return (format_json(&cfg, compact), 0);
        }
    if xray_to_sb && trimmed.starts_with('[') && is_whole_json_value(trimmed)
        && let Some(arr) = try_convert_xray_array(trimmed, compact) {
            return arr;
        }

    // Otherwise walk line by line (json_to_uri is false at this point).
    let mut res = String::new();
    let mut skipped: i64 = 0;
    for line in input.split('\n') {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let line_compact = is_compact_json(t);

        if (try_base64 || xray_to_sb)
            && let Some(b64) = try_decode_base64_with_flag(t) {
                let inner = convert_with_stats(&b64.decoded, json_to_uri, try_base64, xray_to_sb);
                let output = if try_base64 {
                    inner.0.clone()
                } else {
                    encode_base64_like(&inner.0, &b64)
                };
                res.push_str(&output);
                res.push('\n');
                skipped += inner.1;
                continue;
            }
        if xray_to_sb && t.starts_with('{') && is_whole_json_value(t) {
            match crate::singbox::convert(t, "") {
                crate::singbox::ConvertResult::Ok(cfg) => {
                    res.push_str(&format_json(&cfg, line_compact));
                    res.push('\n');
                    continue;
                }
                crate::singbox::ConvertResult::Unsupported => {
                    skipped += 1;
                    continue;
                }
                crate::singbox::ConvertResult::NotXray => {}
            }
        }
        if xray_to_sb && t.starts_with('[') && is_whole_json_value(t)
            && let Some(arr) = try_convert_xray_array(t, line_compact) {
                res.push_str(&arr.0);
                res.push('\n');
                skipped += arr.1;
                continue;
            }
        res.push_str(t);
        res.push('\n');
    }
    (res.trim().to_string(), skipped)
}
