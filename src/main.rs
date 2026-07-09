use std::io::{Read, Write};
use hpwnr::{
    convert, decrypt_link, encrypt_crypt5_legacy, encrypt_happ, encrypt_v2, inspect, unwrap_link,
    ConvertOps, HappMode, LinkKind, V2Key,
};

// Public Suffix List lookup, only needed when naming fetched files
#[cfg(feature = "fetch")]
mod psl;

const SHORT_DESC: &str = "Tool to decrypt/encrypt Happ and V2RayTun links.";

#[cfg(feature = "fetch")]
const FULL_HELP: &str = concat!("hpwnr v", env!("CARGO_PKG_VERSION"), "\n\n", r#"Happ and V2RayTun subscription-link decryptor/encryptor that can fetch, decrypt, encrypt, and convert proxy profiles.

Developed by slavrom21 & Omegaplex
https://github.com/Omegaplexx/hpwnr


── Happ ───────────────────────────
DECRYPT:
  hpwnr happ://crypt5/…
  hpwnr happ://crypt3/…
  hpwnr happ://add/…
ENCRYPT:
  hpwnr https://…
  hpwnr https://… crypt2
  hpwnr https://… crypt4
  hpwnr https://… crypt5old

KEYS:
  crypt5 (default) / crypt5old (legacy) / crypt4 / crypt3 / crypt2 / crypt

crypt5 uses a new salted+XOR layout; crypt5old is the legacy one. Both decrypt automatically.

── V2RayTun ───────────────────────
DECRYPT:
  hpwnr v2raytun://crypt/…
  hpwnr v2raytun://import/…
ENCRYPT:
  hpwnr https://… v2
  hpwnr https://… v2r crypt4
  hpwnr https://… v2raytun key3

KEYS:
  crypt3 (default) / crypt4 / key3
ARGUMENTS:
  v2 / v2r / v2ray / v2raytun

── Fetch ──────────────────────────
Fetches the link when hwid, ua, or fetch is passed, or when a convert mode follows an http(s) URL.
hwid and ua are optional request headers.
FETCH:
  hpwnr https://… fetch
  hpwnr https://… hwid 123abc
  hpwnr https://… hwid 123abc ua happ
  hpwnr v2raytun://… hwid abc123 ua v2ray
  hpwnr happ://… hwid abc123 ua "My/Custom/UA"

USER-AGENT ALIASES:
  happ → Happ/3.26.1
  incy → INCY/3.3.1
  v2 / v2r / v2ray / v2raytun → v2raytun/android

── Convert ────────────────────────
Convert Xray configs to sing-box format or to URIs.

  raw    Show the input as is, without conversion
  b64    Same as above but decode Base64 if necessary
  sb     Convert to sing-box JSON format (unsupported Xray configs will be skipped)
  uri    Convert to vless/vmess/trojan/hy2/ss/tuic links (default)

FETCH + CONVERT:
  hpwnr https://… sb
  hpwnr https://… hwid 123 sb
  hpwnr happ://… hwid 123 ua happ raw
CONVERT:
  hpwnr subscription.txt sb
  hpwnr hpwnresp_example_sb.txt uri

Combine the sb and uri flags to output only sing-box-compatible links.

───────────────────────────────────
If the decrypted URL carries ?key=keyNN and the server returns an Encrypt-Tag header, the response body is decrypted automatically (AES-128-GCM).

If the server response is more than 15000 characters, it is saved to hpwnresp_<domain>.txt, overwritten each run; otherwise it is printed.
Converting a file writes a copy: <name>_<mode>.<ext> where <mode> is sb, uri, b64, or sb+uri, replacing any existing suffix.

URL-encoded, Base64-encoded and wrapped Happ/V2RayTun links inside HTTPS URLs are resolved automatically.
  happ://add/https%3A%2F%2F…
  v2raytun://import/https%3A%2F%2F…
  https://…happ://…
  https://…v2raytun://…
will be converted to
  https://…"#);

#[cfg(not(feature = "fetch"))]
const FULL_HELP: &str = concat!("hpwnr lite v", env!("CARGO_PKG_VERSION"), "\n\n", r#"Happ and V2RayTun subscription-link decryptor/encryptor with proxy config conversion.

Developed by slavrom21 & Omegaplex
https://github.com/Omegaplexx/hpwnr


── Happ ───────────────────────────
DECRYPT:
  hpwnr happ://crypt5/…
  hpwnr happ://crypt3/…
  hpwnr happ://add/…
ENCRYPT:
  hpwnr https://…
  hpwnr https://… crypt2
  hpwnr https://… crypt4
  hpwnr https://… crypt5old

KEYS:
  crypt5 (default) / crypt5old (legacy) / crypt4 / crypt3 / crypt2 / crypt

crypt5 uses a new salted+XOR layout; crypt5old is the legacy one. Both decrypt automatically.

── V2RayTun ───────────────────────
DECRYPT:
  hpwnr v2raytun://crypt/…
  hpwnr v2raytun://import/…
ENCRYPT:
  hpwnr https://… v2
  hpwnr https://… v2r crypt4
  hpwnr https://… v2raytun key3

KEYS:
  crypt3 (default) / crypt4 / key3
ARGUMENTS:
  v2 / v2r / v2ray / v2raytun

── Convert ────────────────────────
Convert Xray configs to sing-box format or to URIs.

  raw    Show the input as is, without conversion
  b64    Same as above but decode Base64 if necessary
  sb     Convert to sing-box JSON format (unsupported Xray configs will be skipped)
  uri    Convert to vless/vmess/trojan/hy2/ss/tuic links (default)

CONVERT:
  hpwnr subscription.txt sb
  hpwnr hpwnresp_example_sb.txt uri

Combine the sb and uri flags to output only sing-box-compatible links.

───────────────────────────────────
Converting a file writes a copy: <name>_<mode>.<ext> where <mode> is sb, uri, b64, or sb+uri, replacing any existing suffix.

URL-encoded, Base64-encoded and wrapped Happ/V2RayTun links inside HTTPS URLs are resolved automatically.
  happ://add/https%3A%2F%2F…
  v2raytun://import/https%3A%2F%2F…
  https://…happ://…
  https://…v2raytun://…
will be converted to
  https://…"#);

// True for -h / --help in any dash/case form
fn is_help_arg(s: &str) -> bool {
    let a = s.trim_start_matches('-').to_lowercase();
    a == "h" || a == "help"
}

// Drop leading dashes from an argument
fn strip_dashes(s: &str) -> &str {
    s.trim_start_matches('-')
}

// Conversion mode: raw output, or accumulated ConvertOps passes from the b64/uri/sb flags
enum ConvertMode {
    Raw,
    Ops(ConvertOps),
}

// Merge a convert flag into the selection; b64/uri/sb accumulate, raw replaces
fn merge_conv(cur: &Option<ConvertMode>, add: ConvertOps) -> ConvertMode {
    match cur {
        Some(ConvertMode::Ops(x)) => ConvertMode::Ops(*x | add),
        _ => ConvertMode::Ops(add),
    }
}

// Parsed command-line arguments
struct ParsedArgs {
    v2mode: bool,
    ordinal: i32,
    crypt5_legacy: bool,
    texts: Vec<String>,
    #[cfg(feature = "fetch")]
    hwid: String,
    #[cfg(feature = "fetch")]
    ua: String,
    #[cfg(feature = "fetch")]
    fetch: bool,
    conv: Option<ConvertMode>,
}

// Parse args: detect v2 mode, key/ordinal, hwid, ua, convert flags, and collect the rest as text
fn parse_all_args(args: &[String]) -> ParsedArgs {
    let mut p = ParsedArgs {
        v2mode: false,
        ordinal: -1,
        crypt5_legacy: false,
        texts: Vec::new(),
        #[cfg(feature = "fetch")]
        hwid: String::new(),
        #[cfg(feature = "fetch")]
        ua: String::new(),
        #[cfg(feature = "fetch")]
        fetch: false,
        conv: None,
    };
    // First pass: v2 mode changes how crypt3/crypt4/key3 map to keys
    for a in args {
        if matches!(strip_dashes(a).to_lowercase().as_str(), "v2" | "v2r" | "v2ray" | "v2raytun") {
            p.v2mode = true;
        }
    }
    let mut i = 0;
    while i < args.len() {
        let raw = &args[i];
        let a = strip_dashes(raw).to_lowercase();
        match a.as_str() {
            #[cfg(feature = "fetch")]
            "hwid" | "x-hwid" => {
                if i + 1 < args.len() {
                    p.hwid = args[i + 1].clone();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            #[cfg(feature = "fetch")]
            "ua" | "user-agent" => {
                if i + 1 < args.len() {
                    p.ua = args[i + 1].clone();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            #[cfg(feature = "fetch")]
            "fetch" => {
                p.fetch = true;
                i += 1;
            }
            "v2" | "v2r" | "v2ray" | "v2raytun" => {
                i += 1;
            }
            // Convert flags (positional; b64/uri/sb accumulate, raw resets)
            "raw" => {
                p.conv = Some(ConvertMode::Raw);
                i += 1;
            }
            "b64" | "base64" => {
                p.conv = Some(merge_conv(&p.conv, ConvertOps::BASE64));
                i += 1;
            }
            "uri" | "link" | "links" => {
                p.conv = Some(merge_conv(&p.conv, ConvertOps::ALL));
                i += 1;
            }
            "sb" | "sing-box" | "singbox" => {
                p.conv = Some(merge_conv(&p.conv, ConvertOps::SINGBOX | ConvertOps::BASE64));
                i += 1;
            }
            // Key names
            "crypt" => {
                if p.v2mode {
                    p.texts.push(raw.clone());
                } else {
                    p.ordinal = 0;
                }
                i += 1;
            }
            "crypt2" => {
                if p.v2mode {
                    p.texts.push(raw.clone());
                } else {
                    p.ordinal = 1;
                }
                i += 1;
            }
            "crypt3" => {
                p.ordinal = if p.v2mode { 0 } else { 2 };
                i += 1;
            }
            "crypt4" => {
                p.ordinal = if p.v2mode { 1 } else { 3 };
                i += 1;
            }
            "crypt5" => {
                if p.v2mode {
                    p.texts.push(raw.clone());
                } else {
                    p.ordinal = 4;
                }
                i += 1;
            }
            // Legacy crypt5 layout (no salt); crypt5 alone stays the new salted default
            "crypt5old" | "crypt5legacy" | "crypt5-old" | "crypt5-legacy" => {
                if p.v2mode {
                    p.texts.push(raw.clone());
                } else {
                    p.ordinal = 4;
                    p.crypt5_legacy = true;
                }
                i += 1;
            }
            "key3" => {
                if p.v2mode {
                    p.ordinal = 2;
                } else {
                    p.texts.push(raw.clone());
                }
                i += 1;
            }
            _ => {
                p.texts.push(raw.clone());
                i += 1;
            }
        }
    }
    p
}

// Extract just the host from a URL, used to name the saved response file
#[cfg(feature = "fetch")]
fn domain_from_url(raw: &str) -> String {
    let mut s = raw;
    if let Some(i) = s.find("://") {
        s = &s[i + 3..];
    }
    if let Some(i) = s.find(['/', '?', '#']) {
        s = &s[..i];
    }
    if let Some(i) = s.rfind('@') {
        s = &s[i + 1..];
    }
    if let Some(i) = s.find(':') {
        s = &s[..i];
    }
    s.to_string()
}

// Name for a fetched subscription: hpwnresp_<label>.txt, overwritten on each fetch
#[cfg(feature = "fetch")]
fn fetch_file_name(url: &str) -> String {
    format!("hpwnresp_{}.txt", psl::registrable_label(&domain_from_url(url)))
}

// True when the argument is an http(s) URL, so it should be fetched rather than read as a file
#[cfg(feature = "fetch")]
fn is_http_url(s: &str) -> bool {
    let s = s.trim_start();
    let n = s.len();
    (n >= 7 && s.as_bytes()[..7].eq_ignore_ascii_case(b"http://"))
        || (n >= 8 && s.as_bytes()[..8].eq_ignore_ascii_case(b"https://"))
}

// Suffix that records how a file was converted
fn convert_suffix(ops: ConvertOps) -> &'static str {
    match (ops.contains(ConvertOps::SINGBOX), ops.contains(ConvertOps::LINKS)) {
        (true, true) => "sb+uri",
        (true, false) => "sb",
        (false, true) => "uri",
        (false, false) => "b64",
    }
}

// Name for a converted copy: keep the directory and extension, swap any trailing convert suffix for the new one.
// Example: file.txt becomes file_sb.txt, and re-running on file_sb.txt gives file_uri.txt.
fn convert_file_name(input: &str, ops: ConvertOps) -> String {
    use std::path::Path;
    let p = Path::new(input);
    let file = p
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| input.to_string());
    let (stem, ext) = match file.rfind('.') {
        Some(i) if i > 0 => (&file[..i], &file[i..]),
        _ => (file.as_str(), ""),
    };
    let mut base = stem;
    for k in ["_sb+uri", "_b64", "_sb", "_uri"] {
        if let Some(rest) = base.strip_suffix(k) {
            base = rest;
            break;
        }
    }
    let name = format!("{base}_{}{ext}", convert_suffix(ops));
    match p.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join(name).to_string_lossy().into_owned(),
        _ => name,
    }
}

// Write bytes to stdout, adding a trailing newline if one is missing
fn print_body(body: &[u8]) -> Result<(), String> {
    let mut out = std::io::stdout();
    out.write_all(body).map_err(|e| format!("write: {e}"))?;
    if !body.is_empty() && body[body.len() - 1] != b'\n' {
        println!();
    }
    Ok(())
}

// Apply a convert mode to the response bytes (raw passes through, else runs the ConvertOps)
fn apply_conv_mode(body: &[u8], mode: &ConvertMode) -> Vec<u8> {
    match mode {
        ConvertMode::Raw => body.to_vec(),
        ConvertMode::Ops(ops) => {
            let text = String::from_utf8_lossy(body);
            convert(&text, *ops).into_bytes()
        }
    }
}

// True when launched by double-click on Windows.
// A fresh console then has only this process attached; a shell launch attaches cmd/powershell too (count > 1).
#[cfg(windows)]
fn launched_by_double_click() -> bool {
    unsafe extern "system" {
        fn GetConsoleProcessList(process_list: *mut u32, count: u32) -> u32;
    }
    let mut buf = [0u32; 8];
    let n = unsafe { GetConsoleProcessList(buf.as_mut_ptr(), buf.len() as u32) };
    n == 1
}

#[cfg(not(windows))]
fn launched_by_double_click() -> bool {
    false
}

fn main() {
    let double_click = launched_by_double_click();
    let code = run();
    // Pause on double-click so the message stays visible instead of the window vanishing.
    if double_click {
        eprintln!("\nThis is a command-line tool. Run it from a terminal (cmd or PowerShell), not by double-clicking.");
        eprint!("Press Enter to exit...");
        let mut s = String::new();
        let _ = std::io::stdin().read_line(&mut s);
    }
    std::process::exit(code);
}

fn run() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // -h / --help anywhere wins
    for a in &args {
        if is_help_arg(a) {
            eprintln!("{FULL_HELP}");
            return 0;
        }
    }
    // No args prints the short description.
    // The -h hint is dropped on a Windows double-click, where main() already tells the user to use a terminal.
    if args.is_empty() {
        if launched_by_double_click() {
            eprintln!("{SHORT_DESC}");
        } else {
            eprintln!("{SHORT_DESC} Use -h for help.");
        }
        return 0;
    }

    let p = parse_all_args(&args);

    // Fetch triggers: the fetch flag, any hwid/ua header, or a convert mode applied to an http(s) URL.
    #[cfg(feature = "fetch")]
    if p.fetch
        || !p.hwid.is_empty()
        || !p.ua.is_empty()
        || (p.conv.is_some() && p.texts.len() == 1 && is_http_url(&p.texts[0]))
    {
        if p.texts.is_empty() {
            eprintln!("error: no URL or encrypted link provided");
            return 1;
        }
        let norm = unwrap_link(&p.texts.join(" "));
        let target = match decrypt_link(&norm) {
            Ok(Some(t)) => t,
            Ok(None) => norm,
            Err(e) => {
                eprintln!("error: could not decrypt link: {e}");
                return 1;
            }
        };
        match hpwnr::fetch(&target, &p.ua, &p.hwid) {
            Ok(body) => {
                // uri is the default when fetching; use `raw` to opt out of conversion.
                let default_mode = ConvertMode::Ops(ConvertOps::ALL);
                let mode = p.conv.as_ref().unwrap_or(&default_mode);
                let output = apply_conv_mode(&body, mode);
                // Large results go to one file per domain (overwritten each run); smaller ones print.
                const MAX_INLINE: usize = 15000;
                if output.len() > MAX_INLINE {
                    let fname = fetch_file_name(&target);
                    if let Err(e) = std::fs::write(&fname, &output) {
                        eprintln!("error: could not write file: {e}");
                        return 1;
                    }
                    eprintln!("saved to: {fname}");
                } else if let Err(e) = print_body(&output) {
                    eprintln!("error: {e}");
                    return 1;
                }
            }
            Err(e) => {
                eprintln!("error: {e}");
                return 1;
            }
        }
        return 0;
    }

    // Convert without fetching: a convert mode on a file, on literal text, or on stdin
    if let Some(ref mode) = p.conv {
        // stdin: read, convert, and print, since there is no source file name to derive a copy name from
        if p.texts.is_empty() {
            let mut s = String::new();
            if std::io::stdin().read_to_string(&mut s).is_err() {
                eprintln!("error: could not read stdin");
                return 1;
            }
            let output = apply_conv_mode(s.as_bytes(), mode);
            if let Err(e) = print_body(&output) {
                eprintln!("error: {e}");
                return 1;
            }
            return 0;
        }
        let path = p.texts.join(" ");
        match std::fs::read(&path) {
            Ok(data) => {
                let output = apply_conv_mode(&data, mode);
                match mode {
                    // raw only displays the file, so print it instead of writing a copy
                    ConvertMode::Raw => {
                        if let Err(e) = print_body(&output) {
                            eprintln!("error: {e}");
                            return 1;
                        }
                    }
                    // a real conversion writes a suffixed copy next to the input file
                    ConvertMode::Ops(ops) => {
                        let out = convert_file_name(&path, *ops);
                        if let Err(e) = std::fs::write(&out, &output) {
                            eprintln!("error: could not write file: {e}");
                            return 1;
                        }
                        eprintln!("saved to: {out}");
                    }
                }
            }
            Err(_) => {
                // Not a readable file: treat the argument text as content and print the result.
                let output = apply_conv_mode(p.texts.join("\n").as_bytes(), mode);
                if let Err(e) = print_body(&output) {
                    eprintln!("error: {e}");
                    return 1;
                }
            }
        }
        return 0;
    }

    // Decrypt / Encrypt paths

    // A single bare link with no flags: resolve wrappers, then try to decrypt
    if p.texts.len() == 1 && p.ordinal == -1 && !p.v2mode {
        let arg = p.texts[0].trim();
        let norm = unwrap_link(arg);
        match decrypt_link(&norm) {
            Ok(Some(plain)) => {
                println!("{plain}");
                return 0;
            }
            Err(e) => {
                eprintln!("error: {e}");
                return 1;
            }
            Ok(None) => {
                // A wrapper/redirect that resolved to a non-encrypted link: show the resolved link
                if norm != arg {
                    println!("{norm}");
                    return 0;
                }
            }
        }
    }

    // v2 mode: decrypt a v2raytun:// link (after resolving wrappers), or encrypt text with the chosen key
    if p.v2mode {
        if p.texts.len() == 1 {
            let norm = unwrap_link(p.texts[0].trim());
            if matches!(inspect(&norm).kind, LinkKind::V2RayTun) {
                match decrypt_link(&norm) {
                    Ok(Some(plain)) => {
                        println!("{plain}");
                        return 0;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        eprintln!("error: {e}");
                        return 1;
                    }
                }
            }
        }
        if p.texts.is_empty() {
            eprintln!("error: no text to encrypt");
            eprintln!("{FULL_HELP}");
            return 1;
        }
        let mut idx = p.ordinal;
        if !(0..=2).contains(&idx) {
            idx = 0;
        }
        let key = V2Key::from_index(idx as usize).unwrap_or(V2Key::Crypt3);
        match encrypt_v2(key, &p.texts.join(" ")) {
            Ok(r) => {
                println!("{r}");
                return 0;
            }
            Err(e) => {
                eprintln!("error: {e}");
                return 1;
            }
        }
    }

    if p.texts.is_empty() {
        eprintln!("error: no text provided");
        return 1;
    }
    // Otherwise treat the input as happ encryption (crypt5 by default)
    let mut ord = p.ordinal;
    if ord == -1 {
        ord = 4;
    }
    let mode = HappMode::from_ordinal(ord as usize).unwrap_or(HappMode::Crypt5);
    let plaintext = p.texts.join(" ");
    // crypt5 defaults to the new salted layout; crypt5old/crypt5legacy select the legacy layout
    let result = if mode == HappMode::Crypt5 && p.crypt5_legacy {
        encrypt_crypt5_legacy(&plaintext)
    } else {
        encrypt_happ(mode, &plaintext)
    };
    match result {
        Ok(r) => {
            println!("{r}");
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

