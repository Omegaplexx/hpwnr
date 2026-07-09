# hpwnr

Command-line version of [Happwner](https://github.com/Omegaplexx/Happwner). A **Happ** and **V2RayTun** subscription-link decryptor/encryptor that can fetch, decrypt, encrypt, and convert proxy profiles. It is available as both a CLI tool and a Rust library, built on a from-scratch reimplementation of the Happ and V2RayTun crypto.

Developed by slavrom21 & Omegaplex


## Features

* Decrypt `happ://crypt*/` links. Supported formats: `crypt5`, `crypt4`, `crypt3`, `crypt2`, `crypt`
* Decrypt `v2raytun://crypt/` links. Supported keys: `crypt3`, `crypt4`, `key3`
* Encrypt plaintext back into any of those formats
* Resolve wrapper/redirect links: `happ://add/`, `v2raytun://import/`, `incy://add/`, `incy://import/`, and `happ://` or `v2raytun://` links embedded in `http(s)` URLs
* Fetch subscription profiles over HTTP (custom User-Agent / X-HWID) and automatically decrypt the AES-128-GCM body layer *(full build only, see [Variants](#variants))*
* Convert Xray configs into `vless`/`vmess`/`trojan`/`hy2`/`ss`/`tuic` links, or into a merged **sing-box** config


## Variants

hpwnr builds in two flavors, selected with a Cargo feature:

* **full** (default) — everything above, including HTTP fetch and AES-128-GCM response decryption. Pulls in a TLS stack (`ureq` + `ring`).
* **lite** (`--no-default-features`) — crypt/decrypt and convert only, with the whole network stack removed: no fetch, no AES response layer, no User-Agent/HWID handling. It has no C dependencies, which makes it roughly a third of the size (~0.8 MB vs ~2.1 MB) and portable to far more targets.

```bash
cargo build --release                        # full
cargo build --release --no-default-features  # lite
```

The `fetch` feature is what carries the network stack; `default = ["fetch"]`, so dropping default features gives the lite build.


## Usage

`hpwnr <link> <arguments>`

Use `h` or `help` to show the help page. The argument order and leading hyphens do not matter, so `h`, `-h`, `--help` all work.

### Supported URLs

* `https://…` - a regular HTTPS URL
* `happ://crypt…` - an encrypted Happ link
* `v2raytun://crypt/…` - an encrypted V2RayTun link
* `happ://add…`, `v2raytun://import…`, `incy://add…`, `incy://import…` - the Happ/V2RayTun/INCY "open-in" deeplinks
* `https://somesite.com/happ%3A%2F%2Fcrypt…` - an encrypted Happ link embedded in an HTTPS URL
* `https://somesite.com/mysub?key=key[01-10]` - a URL with a `key` parameter. In fetch mode, if the server returns an `Encrypt-Tag` header, the response body is decrypted automatically (AES-128-GCM) with that key

### Arguments

#### Decryption

No arguments needed. Use `hpwnr <crypt link>` to decrypt.

#### Encryption

* `crypt` / `crypt[2-5]` - encrypt the given text into the matching `happ://crypt*` format. `crypt5` is the default. Works only with decrypted text
* `crypt5old` / `crypt5legacy` - encrypt with the legacy `crypt5` layout; plain `crypt5` uses the new salted+XOR layout. Both decrypt automatically
* `v2` / `v2r` / `v2ray` / `v2raytun` - encrypt into `v2raytun://crypt` format. The default key is `crypt3`. Works only with decrypted text
* `crypt3` / `crypt4` / `key3` - pick the V2RayTun key (use after the `v2` argument)

#### Fetching

*Full build only (omitted from the lite variant).*

A link is fetched when you pass `fetch`, `hwid`, or `ua`, or when a convert mode (`sb`/`uri`/`b64`/`raw`) follows an `http(s)` URL. It is resolved and decrypted first if needed, then requested.

* `fetch` - fetch the link with no extra headers (use when you do not need `hwid`/`ua`)
* `hwid <value>` - fetch and send the `X-HWID` header. Usually paired with `ua`
* `ua <happ / incy / v2 / "MyCustomUA">` - fetch and send the `User-Agent` header. Aliases: `happ` → `Happ/3.26.1`, `incy` → `INCY/3.3.1`, `v2` / `v2r` / `v2ray` / `v2raytun` → `v2raytun/android`

#### Conversion

Conversion runs on a fetched profile, on a local file, or on stdin. A convert mode after an `http(s)` URL fetches that URL first; after a local path it converts the file; with no positional input it reads stdin.

* `raw` - return the response as is, no conversion
* `b64` - same, but decode Base64 if needed
* `uri` - convert Xray configs to `vless`/`vmess`/`trojan`/`hy2`/`ss`/`tuic` links (default)
* `sb` - convert Xray configs to a merged sing-box config (unsupported outbounds are skipped)

Combine `sb` and `uri` to get only sing-box-compatible URIs: unsupported outbounds are dropped and vless flow is normalized to a sing-box-valid form.

#### Output

* A fetched response prints when it is small; over 15000 characters it is written to `hpwnresp_<domain>.txt` instead, overwritten on each run.
* Converting a local file writes a sibling copy `<name>_<mode>.<ext>`, where `<mode>` is `sb`, `uri`, `b64`, or `sb+uri`, replacing any existing mode suffix.
* Everything else (decryption, encryption, stdin conversion, small responses) prints to stdout.

### Usage examples

#### Decryption

```
# Happ
hpwnr happ://crypt5/…
hpwnr happ://crypt4/…

# V2RayTun
hpwnr v2raytun://crypt/…
```

#### Encryption

```
# Happ (crypt5 by default, or pick a format)
hpwnr https://example.com/sub
hpwnr https://example.com/sub crypt4
hpwnr https://example.com/sub crypt5old   # legacy crypt5 layout

# V2RayTun (crypt3 by default, or pick a key)
hpwnr https://example.com/sub v2
hpwnr https://example.com/sub v2r crypt4
```

#### Fetching

```
hpwnr https://example.com/sub fetch
hpwnr https://example.com/sub hwid abc123
hpwnr https://example.com/sub hwid abc123 ua happ
hpwnr https://example.com/sub hwid f8xdh2e6d5140zv7 ua "My/Custom/UA"
```

#### Conversion

```
# fetch + convert
hpwnr https://example.com/sub sb
hpwnr https://example.com/sub hwid 1234 ua v2 sb
hpwnr https://example.com/sub hwid 1234 ua happ sb uri

# local file / stdin (no fetch)
hpwnr subscription.txt sb
cat subscription.txt | hpwnr uri
```


## Build

```bash
cargo build --release                        # full, binary at target/release/hpwnr
cargo build --release --no-default-features   # lite (see Variants)
```

Cross-compile with [`cross`](https://github.com/cross-rs/cross), which supplies the per-target toolchains (including the Android NDK):

```bash
cross build --release --target aarch64-linux-android
cross build --release --target x86_64-unknown-linux-musl
```

The release profile is size-optimized and stripped; musl targets are statically linked. Add `--no-default-features` to any of these commands to build the lite variant instead.

### Supported platforms

Both variants build for every mainstream target: musl Linux (`x86_64`/`i686`/`aarch64`/`armv7`/`riscv64`), Windows (gnu/MinGW, `x86_64` and `i686`), every Android ABI (`aarch64`/`armv7`/`x86_64`/`i686`), and macOS and iOS (linked on a Mac). Because lite has no C dependencies it also reaches targets the full build cannot, such as ARMv6 (`arm-unknown-linux-musleabihf`) and WebAssembly (`wasm32-wasip1`).

Two manual GitHub Actions workflows build both variants for all of these targets. `.github/workflows/release.yml` publishes them to a GitHub Release, with assets named `hpwnr-<platform>` (full) and `hpwnr-lite-<platform>` (lite). `.github/workflows/build.yml` builds without releasing: by default it uploads each binary as its own artifact, or, with its `individual_binaries` option turned off, collects them into two zip archives (`hpwnr_v<version>` and `hpwnr-lite_v<version>`).


## Library usage

```toml
[dependencies]
hpwnr = "1.0.0"
```

```rust
use hpwnr::{decrypt, encrypt_happ, encrypt_crypt5_legacy, encrypt_v2, fetch, unwrap_link, inspect, convert, ConvertOps, HappMode, V2Key};

let link  = encrypt_happ(HappMode::Crypt5, "https://example.com/sub")?; // crypt5 = new salted layout
let old   = encrypt_crypt5_legacy("https://example.com/sub")?;          // legacy crypt5 layout
let plain = decrypt(&link)?;                        // happ and v2raytun
let real  = unwrap_link("happ://add/…");            // resolve wrappers/redirects
let body  = fetch(&plain, "happ", "HWID123")?;      // download + strip AES-GCM
let info  = inspect(&link);                         // classify without decrypting
let norm  = convert(subscription, ConvertOps::ALL); // JSON outbounds -> proxy URIs
let sb    = convert(subscription, ConvertOps::SINGBOX | ConvertOps::BASE64); // Xray -> sing-box
# let subscription = "";
# Ok::<(), hpwnr::Error>(())
```

For pasted input, `resolve_and_decrypt` unwraps any wrapper/embedded link then decrypts, returning `Ok(None)` if the result is not an encrypted link:

```rust
use hpwnr::resolve_and_decrypt;

if let Some(plain) = resolve_and_decrypt("happ://add/…")? {
    println!("{plain}");
}
# Ok::<(), hpwnr::Error>(())
```

All fallible calls return `Result<T, hpwnr::Error>`; `Error` is a plain `enum` you can `match` on. `ConvertOps` values (`LINKS`, `BASE64`, `ALL`, `SINGBOX`) combine with `|`.

The `fetch` and `decrypt_response_body` functions, along with the `AesGcm` / `AesTagLen` / `Http` error variants, require the default `fetch` feature. For a library without the bundled HTTP/TLS stack (matching the lite CLI variant), disable it:

```toml
[dependencies]
hpwnr = { version = "1.0.0", default-features = false }
```

Every public item is documented; run `cargo doc --open` for the full API reference.

> **Note:** the crate exposes a Rust API. To call it from another language, run the CLI binary as a subprocess (see [Calling from other languages](#calling-from-other-languages)).


## Calling from other languages

hpwnr ships as a Rust library, but the CLI binary doubles as a language-agnostic backend: spawn it as a subprocess, pass each link or value as its own argument (or pipe a subscription blob to stdin), and read the result from stdout.

**Contract**

* The result (decrypted URL, encrypted link, or converted config) is written to **stdout**.
* Errors are written to **stderr**, prefixed with `error:`, with **exit code 1**; success is exit code 0.
* Pass each link/value as one argument, and prefer the argv/exec form (arrays, `ProcessBuilder`, `ArgumentList`) over a shell command string so that `?`, `&`, and `%` inside URLs need no escaping.
* Convert a blob you already have by piping it to stdin: `… | hpwnr sb`.
* One exception to stdout: a *fetched* response over 15000 characters is written to `hpwnresp_<domain>.txt` in the working directory (the path is echoed to stderr as `saved to: …`) instead of stdout. Decrypt, encrypt, and local/stdin conversion always print to stdout.

**Python**

```python
import subprocess

def hpwnr(*args, stdin=None):
    r = subprocess.run(["hpwnr", *args], input=stdin,
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip())
    return r.stdout.strip()

url  = hpwnr("happ://crypt5/…")                    # decrypt
link = hpwnr("https://example.com/sub", "crypt4")  # encrypt
sb   = hpwnr("sb", stdin=open("sub.txt").read())   # convert a blob to sing-box
```

**Node.js**

```javascript
const { execFileSync } = require("node:child_process");

const hpwnr = (args, stdin) =>
  execFileSync("hpwnr", args, { input: stdin, encoding: "utf8" }).trim();

const url  = hpwnr(["happ://crypt5/…"]);
const link = hpwnr(["https://example.com/sub", "crypt4"]);
const sb   = hpwnr(["sb"], subscriptionText);
```

**Java**

```java
static String hpwnr(String... args) throws IOException, InterruptedException {
    var cmd = new ArrayList<String>(List.of("hpwnr"));
    cmd.addAll(List.of(args));
    Process p = new ProcessBuilder(cmd).start();
    byte[] out = p.getInputStream().readAllBytes();   // stdout
    byte[] err = p.getErrorStream().readAllBytes();   // stderr (always small)
    if (p.waitFor() != 0) throw new IOException(new String(err).strip());
    return new String(out).strip();
}

String url  = hpwnr("happ://crypt5/…");
String link = hpwnr("https://example.com/sub", "crypt4");
```

**C#**

```csharp
using System.Diagnostics;

static string Hpwnr(string[] args, string? stdin = null) {
    var psi = new ProcessStartInfo("hpwnr") {
        RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
    };
    foreach (var a in args) psi.ArgumentList.Add(a);
    using var p = Process.Start(psi)!;
    if (stdin is not null) { p.StandardInput.Write(stdin); p.StandardInput.Close(); }
    string outp = p.StandardOutput.ReadToEnd();
    string errp = p.StandardError.ReadToEnd();
    p.WaitForExit();
    if (p.ExitCode != 0) throw new Exception(errp.Trim());
    return outp.Trim();
}

string url  = Hpwnr(new[] { "happ://crypt5/…" });
string link = Hpwnr(new[] { "https://example.com/sub", "crypt4" });
```

**C / C++**

```c
// popen captures stdout; stderr stays on the parent. For stdin input or robust
// error capture, use pipe() + fork() + execvp() instead of a shell string.
FILE *p = popen("hpwnr 'happ://crypt5/…'", "r");   // quote args in shell form
char out[65536];
size_t n = fread(out, 1, sizeof out - 1, p);
out[n] = '\0';
int rc = pclose(p);                                 // rc != 0 => error
```

Any language that can spawn a process and read stdout works the same way (Go `os/exec`, Ruby `Open3`, PHP `proc_open`, and so on).


## License

Provided as is, without warranty. Use it only for legal analysis, interoperability, research, and education, and only with data you are entitled to access. Happ, V2RayTun, and related names may be protected by third-party rights; this project is not affiliated with their owners.
