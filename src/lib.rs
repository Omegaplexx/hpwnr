//! Happ and V2RayTun subscription-link decryptor/encryptor that can fetch, decrypt, encrypt, and convert proxy profiles.
//!
//! This crate reads `happ://` and `v2raytun://` links back to their plaintext URLs, builds
//! fresh links from a URL, and converts Xray configs into sing-box configs or proxy URIs.
//! With the `fetch` feature it can also request a subscription and decrypt the response body.
//!
//! All functions are panic-free: bad input is reported through [`Error`], never a panic. Only
//! `fetch` performs network I/O.
//! Disable default features (`default-features = false`) for a build without the HTTP fetch stack.
//!
//! # Examples
//!
//! ```
//! use hpwnr::{encrypt_happ, decrypt, HappMode};
//!
//! let link = encrypt_happ(HappMode::Crypt5, "https://example.com/sub")?;
//! assert_eq!(decrypt(&link)?, "https://example.com/sub");
//! # Ok::<(), hpwnr::Error>(())
//! ```

#![forbid(unsafe_code)]

mod keys;
mod json;
mod convert;
mod singbox;

pub use convert::{convert, ConvertOps};

#[cfg(feature = "fetch")]
use std::io::Read;
use base64::{Engine, engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD}};
use rand::{RngCore, rngs::OsRng};
use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce};
#[cfg(feature = "fetch")]
use aes_gcm::{Aes128Gcm, Nonce as GcmNonce};

/// Errors returned by this crate.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Input was not valid base64.
    Base64,
    /// An RSA operation failed (parsing or decrypt/encrypt).
    Rsa(String),
    /// ChaCha20-Poly1305 authentication or decryption failed.
    ChaCha,
    /// AES-128-GCM authentication or decryption failed.
    #[cfg(feature = "fetch")]
    AesGcm,
    /// The Encrypt-Tag was not 16 bytes.
    #[cfg(feature = "fetch")]
    AesTagLen(usize),
    /// crypt..crypt4 ciphertext length is not a multiple of the RSA block size.
    BlockAlignment,
    /// The input did not start with a recognized happ:// or v2raytun:// prefix.
    UnknownPrefix,
    /// crypt5 payload was too short.
    Crypt5PayloadTooShort,
    /// crypt5 body was too short.
    Crypt5BodyTooShort,
    /// crypt5 segment-length digits were missing.
    Crypt5SegmentLengthMissing,
    /// crypt5 encrypted segment was truncated.
    Crypt5SegmentTruncated,
    /// crypt5 ChaCha20 key had an unexpected length.
    ChaChaKeyLen(usize),
    /// crypt5 salted-layout header was too short to hold the tag and salt.
    Crypt5SaltedHeaderTooShort,
    /// crypt5 salt had an unexpected length.
    Crypt5SaltLen(usize),
    /// No PKCS#8 key matched the crypt5 marker.
    UnknownCrypt5Marker(String),
    /// No embedded key matched the given name.
    UnknownKey(String),
    /// Plaintext is too large for a single V2RayTun RSA block.
    V2TooLong {
        /// Length of the plaintext in bytes.
        len: usize,
        /// Maximum bytes that fit in one RSA block.
        max: usize,
    },
    /// Could not produce a clean V2RayTun link within the retry budget.
    V2NoCleanLink,
    /// HTTP request failed.
    #[cfg(feature = "fetch")]
    Http(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Base64 => write!(f, "invalid base64"),
            Error::Rsa(e) => write!(f, "rsa error: {e}"),
            Error::ChaCha => write!(f, "chacha20-poly1305 decrypt failed"),
            #[cfg(feature = "fetch")]
            Error::AesGcm => write!(f, "aes-128-gcm decrypt failed"),
            #[cfg(feature = "fetch")]
            Error::AesTagLen(n) => write!(f, "Encrypt-Tag must be 16 bytes, got {n}"),
            Error::BlockAlignment => write!(f, "ciphertext length is not a multiple of the RSA block size"),
            Error::UnknownPrefix => write!(f, "not a recognized happ:// or v2raytun:// link"),
            Error::Crypt5PayloadTooShort => write!(f, "crypt5 payload too short"),
            Error::Crypt5BodyTooShort => write!(f, "crypt5 body too short"),
            Error::Crypt5SegmentLengthMissing => write!(f, "crypt5 segment length missing"),
            Error::Crypt5SegmentTruncated => write!(f, "crypt5 segment truncated"),
            Error::ChaChaKeyLen(n) => write!(f, "unexpected crypt5 chacha key length: {n}"),
            Error::Crypt5SaltedHeaderTooShort => write!(f, "crypt5 salted header too short"),
            Error::Crypt5SaltLen(n) => write!(f, "unexpected crypt5 salt length: {n}"),
            Error::UnknownCrypt5Marker(m) => write!(f, "unknown crypt5 marker: {m}"),
            Error::UnknownKey(k) => write!(f, "unknown key: {k}"),
            Error::V2TooLong { len, max } => write!(f, "v2raytun plaintext {len} bytes exceeds max {max}"),
            Error::V2NoCleanLink => write!(f, "v2raytun: could not produce a clean link"),
            #[cfg(feature = "fetch")]
            Error::Http(e) => write!(f, "http error: {e}"),
        }
    }
}

impl std::error::Error for Error {}

/// Crate result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Happ encryption mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HappMode {
    /// crypt: RSA-1024
    Crypt,
    /// crypt2: RSA-4096
    Crypt2,
    /// crypt3: RSA-4096
    Crypt3,
    /// crypt4: RSA-4096
    Crypt4,
    /// crypt5: RSA-4096 plus ChaCha20-Poly1305
    Crypt5,
}

impl HappMode {
    /// Build a mode from its ordinal (0=crypt .. 4=crypt5)
    pub fn from_ordinal(o: usize) -> Option<HappMode> {
        match o {
            0 => Some(HappMode::Crypt),
            1 => Some(HappMode::Crypt2),
            2 => Some(HappMode::Crypt3),
            3 => Some(HappMode::Crypt4),
            4 => Some(HappMode::Crypt5),
            _ => None,
        }
    }
    /// The textual name (crypt, crypt2, etc.)
    pub fn name(self) -> &'static str { MODE_NAMES[self.ordinal()] }
    fn ordinal(self) -> usize {
        match self {
            HappMode::Crypt => 0,
            HappMode::Crypt2 => 1,
            HappMode::Crypt3 => 2,
            HappMode::Crypt4 => 3,
            HappMode::Crypt5 => 4,
        }
    }
}

/// V2RayTun key choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V2Key {
    /// crypt3 (default).
    Crypt3,
    /// crypt4.
    Crypt4,
    /// key3.
    Key3,
}

impl V2Key {
    /// Build a key from its index (0=crypt3, 1=crypt4, 2=key3).
    pub fn from_index(i: usize) -> Option<V2Key> {
        match i {
            0 => Some(V2Key::Crypt3),
            1 => Some(V2Key::Crypt4),
            2 => Some(V2Key::Key3),
            _ => None,
        }
    }
    fn index(self) -> usize {
        match self {
            V2Key::Crypt3 => 0,
            V2Key::Crypt4 => 1,
            V2Key::Key3 => 2,
        }
    }
    fn name(self) -> &'static str { keys::V2_KEYS[self.index()].0 }
}

/// The kind of link an input is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkKind {
    /// A happ://cryptN/ link in the given mode.
    Happ(HappMode),
    /// A v2raytun://crypt/ link.
    V2RayTun,
    /// Not a recognized encrypted link.
    Plain,
}

/// Result of inspect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputInfo {
    /// Detected link kind.
    pub kind: LinkKind,
    /// Length of the payload after the scheme prefix.
    pub payload_len: usize,
    /// For crypt5, the 8-char PKCS#8 marker, if recoverable.
    pub crypt5_marker: Option<String>,
}

const V2_PREFIX: &str = "v2raytun://crypt/";
const ADD_PREFIX: &str = "happ://add/";
const IMPORT_PREFIX: &str = "v2raytun://import/";
// Fixed IV "kkkkkkkkkkkk" (12 bytes of 0x6b)
#[cfg(feature = "fetch")]
const AES_GCM_IV: &[u8; 12] = b"kkkkkkkkkkkk";
// Mode names indexed by ordinal: crypt=0 ... crypt5=4
const MODE_NAMES: [&str; 5] = ["crypt", "crypt2", "crypt3", "crypt4", "crypt5"];
// crypt5 marker kept for decryption only, never picked when encrypting (orphaned in every Happ build)
const CRYPT5_ENCRYPT_EXCLUDE_MARKER: &str = "qzmtapkx";
// happ:// prefixes mapped to ordinals, longest first so crypt5 wins over crypt
const HAPP_PREFIXES: [(&str, i32); 5] = [
    ("happ://crypt5/", 4),
    ("happ://crypt4/", 3),
    ("happ://crypt3/", 2),
    ("happ://crypt2/", 1),
    ("happ://crypt/", 0),
];

// base64 decode, normalized: strip whitespace, url-safe to standard, re-pad with =
fn b64_dec(s: &[u8]) -> Result<Vec<u8>> {
    let mut clean: Vec<u8> = Vec::with_capacity(s.len());
    for &c in s {
        match c {
            b' ' | b'\n' | b'\r' | b'\t' => {}
            b'-' => clean.push(b'+'),
            b'_' => clean.push(b'/'),
            _ => clean.push(c),
        }
    }
    let r = clean.len() % 4;
    if r != 0 {
        clean.resize(clean.len() + (4 - r), b'=');
    }
    STANDARD.decode(&clean).map_err(|_| Error::Base64)
}

// Standard base64 encode
fn b64_enc(b: &[u8]) -> String {
    STANDARD.encode(b)
}

// URL-safe base64 encode, no padding
fn b64_enc_url(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

// Decode url-safe base64 that has no padding (drop any stray =)
fn url_dec_nopad(s: &str) -> Result<Vec<u8>> {
    let stripped: Vec<u8> = s.bytes().filter(|&c| c != b'=').collect();
    URL_SAFE_NO_PAD.decode(&stripped).map_err(|_| Error::Base64)
}

// Swap adjacent bytes in pairs (ABCD -> BADC); self-inverse
fn swap_pairs(b: &[u8]) -> Vec<u8> {
    let mut r = b.to_vec();
    let mut i = 0;
    while i + 1 < r.len() {
        r.swap(i, i + 1);
        i += 2;
    }
    r
}

// Swap the two halves of each 4-byte block (ABCD -> CDAB); self-inverse
fn block_pair_swap(b: &[u8]) -> Vec<u8> {
    let mut r = b.to_vec();
    let full = r.len() - r.len() % 4;
    let mut i = 0;
    while i < full {
        r.swap(i, i + 2);
        r.swap(i + 1, i + 3);
        i += 4;
    }
    r
}

// PKCS#1 RSA key for crypt..crypt4, by ordinal
fn load_pkcs1(ordinal: usize) -> Result<RsaPrivateKey> {
    let der = STANDARD.decode(keys::PKCS1_KEYS[ordinal].as_bytes()).map_err(|_| Error::Base64)?;
    RsaPrivateKey::from_pkcs1_der(&der).map_err(|e| Error::Rsa(e.to_string()))
}

// Parse a PKCS#8 RSA private key from base64
fn load_pkcs8(b64: &str) -> Result<RsaPrivateKey> {
    let der = STANDARD.decode(b64.as_bytes()).map_err(|_| Error::Base64)?;
    RsaPrivateKey::from_pkcs8_der(&der).map_err(|e| Error::Rsa(e.to_string()))
}

// PKCS#8 key for a crypt5 marker (first + last 4 chars of the payload)
fn load_crypt5(marker: &str) -> Result<RsaPrivateKey> {
    let b64 = keys::CRYPT5_PKCS8
        .iter()
        .find(|(k, _)| *k == marker)
        .map(|(_, v)| *v)
        .ok_or_else(|| Error::UnknownCrypt5Marker(marker.to_string()))?;
    load_pkcs8(b64)
}

// PKCS#8 key for a v2raytun key name (crypt3, crypt4, key3)
fn load_v2(name: &str) -> Result<RsaPrivateKey> {
    let b64 = keys::V2_KEYS
        .iter()
        .find(|(k, _)| *k == name)
        .map(|(_, v)| *v)
        .ok_or_else(|| Error::UnknownKey(name.to_string()))?;
    load_pkcs8(b64)
}

// RSA encrypt one block, PKCS#1 v1.5 padding
fn rsa_encrypt(pub_key: &RsaPublicKey, data: &[u8]) -> Result<Vec<u8>> {
    let mut rng = OsRng;
    pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, data).map_err(|e| Error::Rsa(e.to_string()))
}

// RSA decrypt one block, PKCS#1 v1.5 padding
fn rsa_decrypt(priv_key: &RsaPrivateKey, ct: &[u8]) -> Result<Vec<u8>> {
    priv_key.decrypt(Pkcs1v15Encrypt, ct).map_err(|e| Error::Rsa(e.to_string()))
}

// ChaCha20-Poly1305 open (12-byte nonce, empty AAD); tag is the trailing 16 bytes
fn chacha_decrypt(key: &[u8], nonce: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::ChaCha)?;
    cipher.decrypt(ChaNonce::from_slice(nonce), ct).map_err(|_| Error::ChaCha)
}

// ChaCha20-Poly1305 seal (12-byte nonce, empty AAD); output is ciphertext||tag
fn chacha_encrypt(key: &[u8], nonce: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::ChaCha)?;
    cipher.encrypt(ChaNonce::from_slice(nonce), pt).map_err(|_| Error::ChaCha)
}

// AES-128-GCM open for subscription bodies; tag arrives separately in the Encrypt-Tag header
#[cfg(feature = "fetch")]
fn decrypt_aes_gcm(body_b64: &str, tag_b64: &str, key: &[u8]) -> Result<Vec<u8>> {
    // Body and tag use the same flexible base64 as everywhere else, matching b64DecodeFlexible
    let ct = b64_dec(body_b64.as_bytes())?;
    let tag = b64_dec(tag_b64.as_bytes())?;
    if tag.len() != 16 {
        return Err(Error::AesTagLen(tag.len()));
    }
    let gcm = Aes128Gcm::new_from_slice(key).map_err(|_| Error::AesGcm)?;
    // RustCrypto's aead wants the tag appended to the ciphertext
    let mut joined = ct;
    joined.extend_from_slice(&tag);
    gcm.decrypt(GcmNonce::from_slice(AES_GCM_IV.as_slice()), joined.as_slice()).map_err(|_| Error::AesGcm)
}

// crypt..crypt4: RSA/PKCS1, decrypted block by block by key size
fn decrypt_crypt(ordinal: usize, payload: &str) -> Result<String> {
    let priv_key = load_pkcs1(ordinal)?;
    let ct = b64_dec(payload.as_bytes())?;
    if ct.is_empty() {
        return Err(Error::Rsa("crypt: empty ciphertext".into()));
    }
    let pub_key = priv_key.to_public_key();
    let ks = pub_key.size();
    if ct.len() % ks != 0 {
        return Err(Error::BlockAlignment);
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < ct.len() {
        let plain = rsa_decrypt(&priv_key, &ct[i..i + ks])?;
        out.extend_from_slice(&plain);
        i += ks;
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

// crypt..crypt4: RSA/PKCS1, encrypted block by block (key size - 11 bytes per block)
fn encrypt_crypt(ordinal: usize, plaintext: &str) -> Result<String> {
    let priv_key = load_pkcs1(ordinal)?;
    let pub_key = priv_key.to_public_key();
    let ks = pub_key.size();
    let max_chunk = ks - 11;
    let data = plaintext.as_bytes();
    let mut out = Vec::new();
    let mut off = 0;
    while off < data.len() {
        let n = std::cmp::min(max_chunk, data.len() - off);
        let enc = rsa_encrypt(&pub_key, &data[off..off + n])?;
        out.extend_from_slice(&enc);
        off += n;
    }
    Ok(format!("happ://{}/{}", MODE_NAMES[ordinal], b64_enc(&out)))
}

// crypt5: block-swap, then RSA(PKCS8) yields a ChaCha key, then ChaCha20-Poly1305, then base64.
// Two body layouts (legacy / salted); body[12] being a digit picks legacy first, the other is a fallback.
fn decrypt_crypt5(payload: &str) -> Result<String> {
    let shuffled = block_pair_swap(payload.as_bytes());
    if shuffled.len() < 8 {
        return Err(Error::Crypt5PayloadTooShort);
    }
    let n = shuffled.len();
    // First + last 4 chars pick the PKCS#8 key; the middle is the body
    let mut marker_bytes = Vec::with_capacity(8);
    marker_bytes.extend_from_slice(&shuffled[0..4]);
    marker_bytes.extend_from_slice(&shuffled[n - 4..n]);
    let marker = String::from_utf8_lossy(&marker_bytes).into_owned();
    let body = &shuffled[4..n - 4];
    if body.len() < 13 {
        return Err(Error::Crypt5BodyTooShort);
    }

    let priv_key = load_crypt5(&marker)?;

    let prefer_salted = body.len() > 12 && !body[12].is_ascii_digit();
    let layouts = if prefer_salted { [true, false] } else { [false, true] };

    let mut last_err = Error::Crypt5BodyTooShort;
    for &salted in &layouts {
        match decrypt_crypt5_body(body, &priv_key, salted) {
            Ok(plain) => return Ok(plain),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

// Decrypt one crypt5 body in the given layout (see decrypt_crypt5).
fn decrypt_crypt5_body(body: &[u8], priv_key: &RsaPrivateKey, salted: bool) -> Result<String> {
    // 12-byte nonce; the salted layout inserts a 2-char tag + 8-char salt before the segment
    let nonce = &body[0..12];
    let (salt, len_start): (Option<&[u8]>, usize) = if salted {
        if body.len() < 22 {
            return Err(Error::Crypt5SaltedHeaderTooShort);
        }
        (Some(&body[14..22]), 22)
    } else {
        (None, 12)
    };

    // digits = length of the url-b64 segment, then the RSA blob
    let rest = &body[len_start..];
    let mut digit_count = 0;
    while digit_count < rest.len() && rest[digit_count].is_ascii_digit() {
        digit_count += 1;
    }
    if digit_count == 0 {
        return Err(Error::Crypt5SegmentLengthMissing);
    }
    let mut seg_len: usize = 0;
    for &c in &rest[0..digit_count] {
        seg_len = match seg_len.checked_mul(10).and_then(|v| v.checked_add((c - b'0') as usize)) {
            Some(v) => v,
            None => return Err(Error::Crypt5SegmentTruncated),
        };
    }
    let packed = &rest[digit_count..];
    // packed is a 1-byte separator + seg_len bytes + RSA blob; check length without overflowing 1 + seg_len.
    if packed.is_empty() || seg_len > packed.len() - 1 {
        return Err(Error::Crypt5SegmentTruncated);
    }
    let url_b64 = &packed[1..1 + seg_len];
    let rsa_cipher = &packed[1 + seg_len..];

    // RSA-decrypt (after un-swap + base64) to recover the 32-byte value behind the ChaCha key
    let rsa_ct = b64_dec(rsa_cipher)?;
    let rsa_plain = rsa_decrypt(priv_key, &rsa_ct)?;
    let rsa_value = b64_dec(&swap_pairs(&rsa_plain))?;
    if rsa_value.len() != 32 {
        return Err(Error::ChaChaKeyLen(rsa_value.len()));
    }

    // salted: XOR the repeated 8-byte salt into the RSA value to get the ChaCha key
    let chacha_key: Vec<u8> = match salt {
        Some(s) => {
            if s.len() != 8 {
                return Err(Error::Crypt5SaltLen(s.len()));
            }
            (0..32).map(|i| rsa_value[i] ^ s[i % 8]).collect()
        }
        None => rsa_value,
    };

    // ChaCha20-Poly1305 decrypt, then one more swap + base64 to the plaintext
    let ciphertext = b64_dec(url_b64)?;
    let intermediate = chacha_decrypt(&chacha_key, nonce, &ciphertext)?;
    let plain = b64_dec(&swap_pairs(&intermediate))?;
    Ok(String::from_utf8_lossy(&plain).into_owned())
}

// crypt5 encrypt: builds a link that decrypt_crypt5 reads back.
// salted = 2-char tag + 8-char salt after the nonce (key = salt XOR rsaValue); legacy = neither (rsaValue is the key).
fn encrypt_crypt5(plaintext: &str, salted: bool) -> Result<String> {
    // skip the decrypt-only orphan marker (see CRYPT5_ENCRYPT_EXCLUDE_MARKER)
    let candidates: Vec<&(&str, &str)> = keys::CRYPT5_PKCS8
        .iter()
        .filter(|(m, _)| *m != CRYPT5_ENCRYPT_EXCLUDE_MARKER)
        .collect();
    let mut idx = [0u8; 1];
    OsRng.fill_bytes(&mut idx);
    // Random marker decides the PKCS#8 key
    let (marker, _) = *candidates[idx[0] as usize % candidates.len()];
    let priv_key = load_crypt5(marker)?;
    let pub_key = priv_key.to_public_key();

    const ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Fresh 32-byte ChaCha key
    let mut chacha_key = [0u8; 32];
    OsRng.fill_bytes(&mut chacha_key);

    // salted layout: 8-char salt + 2-char tag, both non-digit letters; tag[0] routes decrypt here, a digit in tag[1] makes Happ reject.
    let (salt, tag): (Option<[u8; 8]>, Option<[u8; 2]>) = if salted {
        let mut s = [0u8; 8];
        OsRng.fill_bytes(&mut s);
        for b in s.iter_mut() {
            *b = ALNUM[*b as usize % ALNUM.len()];
        }
        let mut t = [0u8; 2];
        OsRng.fill_bytes(&mut t);
        t[0] = LETTERS[t[0] as usize % LETTERS.len()];
        t[1] = LETTERS[t[1] as usize % LETTERS.len()];
        (Some(s), Some(t))
    } else {
        (None, None)
    };

    // salted: the RSA blob carries (key XOR repeated-salt) so decrypt recovers the key; legacy: the key itself
    let rsa_value: [u8; 32] = match &salt {
        Some(s) => core::array::from_fn(|i| chacha_key[i] ^ s[i % 8]),
        None => chacha_key,
    };
    let swapped = swap_pairs(b64_enc(&rsa_value).as_bytes());
    let rsa_ct_b64 = b64_enc(&rsa_encrypt(&pub_key, &swapped)?);

    // 12-char ASCII nonce drawn from an alphanumeric alphabet
    let mut nonce_raw = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_raw);
    for b in nonce_raw.iter_mut() {
        *b = ALNUM[*b as usize % ALNUM.len()];
    }

    let plaintext_b64 = b64_enc(plaintext.as_bytes());
    let swapped_pt = swap_pairs(plaintext_b64.as_bytes());
    let ct_with_tag = chacha_encrypt(&chacha_key, &nonce_raw, &swapped_pt)?;
    // Standard base64 (with padding), same as rsa_ct_b64 and crypt1-4: Happ rejects the url-safe -/_ alphabet here
    let url_b64 = b64_enc(&ct_with_tag);

    // body = nonce [+ tag + salt when salted] + segLen + ':' + url-b64(ciphertext||tag) + rsa-b64
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&nonce_raw);
    if let (Some(t), Some(s)) = (&tag, &salt) {
        body.extend_from_slice(t);
        body.extend_from_slice(s);
    }
    body.extend_from_slice(url_b64.len().to_string().as_bytes());
    body.push(b':');
    body.extend_from_slice(url_b64.as_bytes());
    body.extend_from_slice(rsa_ct_b64.as_bytes());

    // Wrap the body in the marker halves, then block-pair-swap the whole thing
    let mut pre = Vec::new();
    pre.extend_from_slice(&marker.as_bytes()[0..4]);
    pre.extend_from_slice(&body);
    pre.extend_from_slice(&marker.as_bytes()[4..8]);
    let shuffled = block_pair_swap(&pre);
    Ok(format!("happ://crypt5/{}", String::from_utf8_lossy(&shuffled)))
}

// v2raytun encrypt: RSA + url-safe base64, retried until the link is clean and round-trips
fn v2_encrypt(key_name: &str, plaintext: &str) -> Result<String> {
    let priv_key = load_v2(key_name)?;
    let pub_key = priv_key.to_public_key();
    let ks = pub_key.size();
    let max_bytes = ks - 11;
    let data = plaintext.as_bytes();
    if data.len() > max_bytes {
        return Err(Error::V2TooLong { len: data.len(), max: max_bytes });
    }
    // Reject links containing __ or -- and verify they decrypt back before accepting
    for _ in 0..10000 {
        let ct = rsa_encrypt(&pub_key, data)?;
        let b64 = b64_enc_url(&ct);
        if b64.contains("__") || b64.contains("--") {
            continue;
        }
        let decoded = match url_dec_nopad(&b64) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let back = match rsa_decrypt(&priv_key, &decoded) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if back.as_slice() == data {
            return Ok(format!("{}{}", V2_PREFIX, b64));
        }
    }
    Err(Error::V2NoCleanLink)
}

// v2raytun decrypt: try each key, require block alignment, decrypt blocks, accept only a strict-UTF-8 scheme link
fn v2_decrypt(payload: &str) -> Result<String> {
    let ct = b64_dec(payload.as_bytes())?;
    if ct.is_empty() {
        return Err(Error::Rsa("v2raytun: empty ciphertext".into()));
    }
    let mut last = Error::Rsa("v2raytun: no embedded key matched".into());
    for &(name, _) in keys::V2_KEYS {
        let priv_key = load_v2(name)?;
        let ks = priv_key.to_public_key().size();
        if ct.len() % ks != 0 {
            last = Error::BlockAlignment;
            continue;
        }
        let mut out = Vec::with_capacity(ct.len());
        let mut whole_ok = true;
        let mut off = 0;
        while off < ct.len() {
            match rsa_decrypt(&priv_key, &ct[off..off + ks]) {
                Ok(block) => out.extend_from_slice(&block),
                Err(_) => {
                    whole_ok = false;
                    break;
                }
            }
            off += ks;
        }
        if !whole_ok {
            continue;
        }
        if let Ok(text) = std::str::from_utf8(&out) {
            let trimmed = text.trim();
            if looks_like_scheme_link(trimmed) {
                return Ok(trimmed.to_string());
            }
        }
    }
    Err(last)
}

// Pull the ?key= value out of a URL's query string
#[cfg(feature = "fetch")]
fn url_key_param(raw: &str) -> String {
    let q = match raw.split_once('?') {
        Some((_, q)) => q,
        None => return String::new(),
    };
    let q = q.split('#').next().unwrap_or("");
    for pair in q.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == "key" {
            return v.to_string();
        }
    }
    String::new()
}

// Look up the 16-byte AES-GCM key by keyNN name
#[cfg(feature = "fetch")]
fn aes_gcm_key(name: &str) -> Option<&'static [u8; 16]> {
    keys::AES_GCM_KEYS.iter().find(|(k, _)| *k == name).map(|(_, v)| v)
}

// block-pair-swap then take first + last 4 chars to recover the crypt5 marker
fn crypt5_marker_of(payload: &str) -> Option<String> {
    let shuffled = block_pair_swap(payload.as_bytes());
    if shuffled.len() < 8 {
        return None;
    }
    let n = shuffled.len();
    let mut m = Vec::with_capacity(8);
    m.extend_from_slice(&shuffled[0..4]);
    m.extend_from_slice(&shuffled[n - 4..n]);
    Some(String::from_utf8_lossy(&m).into_owned())
}

// Hex digit value, or None
fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// Percent-decode %XX escapes; everything else passes through
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len()
            && let (Some(h), Some(l)) = (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ASCII case-insensitive prefix test
fn starts_with_ci(s: &str, prefix: &str) -> bool {
    let sb = s.as_bytes();
    let pb = prefix.as_bytes();
    sb.len() >= pb.len() && sb[..pb.len()].eq_ignore_ascii_case(pb)
}

// ASCII case-insensitive prefix strip
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if starts_with_ci(s, prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

// ASCII case-insensitive substring test
fn contains_ci(s: &str, needle: &str) -> bool {
    s.to_ascii_lowercase().contains(&needle.to_ascii_lowercase())
}

// True if s starts like "<scheme>://" (RFC-ish scheme grammar)
fn looks_like_scheme_link(s: &str) -> bool {
    let s = s.trim_start();
    let b = s.as_bytes();
    if b.is_empty() || !b[0].is_ascii_alphabetic() {
        return false;
    }
    let mut i = 1;
    while i < b.len() {
        let c = b[i];
        if c == b':' {
            return b.len() >= i + 3 && &b[i..i + 3] == b"://";
        }
        if c.is_ascii_alphanumeric() || c == b'+' || c == b'.' || c == b'-' {
            i += 1;
            continue;
        }
        return false;
    }
    false
}

// Decode a base64 blob into a scheme link, if that is what it is
fn decode_base64_link(s: &str) -> Option<String> {
    let cleaned = s.trim();
    if cleaned.len() < 8 {
        return None;
    }
    let mut has_std = false;
    let mut has_url = false;
    for c in cleaned.bytes() {
        match c {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'=' => {}
            b'+' | b'/' => has_std = true,
            b'-' | b'_' => has_url = true,
            _ => return None,
        }
    }
    if has_std && has_url {
        return None;
    }
    let padded = match cleaned.len() % 4 {
        2 => format!("{cleaned}=="),
        3 => format!("{cleaned}="),
        _ => cleaned.to_string(),
    };
    let data = if has_url {
        URL_SAFE.decode(padded.as_bytes()).ok()?
    } else {
        STANDARD.decode(padded.as_bytes()).ok()?
    };
    if data.is_empty() {
        return None;
    }
    for &v in &data {
        if !((0x20..=0x7e).contains(&v) || v == 0x09 || v == 0x0a || v == 0x0d) {
            return None;
        }
    }
    let decoded = String::from_utf8_lossy(&data).trim().to_string();
    if looks_like_scheme_link(&decoded) {
        Some(decoded)
    } else {
        None
    }
}

// Strip happ://add/ or v2raytun://import/ and resolve the inner link (url-decode or base64)
fn unwrap_wrapper(s: &str) -> Option<String> {
    let t = s.trim();
    let inner = strip_prefix_ci(t, ADD_PREFIX).or_else(|| strip_prefix_ci(t, IMPORT_PREFIX))?;
    let mut rest = inner.trim().to_string();
    if rest.is_empty() {
        return None;
    }
    if rest.contains('%') {
        let dec = percent_decode(&rest);
        if !dec.is_empty() {
            rest = dec.trim().to_string();
        }
    }
    if looks_like_scheme_link(&rest) {
        return Some(rest);
    }
    if let Some(b) = decode_base64_link(&rest) {
        return Some(b);
    }
    if rest.is_empty() { None } else { Some(rest) }
}

// Characters that terminate an embedded scheme link
fn is_link_delimiter(c: u8) -> bool {
    if !(0x20..=0x7e).contains(&c) {
        return true;
    }
    matches!(
        c,
        b' ' | b'&' | b'#' | b'"' | b'\'' | b'`' | b'<' | b'>' | b'\\' | b'|' | b'^' | b'{' | b'}' | b'[' | b']'
    )
}

// Index of `<scheme>://` or `<scheme>%3a` (case-insensitive)
fn index_of_scheme(s: &str, scheme: &str) -> Option<usize> {
    let sb = s.as_bytes();
    let scb = scheme.as_bytes();
    let n = sb.len();
    let m = scb.len();
    let mut i = 0;
    while i + m <= n {
        if sb[i..i + m].eq_ignore_ascii_case(scb) {
            let rest = i + m;
            if rest + 3 <= n && &sb[rest..rest + 3] == b"://" {
                return Some(i);
            }
            if rest + 3 <= n && sb[rest] == b'%' && sb[rest + 1] == b'3' && (sb[rest + 2] == b'a' || sb[rest + 2] == b'A') {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

// Take everything from start up to the first delimiter
fn carve_candidate(s: &str, start: usize) -> String {
    let sb = s.as_bytes();
    let mut end = start;
    while end < sb.len() && !is_link_delimiter(sb[end]) {
        end += 1;
    }
    String::from_utf8_lossy(&sb[start..end]).into_owned()
}

// Extract a `<scheme>://` link embedded in an http(s) URL (up to 2 levels of url-decoding)
fn extract_embedded(raw: &str, scheme: &str) -> Option<String> {
    extract_embedded_depth(raw, scheme, 0)
}

fn extract_embedded_depth(raw: &str, scheme: &str, depth: usize) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let full = format!("{scheme}://");
    if starts_with_ci(trimmed, &full) {
        return None;
    }
    if !starts_with_ci(trimmed, "http://") && !starts_with_ci(trimmed, "https://") {
        return None;
    }
    let start = match index_of_scheme(trimmed, scheme) {
        Some(i) => i,
        None => {
            if depth < 2 && contains_ci(trimmed, &format!("{scheme}%")) {
                let once = percent_decode(trimmed);
                if once != trimmed {
                    return extract_embedded_depth(&once, scheme, depth + 1);
                }
            }
            return None;
        }
    };
    let candidate = carve_candidate(trimmed, start);
    let mut decoded = percent_decode(&candidate).trim().to_string();
    let mut guard = 0;
    while guard < 2 && starts_with_ci(&decoded, &format!("{scheme}%")) {
        let next = percent_decode(&decoded);
        let next_t = next.trim().to_string();
        if next_t == decoded {
            break;
        }
        decoded = next_t;
        guard += 1;
    }
    if !starts_with_ci(&decoded, &full) || decoded.len() <= full.len() || decoded == trimmed {
        return None;
    }
    Some(decoded)
}

// Resolve a User-Agent alias (happ, v2, etc.) to its full string, or pass a custom one through
#[cfg(feature = "fetch")]
fn resolve_ua(ua: &str) -> String {
    match ua.to_lowercase().as_str() {
        "happ" => "Happ/4.6.0".to_string(),
        "incy" => "INCY/3.7.0".to_string(),
        "v2raytun" | "v2r" | "v2ray" | "v2" => "v2raytun/android".to_string(),
        _ => ua.to_string(),
    }
}

// --- INCY deep links (incy://add/<url>, incy://import/<base64>): 1:1 port of Happwner's IncyLinks.kt ---
const INCY_ADD_PREFIX: &str = "incy://add/";
const INCY_IMPORT_PREFIX: &str = "incy://import/";
const INCY_SCHEME: &str = "incy://";
const INCY_EXTRACT_MAX_DEPTH: usize = 2;
const INCY_SCHEMES: [&str; 12] = [
    "http://", "https://", "vless://", "vmess://", "trojan://", "ss://", "hy2://", "hysteria2://",
    "socks://", "socks5://", "wireguard://", "wg://",
];

// Is this an incy://add/ or incy://import/ deep link?
fn is_incy_link(link: &str) -> bool {
    let t = link.trim();
    starts_with_ci(t, INCY_ADD_PREFIX) || starts_with_ci(t, INCY_IMPORT_PREFIX)
}

// Whether s starts with one of INCY's accepted schemes
fn incy_looks_like_scheme_link(s: &str) -> bool {
    INCY_SCHEMES.iter().any(|p| starts_with_ci(s, p))
}

// Pad to a multiple of 4, base64-decode (standard) and read as UTF-8; None on failure or empty
fn incy_decode_base64_or_null(s: &str) -> Option<String> {
    let mut t = s.to_string();
    let pad = (4 - t.len() % 4) % 4;
    for _ in 0..pad {
        t.push('=');
    }
    let data = STANDARD.decode(t.as_bytes()).ok()?;
    if data.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&data).into_owned())
}

// Strip incy://add/ or incy://import/ and unwrap (url-decode, then scheme-or-base64) to the inner link
fn strip_incy_prefix(link: &str) -> Option<String> {
    let trimmed = link.trim();
    let tail = strip_prefix_ci(trimmed, INCY_ADD_PREFIX)
        .or_else(|| strip_prefix_ci(trimmed, INCY_IMPORT_PREFIX))?
        .trim();
    if tail.is_empty() {
        return None;
    }
    let decoded = percent_decode(tail);
    let decoded = if decoded.is_empty() { tail.to_string() } else { decoded };
    if decoded.is_empty() {
        return None;
    }
    if incy_looks_like_scheme_link(&decoded) {
        return Some(decoded);
    }
    let std = decoded.replace('-', "+").replace('_', "/");
    if let Some(d) = incy_decode_base64_or_null(&std) {
        return Some(d);
    }
    if let Some(d) = incy_decode_base64_or_null(&decoded) {
        return Some(d);
    }
    None
}

// Extract an incy://add/ or incy://import/ link wrapped in http(s) (up to 2 levels of url-decoding)
fn extract_embedded_incy_link(raw: &str) -> Option<String> {
    extract_embedded_incy_link_depth(raw, 0)
}

fn extract_embedded_incy_link_depth(raw: &str, depth: usize) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if starts_with_ci(trimmed, INCY_SCHEME) {
        return None;
    }
    if !starts_with_ci(trimmed, "http://") && !starts_with_ci(trimmed, "https://") {
        return None;
    }
    let start = match index_of_scheme(trimmed, "incy") {
        Some(i) => i,
        None => {
            if depth < INCY_EXTRACT_MAX_DEPTH && contains_ci(trimmed, "incy%") {
                let once = percent_decode(trimmed);
                if once != trimmed {
                    return extract_embedded_incy_link_depth(&once, depth + 1);
                }
            }
            return None;
        }
    };
    let candidate = carve_candidate(trimmed, start);
    let mut decoded = percent_decode(&candidate).trim().to_string();
    let mut guard = 0;
    while guard < INCY_EXTRACT_MAX_DEPTH && starts_with_ci(&decoded, "incy%") {
        let next = percent_decode(&decoded);
        let next_t = next.trim().to_string();
        if next_t == decoded {
            break;
        }
        decoded = next_t;
        guard += 1;
    }
    if !is_incy_link(&decoded) {
        return None;
    }
    if decoded == trimmed {
        return None;
    }
    Some(decoded)
}

/// Resolves a wrapper or an http(s)-embedded `happ`/`v2raytun`/`incy` link down to the real
/// link, or returns the input trimmed when there is nothing to unwrap.
///
/// # Examples
///
/// ```
/// let inner = hpwnr::unwrap_link("happ://add/https%3A%2F%2Fexample.com%2Fsub");
/// assert_eq!(inner, "https://example.com/sub");
/// ```
pub fn unwrap_link(s: &str) -> String {
    let mut cur = s.trim().to_string();
    // Resolve nested wrappers (bounded); each pass must change the string or the loop stops
    for _ in 0..6 {
        match unwrap_once(&cur) {
            Some(next) if next != cur => cur = next,
            _ => break,
        }
    }
    cur
}

// One unwrap pass: strip a happ/v2raytun/incy wrapper or pull a link out of an http(s) URL, else None
fn unwrap_once(s: &str) -> Option<String> {
    let t = s.trim();
    if let Some(inner) = unwrap_wrapper(t) {
        return Some(inner);
    }
    if let Some(inner) = strip_incy_prefix(t) {
        return Some(inner);
    }
    if starts_with_ci(t, "http://") || starts_with_ci(t, "https://") {
        if let Some(h) = extract_embedded(t, "happ") {
            return Some(h);
        }
        if let Some(v) = extract_embedded(t, "v2raytun") {
            return Some(v);
        }
        if let Some(i) = extract_embedded_incy_link(t) {
            return Some(i);
        }
    }
    None
}

/// Decrypts a `happ://` or `v2raytun://` link, returning `Ok(None)` when the input is not a
/// recognized encrypted link.
///
/// # Errors
///
/// Returns an [`Error`] when the link is recognized but its ciphertext cannot be decrypted.
pub fn decrypt_link(s: &str) -> Result<Option<String>> {
    if let Some(rest) = strip_prefix_ci(s, V2_PREFIX) {
        return v2_decrypt(rest).map(Some);
    }
    for &(prefix, ordinal) in &HAPP_PREFIXES {
        if let Some(rest) = strip_prefix_ci(s, prefix) {
            let plain = if ordinal == 4 {
                decrypt_crypt5(rest)?
            } else {
                decrypt_crypt(ordinal as usize, rest)?
            };
            return Ok(Some(plain));
        }
    }
    Ok(None)
}

/// Decrypts a recognized `happ://` or `v2raytun://` link to its plaintext URL.
///
/// # Errors
///
/// Returns [`Error::UnknownPrefix`] when the input is not a recognized link, or another
/// [`Error`] variant when decryption fails.
///
/// # Examples
///
/// ```
/// use hpwnr::{encrypt_happ, decrypt, HappMode};
///
/// let link = encrypt_happ(HappMode::Crypt3, "https://example.com/sub")?;
/// assert_eq!(decrypt(&link)?, "https://example.com/sub");
/// # Ok::<(), hpwnr::Error>(())
/// ```
pub fn decrypt(s: &str) -> Result<String> {
    decrypt_link(s)?.ok_or(Error::UnknownPrefix)
}

/// Unwraps any wrapper or embedded link with [`unwrap_link`] and then decrypts it, returning
/// `Ok(None)` when the result is not a recognized encrypted link.
///
/// # Errors
///
/// Returns an [`Error`] when a recognized link is found but cannot be decrypted.
pub fn resolve_and_decrypt(input: &str) -> Result<Option<String>> {
    decrypt_link(&unwrap_link(input))
}

/// Decrypts a V2RayTun payload, the part of a `v2raytun://crypt/` link after the prefix.
///
/// Several keys are tried in turn; since RSA PKCS#1 v1.5 has no authentication tag, a decryption is
/// accepted only when it looks like a `scheme://` link, which real V2RayTun subscriptions always are.
///
/// # Errors
///
/// Returns an [`Error`] when the payload cannot be decrypted.
pub fn decrypt_v2_payload(payload: &str) -> Result<String> {
    v2_decrypt(payload)
}

/// Encrypts `plaintext` into a `happ://cryptN/` link using the given [`HappMode`].
///
/// # Errors
///
/// Returns an [`Error`] when encryption fails, for example when the plaintext is too large for
/// the chosen RSA key.
///
/// # Examples
///
/// ```
/// use hpwnr::{encrypt_happ, HappMode};
///
/// let link = encrypt_happ(HappMode::Crypt5, "https://example.com/sub")?;
/// assert!(link.starts_with("happ://crypt5/"));
/// # Ok::<(), hpwnr::Error>(())
/// ```
pub fn encrypt_happ(mode: HappMode, plaintext: &str) -> Result<String> {
    if mode == HappMode::Crypt5 {
        encrypt_crypt5(plaintext, true)
    } else {
        encrypt_crypt(mode.ordinal(), plaintext)
    }
}

/// Encrypts `plaintext` into a `happ://crypt5/` link using the legacy layout, where the RSA
/// blob is the ChaCha key directly with no salt.
///
/// Prefer [`encrypt_happ`] with [`HappMode::Crypt5`] for the current salted layout; either
/// layout decrypts with [`decrypt`].
///
/// # Errors
///
/// Returns an [`Error`] when encryption fails.
pub fn encrypt_crypt5_legacy(plaintext: &str) -> Result<String> {
    encrypt_crypt5(plaintext, false)
}

/// Encrypts `plaintext` into a `v2raytun://crypt/` link using the chosen [`V2Key`].
///
/// # Errors
///
/// Returns [`Error::V2TooLong`] when the plaintext exceeds one RSA block, or
/// [`Error::V2NoCleanLink`] when a clean link cannot be produced within the retry budget.
pub fn encrypt_v2(key: V2Key, plaintext: &str) -> Result<String> {
    v2_encrypt(key.name(), plaintext)
}

/// Classifies a link without decrypting it, reporting its [`LinkKind`] and payload details.
///
/// # Examples
///
/// ```
/// use hpwnr::{encrypt_happ, inspect, HappMode, LinkKind};
///
/// let link = encrypt_happ(HappMode::Crypt5, "https://example.com/sub")?;
/// assert_eq!(inspect(&link).kind, LinkKind::Happ(HappMode::Crypt5));
/// assert_eq!(inspect("https://example.com").kind, LinkKind::Plain);
/// # Ok::<(), hpwnr::Error>(())
/// ```
pub fn inspect(s: &str) -> InputInfo {
    if let Some(rest) = strip_prefix_ci(s, V2_PREFIX) {
        return InputInfo { kind: LinkKind::V2RayTun, payload_len: rest.len(), crypt5_marker: None };
    }
    for &(prefix, ordinal) in &HAPP_PREFIXES {
        if let Some(rest) = strip_prefix_ci(s, prefix) {
            let mode = HappMode::from_ordinal(ordinal as usize).unwrap_or(HappMode::Crypt5);
            let marker = if ordinal == 4 { crypt5_marker_of(rest) } else { None };
            return InputInfo { kind: LinkKind::Happ(mode), payload_len: rest.len(), crypt5_marker: marker };
        }
    }
    InputInfo { kind: LinkKind::Plain, payload_len: s.len(), crypt5_marker: None }
}

/// Decrypts an AES-128-GCM subscription body when the URL carried `?key=keyNN` and the server
/// returned an `Encrypt-Tag`, otherwise returns the body unchanged.
///
/// Available with the `fetch` feature.
#[cfg(feature = "fetch")]
pub fn decrypt_response_body(url: &str, body: Vec<u8>, encrypt_tag: Option<&str>) -> Vec<u8> {
    let key_name = url_key_param(url);
    if key_name.is_empty() {
        return body;
    }
    let key = match aes_gcm_key(&key_name) {
        Some(k) => k,
        None => return body,
    };
    let tag = match encrypt_tag {
        Some(t) if !t.is_empty() => t,
        _ => return body,
    };
    match decrypt_aes_gcm(&String::from_utf8_lossy(&body), tag, key) {
        Ok(plain) => plain,
        Err(_) => body,
    }
}

/// Fetches a subscription over HTTP, sending `user_agent` and `hwid` as headers when they are
/// non-empty, and stripping any AES-128-GCM layer from the response.
///
/// Both `user_agent` and `hwid` are optional; pass empty strings to send neither header.
/// Available with the `fetch` feature.
///
/// # Errors
///
/// Returns [`Error::Http`] when the request fails.
#[cfg(feature = "fetch")]
pub fn fetch(url: &str, user_agent: &str, hwid: &str) -> Result<Vec<u8>> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(std::time::Duration::from_secs(15))
        .timeout_read(std::time::Duration::from_secs(30))
        .build();
    let mut req = agent.get(url);
    if !user_agent.is_empty() {
        req = req.set("User-Agent", &resolve_ua(user_agent));
    }
    if !hwid.is_empty() {
        req = req.set("X-HWID", hwid);
    }
    let resp = match req.call() {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(ureq::Error::Transport(t)) => return Err(Error::Http(t.to_string())),
    };
    let tag = resp.header("Encrypt-Tag").map(|s| s.to_string());
    let mut body = Vec::new();
    resp.into_reader().read_to_end(&mut body).map_err(|e| Error::Http(e.to_string()))?;
    Ok(decrypt_response_body(url, body, tag.as_deref()))
}
