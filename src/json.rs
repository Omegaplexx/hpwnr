#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    // Raw object lookup (containsKey semantics: present even if the value is null).
    pub(crate) fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    // org.json has(key): the key is mapped (a null value still counts as present).
    pub(crate) fn has(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    // Present and non-null: opt and get treat an explicit null the same as a missing key.
    fn field(&self, key: &str) -> Option<&Json> {
        match self.get(key) {
            Some(Json::Null) | None => None,
            other => other,
        }
    }

    // Coerce a scalar to a string the way org.json optString does (numbers and bools included).
    fn as_str_coerced(&self) -> Option<String> {
        match self {
            Json::Str(s) => Some(s.clone()),
            Json::Num(n) => Some(fmt_num(*n)),
            Json::Bool(b) => Some((if *b { "true" } else { "false" }).to_string()),
            _ => None,
        }
    }

    // optString(key, default): coerced value, or default if absent/null/non-scalar.
    pub(crate) fn opt_str(&self, key: &str, default: &str) -> String {
        self.field(key)
            .and_then(|v| v.as_str_coerced())
            .unwrap_or_else(|| default.to_string())
    }

    // optInt(key, default): Number or numeric String coerced to an integer, else default.
    pub(crate) fn opt_int(&self, key: &str, default: i64) -> i64 {
        match self.field(key) {
            Some(Json::Num(n)) => *n as i64,
            Some(Json::Str(s)) => parse_int_lenient(s).unwrap_or(default),
            _ => default,
        }
    }

    // getInt(key): like optInt but reports failure (org.json would throw) as None.
    pub(crate) fn get_int(&self, key: &str) -> Option<i64> {
        match self.field(key) {
            Some(Json::Num(n)) => Some(*n as i64),
            Some(Json::Str(s)) => parse_int_lenient(s),
            _ => None,
        }
    }

    // getString(key): coerce any present scalar to its string form; None for missing/null/non-scalar
    pub(crate) fn get_str(&self, key: &str) -> Option<String> {
        self.field(key).and_then(|v| v.as_str_coerced())
    }

    // optJSONObject(key): the value if it is an object, else None.
    pub(crate) fn opt_obj(&self, key: &str) -> Option<&Json> {
        match self.field(key) {
            Some(v @ Json::Obj(_)) => Some(v),
            _ => None,
        }
    }

    // optJSONArray(key): the value if it is an array, else None.
    pub(crate) fn opt_arr(&self, key: &str) -> Option<&Json> {
        match self.field(key) {
            Some(v @ Json::Arr(_)) => Some(v),
            _ => None,
        }
    }

    // optBoolean(key, default): true/false, also coercing "true"/"false" strings.
    pub(crate) fn opt_bool(&self, key: &str, default: bool) -> bool {
        match self.field(key) {
            Some(Json::Bool(b)) => *b,
            Some(Json::Str(s)) if s.eq_ignore_ascii_case("true") => true,
            Some(Json::Str(s)) if s.eq_ignore_ascii_case("false") => false,
            _ => default,
        }
    }

    // Elements of an array value (empty slice for any non-array).
    pub(crate) fn arr_items(&self) -> &[Json] {
        match self {
            Json::Arr(a) => a,
            _ => &[],
        }
    }

    pub(crate) fn is_obj(&self) -> bool {
        matches!(self, Json::Obj(_))
    }

    // ---- constructors (mirroring new JSONObject() / new JSONArray() and scalar boxing) ----
    pub(crate) fn obj() -> Json {
        Json::Obj(Vec::new())
    }
    pub(crate) fn arr() -> Json {
        Json::Arr(Vec::new())
    }
    pub(crate) fn str<S: Into<String>>(s: S) -> Json {
        Json::Str(s.into())
    }
    pub(crate) fn int(n: i64) -> Json {
        Json::Num(n as f64)
    }
    pub(crate) fn bool(b: bool) -> Json {
        Json::Bool(b)
    }

    // ---- object mutation (org.json JSONObject.put/remove semantics) ----
    // put(key, value): replace in place if the key exists (insertion order preserved), else append.
    pub(crate) fn set<S: Into<String>>(&mut self, key: S, val: Json) {
        if let Json::Obj(m) = self {
            let key = key.into();
            if let Some(slot) = m.iter_mut().find(|(k, _)| *k == key) {
                slot.1 = val;
            } else {
                m.push((key, val));
            }
        }
    }
    // remove(key): drop the entry if present.
    pub(crate) fn remove(&mut self, key: &str) {
        if let Json::Obj(m) = self {
            m.retain(|(k, _)| k != key);
        }
    }

    // ---- read helpers ----
    // opt(name): raw value if the key is present (even an explicit null), else None.
    pub(crate) fn opt(&self, key: &str) -> Option<&Json> {
        self.get(key)
    }
    // isNull(name): true if the key is missing or maps to an explicit null.
    pub(crate) fn is_null(&self, key: &str) -> bool {
        self.field(key).is_none()
    }
    // Keys in insertion order, for iterating an object (safe to hold across mutation).
    pub(crate) fn keys(&self) -> Vec<String> {
        match self {
            Json::Obj(m) => m.iter().map(|(k, _)| k.clone()).collect(),
            _ => Vec::new(),
        }
    }
    // length(): elements for arrays, keys for objects, else 0.
    pub(crate) fn len(&self) -> usize {
        match self {
            Json::Arr(a) => a.len(),
            Json::Obj(m) => m.len(),
            _ => 0,
        }
    }
    // Array element at index (present incl null), or None if out of range / not an array.
    pub(crate) fn arr_opt(&self, i: usize) -> Option<&Json> {
        match self {
            Json::Arr(a) => a.get(i),
            _ => None,
        }
    }
    // optJSONObject(i): array element at index if it is an object.
    pub(crate) fn arr_obj(&self, i: usize) -> Option<&Json> {
        match self.arr_opt(i) {
            Some(v @ Json::Obj(_)) => Some(v),
            _ => None,
        }
    }
    // optString(i): coerced string of the array element at index, or "" (null/container/missing).
    pub(crate) fn arr_opt_str(&self, i: usize) -> String {
        match self.arr_opt(i) {
            Some(Json::Str(s)) => s.clone(),
            Some(Json::Num(n)) => fmt_num(*n),
            Some(Json::Bool(b)) => (if *b { "true" } else { "false" }).to_string(),
            _ => String::new(),
        }
    }

    // Any?.toString(): String.valueOf on the value (numbers/bools coerced, containers to JSON text).
    pub(crate) fn to_string_value(&self) -> String {
        match self {
            Json::Null => "null".to_string(),
            Json::Bool(b) => (if *b { "true" } else { "false" }).to_string(),
            Json::Num(n) => fmt_num(*n),
            Json::Str(s) => s.clone(),
            Json::Arr(_) | Json::Obj(_) => stringify_compact(self),
        }
    }

    // ---- serialization ----
    // toString(): compact form (no spaces), matching org.json with indent=null.
    pub(crate) fn to_compact(&self) -> String {
        stringify_compact(self)
    }
    // toString(indent): indented form matching org.json JSONStringer.
    pub(crate) fn to_pretty(&self, indent: usize) -> String {
        let mut out = String::new();
        write_json_pretty(&mut out, self, indent, 0);
        out
    }
}

// Integer from a string: try i64, else a float truncated (accepts "443" and "443.0")
fn parse_int_lenient(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Ok(v) = s.parse::<i64>() {
        return Some(v);
    }
    s.parse::<f64>().ok().map(|f| f as i64)
}

// Whole numbers print without a fractional part (matching org.json's Integer vs Double output).
pub(crate) fn fmt_num(n: f64) -> String {
    if n.is_finite() && n.fract() == 0.0 && n.abs() < 9.007e15 {
        (n as i64).to_string()
    } else {
        n.to_string()
    }
}

// Max object/array nesting the parser descends into. Real configs nest a few levels; this cap keeps
// pathologically nested input from overflowing the stack (deeper input parses as None, like other bad input).
const MAX_DEPTH: usize = 256;

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn new(s: &'a str) -> Self {
        Parser { b: s.as_bytes(), i: 0 }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn ws(&mut self) {
        while let Some(c) = self.peek() {
            if c == b' ' || c == b'\t' || c == b'\n' || c == b'\r' {
                self.i += 1;
            } else {
                break;
            }
        }
    }

    fn value(&mut self, depth: usize) -> Option<Json> {
        // Bound recursion so pathologically nested input can't overflow the stack.
        if depth > MAX_DEPTH {
            return None;
        }
        self.ws();
        match self.peek()? {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => self.string().map(Json::Str),
            b't' => self.lit(b"true", Json::Bool(true)),
            b'f' => self.lit(b"false", Json::Bool(false)),
            b'n' => self.lit(b"null", Json::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => None,
        }
    }

    fn lit(&mut self, kw: &[u8], v: Json) -> Option<Json> {
        if self.b[self.i..].starts_with(kw) {
            self.i += kw.len();
            Some(v)
        } else {
            None
        }
    }

    fn object(&mut self, depth: usize) -> Option<Json> {
        self.i += 1; // consume '{'
        let mut m: Vec<(String, Json)> = Vec::new();
        self.ws();
        if self.peek()? == b'}' {
            self.i += 1;
            return Some(Json::Obj(m));
        }
        loop {
            self.ws();
            if self.peek()? != b'"' {
                return None;
            }
            let key = self.string()?;
            self.ws();
            if self.peek()? != b':' {
                return None;
            }
            self.i += 1;
            let val = self.value(depth + 1)?;
            m.push((key, val));
            self.ws();
            match self.peek()? {
                b',' => self.i += 1,
                b'}' => {
                    self.i += 1;
                    return Some(Json::Obj(m));
                }
                _ => return None,
            }
        }
    }

    fn array(&mut self, depth: usize) -> Option<Json> {
        self.i += 1; // consume '['
        let mut a: Vec<Json> = Vec::new();
        self.ws();
        if self.peek()? == b']' {
            self.i += 1;
            return Some(Json::Arr(a));
        }
        loop {
            let v = self.value(depth + 1)?;
            a.push(v);
            self.ws();
            match self.peek()? {
                b',' => self.i += 1,
                b']' => {
                    self.i += 1;
                    return Some(Json::Arr(a));
                }
                _ => return None,
            }
        }
    }

    // Parse a string from the opening quote; decoded as UTF-8 at the end, escapes and \uXXXX pairs expanded
    fn string(&mut self) -> Option<String> {
        self.i += 1; // consume opening quote
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let c = *self.b.get(self.i)?;
            self.i += 1;
            match c {
                b'"' => return String::from_utf8(buf).ok(),
                b'\\' => {
                    let e = *self.b.get(self.i)?;
                    self.i += 1;
                    match e {
                        b'"' => buf.push(b'"'),
                        b'\\' => buf.push(b'\\'),
                        b'/' => buf.push(b'/'),
                        b'b' => buf.push(0x08),
                        b'f' => buf.push(0x0C),
                        b'n' => buf.push(b'\n'),
                        b'r' => buf.push(b'\r'),
                        b't' => buf.push(b'\t'),
                        b'u' => {
                            let cp = self.hex4()?;
                            let ch = if (0xD800..=0xDBFF).contains(&cp) {
                                if self.b.get(self.i) == Some(&b'\\')
                                    && self.b.get(self.i + 1) == Some(&b'u')
                                {
                                    self.i += 2;
                                    let lo = self.hex4()?;
                                    if !(0xDC00..=0xDFFF).contains(&lo) {
                                        return None;
                                    }
                                    let c = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                    char::from_u32(c)?
                                } else {
                                    return None;
                                }
                            } else if (0xDC00..=0xDFFF).contains(&cp) {
                                return None;
                            } else {
                                char::from_u32(cp)?
                            };
                            let mut tmp = [0u8; 4];
                            buf.extend_from_slice(ch.encode_utf8(&mut tmp).as_bytes());
                        }
                        _ => return None,
                    }
                }
                _ => buf.push(c),
            }
        }
    }

    fn hex4(&mut self) -> Option<u32> {
        let mut v: u32 = 0;
        for _ in 0..4 {
            let c = *self.b.get(self.i)?;
            self.i += 1;
            let d = match c {
                b'0'..=b'9' => (c - b'0') as u32,
                b'a'..=b'f' => (c - b'a' + 10) as u32,
                b'A'..=b'F' => (c - b'A' + 10) as u32,
                _ => return None,
            };
            v = v * 16 + d;
        }
        Some(v)
    }

    fn number(&mut self) -> Option<Json> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.i += 1;
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
            }
        }
        let slice = self.b.get(start..self.i)?;
        let s = std::str::from_utf8(slice).ok()?;
        s.parse::<f64>().ok().map(Json::Num)
    }
}

// Parse the entire input as one JSON value, allowing only trailing whitespace
pub(crate) fn parse_whole(s: &str) -> Option<Json> {
    let mut p = Parser::new(s);
    let v = p.value(0)?;
    p.ws();
    if p.i == p.b.len() { Some(v) } else { None }
}

// Compact serialization, used only for array elements passed through unchanged
pub(crate) fn stringify_compact(v: &Json) -> String {
    let mut out = String::new();
    write_json(&mut out, v);
    out
}

fn write_json(out: &mut String, v: &Json) {
    match v {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Num(n) => out.push_str(&fmt_num(*n)),
        Json::Str(s) => write_json_string(out, s),
        Json::Arr(a) => {
            out.push('[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(out, e);
            }
            out.push(']');
        }
        Json::Obj(m) => {
            out.push('{');
            for (i, (k, val)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json_string(out, k);
                out.push(':');
                write_json(out, val);
            }
            out.push('}');
        }
    }
}

// JSON string escaping. Forward slash is left unescaped, matching Android's JSONObject.toString.
fn write_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

// Append `indent * depth` spaces (one indentation step per nesting level).
fn push_indent(out: &mut String, indent: usize, depth: usize) {
    for _ in 0..(indent * depth) {
        out.push(' ');
    }
}

// Indented serialization matching Android's JSONStringer (one member/element per line, empty {} / [] inline)
fn write_json_pretty(out: &mut String, v: &Json, indent: usize, depth: usize) {
    match v {
        Json::Obj(m) => {
            if m.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (i, (k, val)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('\n');
                push_indent(out, indent, depth + 1);
                write_json_string(out, k);
                out.push_str(": ");
                write_json_pretty(out, val, indent, depth + 1);
            }
            out.push('\n');
            push_indent(out, indent, depth);
            out.push('}');
        }
        Json::Arr(a) => {
            if a.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('\n');
                push_indent(out, indent, depth + 1);
                write_json_pretty(out, e, indent, depth + 1);
            }
            out.push('\n');
            push_indent(out, indent, depth);
            out.push(']');
        }
        // Scalars serialize identically to the compact form.
        _ => write_json(out, v),
    }
}
