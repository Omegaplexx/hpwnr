// Public Suffix List (ICANN section) used to find the registrable label of a host.
// Single-label suffixes like com or uk are covered by the default rule, so only multi-label rules are embedded.
// Each line is an exact suffix, a *.rule wildcard, or a !rule exception.

use std::collections::HashSet;

static PSL_DATA: &str = include_str!("psl.dat");

struct Rules {
    exact: HashSet<&'static str>,
    wildcard: HashSet<&'static str>,
    exception: HashSet<&'static str>,
}

fn rules() -> Rules {
    let mut exact = HashSet::new();
    let mut wildcard = HashSet::new();
    let mut exception = HashSet::new();
    for line in PSL_DATA.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('!') {
            exception.insert(rest);
        } else if let Some(rest) = line.strip_prefix("*.") {
            wildcard.insert(rest);
        } else {
            exact.insert(line);
        }
    }
    Rules { exact, wildcard, exception }
}

// Number of trailing labels that form the public suffix, per the PSL matching algorithm.
fn public_suffix_len(labels: &[&str], r: &Rules) -> usize {
    let n = labels.len();
    // An exception rule wins outright: the suffix is that rule without its leftmost label.
    for i in 0..n {
        let cand = labels[i..].join(".");
        if r.exception.contains(cand.as_str()) {
            return (n - i).saturating_sub(1);
        }
    }
    // Otherwise the longest matching exact or wildcard rule prevails; the default is one label.
    let mut best = 1;
    for i in 0..n {
        let len = n - i;
        let cand = labels[i..].join(".");
        if r.exact.contains(cand.as_str()) && len > best {
            best = len;
        }
        if len >= 2 {
            let rest = labels[i + 1..].join(".");
            if r.wildcard.contains(rest.as_str()) && len > best {
                best = len;
            }
        }
    }
    best
}

// The label directly left of the public suffix: sub.shadowmere.co.uk gives "shadowmere".
pub fn registrable_label(host: &str) -> String {
    // Host names are case-insensitive, but the PSL rules are lowercase, so normalize first.
    let host = host.to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').filter(|s| !s.is_empty()).collect();
    let n = labels.len();
    if n == 0 {
        return "sub".to_string();
    }
    if labels.iter().all(|p| p.bytes().all(|b| b.is_ascii_digit())) {
        // an IPv4 address has no registrable label, so keep the digits joined
        return labels.join("_");
    }
    let r = rules();
    let suffix_len = public_suffix_len(&labels, &r);
    if n > suffix_len {
        labels[n - suffix_len - 1].to_string()
    } else {
        labels[0].to_string()
    }
}
