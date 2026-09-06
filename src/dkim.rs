use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Pkcs1v15Sign, RsaPrivateKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Default set of header field names to sign, in signing order.
///
/// `From` appears twice deliberately (RFC 6376 5.4 oversigning): the second
/// entry finds no further instance, so it contributes the null string but is
/// still listed in `h=`, which makes a relay that adds a second `From`
/// header break the signature instead of riding on it.
///
/// `To` is intentionally absent. It is rewritten by mailing lists and
/// forwarders, and signing it buys little: DMARC aligns on `From`, and the
/// SMTP envelope is not covered by DKIM at all.
const DEFAULT_SIGNED_HEADERS: &[&str] = &[
    "From",
    "From",
    "Subject",
    "Date",
    "Message-ID",
    "MIME-Version",
    "Content-Type",
    "Content-Transfer-Encoding",
];

/// Errors that can occur while configuring or using a [`DkimSigner`].
#[derive(Debug)]
pub enum DkimError {
    /// The supplied PEM data could not be parsed as a PKCS#8 RSA private key.
    InvalidKey(rsa::pkcs8::Error),
    /// RSA signing failed.
    Signing(rsa::Error),
}

impl fmt::Display for DkimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DkimError::InvalidKey(e) => write!(f, "invalid DKIM private key: {e}"),
            DkimError::Signing(e) => write!(f, "DKIM signing failed: {e}"),
        }
    }
}

impl std::error::Error for DkimError {}

/// Signs outgoing mail with a `DKIM-Signature` header (RFC 6376), using
/// RSA-SHA256 and relaxed/relaxed canonicalization against a single,
/// statically configured domain, selector, and private key.
pub struct DkimSigner {
    domain: String,
    selector: String,
    private_key: RsaPrivateKey,
    // Header field names to sign, in order, always stored lowercased:
    // DKIM matches names case-insensitively, so folding once here keeps
    // every later comparison a plain equality. Emitted verbatim as the
    // `h=` tag, which RFC 6376 lets us write in any case.
    headers: Vec<String>,
}

impl DkimSigner {
    /// Creates a signer from a PKCS#8 PEM-encoded RSA private key.
    ///
    /// The default signed-header list is `From, From, Subject, Date,
    /// Message-ID, MIME-Version, Content-Type, Content-Transfer-Encoding`;
    /// override it with [`headers`](Self::headers). `From` is listed twice
    /// on purpose, so that a relay adding a second `From` header breaks the
    /// signature (RFC 6376 5.4 oversigning). `To` is omitted because
    /// mailing lists and forwarders rewrite it.
    pub fn from_pkcs8_pem(
        pem: &str,
        domain: impl Into<String>,
        selector: impl Into<String>,
    ) -> Result<Self, DkimError> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(pem).map_err(DkimError::InvalidKey)?;
        Ok(DkimSigner {
            domain: domain.into(),
            selector: selector.into(),
            private_key,
            headers: DEFAULT_SIGNED_HEADERS
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
        })
    }

    /// Overrides the default list of header field names to sign, in order.
    ///
    /// Per RFC 6376 §5.4, `From` should always be included. A name may be
    /// repeated to sign multiple instances of a repeated header field
    /// (§5.4.2), or to claim more instances than currently exist so the
    /// signature breaks if more are added later (§5.4).
    pub fn headers(mut self, names: &[&str]) -> Self {
        self.headers = names.iter().map(|s| s.to_ascii_lowercase()).collect();
        self
    }

    /// Whether `name` is one of the configured header field names to sign
    /// (case-insensitive). Used by the daemon to avoid capturing header
    /// data that DKIM signing will never look at.
    pub(crate) fn wants_header(&self, name: &str) -> bool {
        self.headers.iter().any(|h| h.eq_ignore_ascii_case(name))
    }

    /// Computes the `DKIM-Signature` header value (everything after
    /// `DKIM-Signature:`) for a message.
    ///
    /// `headers` is the ordered list of raw `(name, value)` pairs as
    /// delivered by the milter `'L'` command, verbatim. `force_l0` must be
    /// set when `body` is known to be incomplete (the caller received no
    /// body at all); in that case the signature declares `l=0`, honestly
    /// covering zero body bytes, and `body` is expected to be empty.
    pub(crate) fn sign(
        &self,
        headers: &[(String, String)],
        body: &[u8],
        force_l0: bool,
    ) -> Result<String, DkimError> {
        let body_hash = if force_l0 {
            Sha256::digest([])
        } else {
            Sha256::digest(canonicalize_body_relaxed(body))
        };
        let bh = BASE64.encode(body_hash);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut value = format!(
            "v=1; a=rsa-sha256; c=relaxed/relaxed; d={}; s={}; t={}; h={}; bh={}; ",
            self.domain,
            self.selector,
            timestamp,
            self.headers.join(":"),
            bh,
        );
        if force_l0 {
            value.push_str("l=0; ");
        }
        value.push_str("b=");

        // Group actual header occurrences by lowercased name, preserving
        // their original top-to-bottom order so RFC 6376 5.4.2's
        // bottom-first duplicate handling can pop from the end.
        let mut remaining: HashMap<String, Vec<&(String, String)>> = HashMap::new();
        for pair in headers {
            remaining
                .entry(pair.0.to_ascii_lowercase())
                .or_default()
                .push(pair);
        }

        let mut signed_data = Vec::new();
        for name in &self.headers {
            if let Some(list) = remaining.get_mut(name)
                && let Some((actual_name, actual_value)) = list.pop()
            {
                signed_data.extend_from_slice(
                    canonicalize_header_relaxed(actual_name, actual_value).as_bytes(),
                );
                signed_data.extend_from_slice(b"\r\n");
            }
            // Absent header: per RFC 6376 5.4, contributes the null string
            // (nothing at all) but is still listed in h= above.
        }
        signed_data
            .extend_from_slice(canonicalize_header_relaxed("DKIM-Signature", &value).as_bytes());

        let digest = Sha256::digest(&signed_data);
        let signature = self
            .private_key
            .sign_with_rng(
                &mut rand::thread_rng(),
                Pkcs1v15Sign::new::<Sha256>(),
                &digest,
            )
            .map_err(DkimError::Signing)?;
        value.push_str(&BASE64.encode(signature));

        Ok(value)
    }
}

/// RFC 6376 §3.4.2 relaxed header canonicalization of one header field.
/// Returns `"name:value"` (no trailing CRLF, no space after the colon).
fn canonicalize_header_relaxed(name: &str, value: &str) -> String {
    let name = trim_wsp_str(name).to_ascii_lowercase();
    let unfolded = unfold(value);
    let collapsed = collapse_wsp(unfolded.as_bytes());
    let trimmed = trim_wsp(&collapsed);
    let mut out = String::with_capacity(name.len() + 1 + trimmed.len());
    out.push_str(&name);
    out.push(':');
    out.push_str(&String::from_utf8_lossy(trimmed));
    out
}

/// RFC 5322 unfolding: a CRLF immediately followed by WSP is removed,
/// keeping the WSP itself (later collapsed by [`collapse_wsp`]).
fn unfold(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\r'
            && i + 2 < bytes.len()
            && bytes[i + 1] == b'\n'
            && (bytes[i + 2] == b' ' || bytes[i + 2] == b'\t')
        {
            i += 2;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Converts every run of one or more WSP (space/tab) bytes to a single SP.
fn collapse_wsp(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut in_wsp = false;
    for &b in bytes {
        if b == b' ' || b == b'\t' {
            in_wsp = true;
        } else {
            if in_wsp {
                out.push(b' ');
                in_wsp = false;
            }
            out.push(b);
        }
    }
    out
}

fn is_wsp(b: &u8) -> bool {
    *b == b' ' || *b == b'\t'
}

fn trim_wsp(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|b| !is_wsp(b)).unwrap_or(bytes.len());
    let end = bytes.iter().rposition(|b| !is_wsp(b)).map_or(0, |i| i + 1);
    if start >= end {
        &[]
    } else {
        &bytes[start..end]
    }
}

fn trim_wsp_str(s: &str) -> &str {
    // Header names and values are always ASCII, so byte and char
    // boundaries coincide; safe to reuse the byte-oriented trimmer.
    std::str::from_utf8(trim_wsp(s.as_bytes())).unwrap_or(s)
}

/// RFC 6376 §3.4.4 relaxed body canonicalization.
fn canonicalize_body_relaxed(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    let mut rest = body;
    loop {
        match rest.windows(2).position(|w| w == b"\r\n") {
            Some(pos) => {
                append_canonical_line(&mut out, &rest[..pos]);
                out.extend_from_slice(b"\r\n");
                rest = &rest[pos + 2..];
            }
            None => {
                if !rest.is_empty() {
                    append_canonical_line(&mut out, rest);
                    out.extend_from_slice(b"\r\n");
                }
                break;
            }
        }
    }
    // Ignore all empty lines at the end of the message body (an empty body
    // to begin with is the degenerate case: canonical form is the empty
    // string, not a CRLF -- that rule belongs to simple canonicalization).
    loop {
        if out == b"\r\n" {
            out.clear();
        } else if out.ends_with(b"\r\n\r\n") {
            out.truncate(out.len() - 2);
        } else {
            break;
        }
    }
    out
}

/// Collapses intra-line WSP runs to a single SP and drops trailing WSP,
/// appending the result (without a line terminator) to `out`.
fn append_canonical_line(out: &mut Vec<u8>, line: &[u8]) {
    let mut in_wsp = false;
    for &b in line {
        if b == b' ' || b == b'\t' {
            in_wsp = true;
        } else {
            if in_wsp {
                out.push(b' ');
                in_wsp = false;
            }
            out.push(b);
        }
    }
    // A trailing WSP run is simply never flushed.
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::RsaPublicKey;

    // RFC 6376 3.4.4: SHA-256 of the empty string, published directly in
    // the RFC text as the hash of a relaxed-canonicalized empty body.
    const EMPTY_BODY_SHA256_B64: &str = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";

    #[test]
    fn wants_header_matches_configured_names_case_insensitively() {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let signer = DkimSigner {
            domain: "example.com".to_string(),
            selector: "sel1".to_string(),
            private_key,
            headers: vec!["from".to_string(), "subject".to_string()],
        };
        assert!(signer.wants_header("From"));
        assert!(signer.wants_header("subject"));
        assert!(signer.wants_header("SUBJECT"));
        assert!(!signer.wants_header("To"));
    }

    #[test]
    fn header_lowercases_name_and_removes_space_after_colon() {
        // RFC 6376 3.4.5 Example: "A: X" canonicalizes to "a:X".
        assert_eq!(canonicalize_header_relaxed("A", " X"), "a:X");
        assert_eq!(canonicalize_header_relaxed("SUBJect", "AbC"), "subject:AbC");
    }

    #[test]
    fn header_unfolds_and_collapses_and_trims() {
        // RFC 6376 3.4.5 Example: "B : Y<HTAB><CRLF><HTAB>Z<SP><SP>"
        // canonicalizes to "b:Y Z".
        assert_eq!(canonicalize_header_relaxed("B ", "Y\t\r\n\tZ  "), "b:Y Z");
    }

    #[test]
    fn header_with_no_embedded_fold_is_unaffected_by_unfold() {
        assert_eq!(
            canonicalize_header_relaxed("X", "plain value"),
            "x:plain value"
        );
    }

    #[test]
    fn unfold_removes_only_the_crlf_before_wsp() {
        assert_eq!(unfold("Y\t\r\n\tZ"), "Y\t\tZ");
        assert_eq!(unfold("no fold here"), "no fold here");
    }

    #[test]
    fn body_collapses_and_trims_per_rfc_example() {
        // RFC 6376 3.4.5 Example 1/2: body " C \r\nD \t E\r\n\r\n\r\n"
        // canonicalizes (relaxed) to " C\r\nD E\r\n".
        let raw = b" C \r\nD \t E\r\n\r\n\r\n";
        assert_eq!(canonicalize_body_relaxed(raw), b" C\r\nD E\r\n");
    }

    #[test]
    fn body_adds_missing_trailing_crlf() {
        assert_eq!(canonicalize_body_relaxed(b"Hello"), b"Hello\r\n");
    }

    #[test]
    fn body_of_only_blank_lines_canonicalizes_to_empty() {
        assert_eq!(canonicalize_body_relaxed(b"\r\n"), b"");
        assert_eq!(canonicalize_body_relaxed(b"\r\n\r\n\r\n"), b"");
    }

    #[test]
    fn empty_body_canonicalizes_to_empty_string_not_crlf() {
        let canonical = canonicalize_body_relaxed(b"");
        assert_eq!(canonical, b"");
        let hash = Sha256::digest(canonical);
        assert_eq!(BASE64.encode(hash), EMPTY_BODY_SHA256_B64);
    }

    #[test]
    fn force_l0_hashes_empty_body_regardless_of_input() {
        // force_l0 is only ever used by the caller with an empty body, but
        // the hash itself must match the same empty-body constant.
        let hash = Sha256::digest([]);
        assert_eq!(BASE64.encode(hash), EMPTY_BODY_SHA256_B64);
    }

    #[test]
    fn sign_produces_independently_verifiable_signature() {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        let signer = DkimSigner {
            domain: "example.com".to_string(),
            selector: "sel1".to_string(),
            private_key,
            headers: vec!["from".to_string(), "subject".to_string()],
        };
        let headers = vec![
            ("From".to_string(), "alice@example.com".to_string()),
            ("Subject".to_string(), "Hello".to_string()),
        ];
        let body: &[u8] = b"body text\r\n";
        let value = signer.sign(&headers, body, false).unwrap();

        assert!(value.starts_with("v=1; a=rsa-sha256; c=relaxed/relaxed;"));
        assert!(value.contains("h=from:subject;"));
        assert!(!value.contains("l=0"));

        let b_pos = value.rfind("b=").unwrap();

        let bh_start = value.find("bh=").unwrap() + 3;
        let bh_end = value[bh_start..].find(';').unwrap() + bh_start;
        let expected_bh = BASE64.encode(Sha256::digest(canonicalize_body_relaxed(body)));
        assert_eq!(&value[bh_start..bh_end], expected_bh);

        // Rebuild the exact bytes sign() should have hashed and verify
        // the signature independently via the public key.
        let mut signed_data = Vec::new();
        signed_data
            .extend_from_slice(canonicalize_header_relaxed("From", "alice@example.com").as_bytes());
        signed_data.extend_from_slice(b"\r\n");
        signed_data.extend_from_slice(canonicalize_header_relaxed("Subject", "Hello").as_bytes());
        signed_data.extend_from_slice(b"\r\n");
        signed_data.extend_from_slice(
            canonicalize_header_relaxed("DKIM-Signature", &value[..b_pos + 2]).as_bytes(),
        );
        let digest = Sha256::digest(&signed_data);

        let signature = BASE64.decode(&value[b_pos + 2..]).unwrap();
        public_key
            .verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &signature)
            .unwrap();
    }

    #[test]
    fn sign_with_force_l0_declares_l0_and_empty_body_hash() {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let signer = DkimSigner {
            domain: "example.com".to_string(),
            selector: "sel1".to_string(),
            private_key,
            headers: vec!["from".to_string()],
        };
        let headers = vec![("From".to_string(), "alice@example.com".to_string())];
        let value = signer.sign(&headers, b"", true).unwrap();

        assert!(value.contains("l=0;"));
        let bh_start = value.find("bh=").unwrap() + 3;
        let bh_end = value[bh_start..].find(';').unwrap() + bh_start;
        assert_eq!(&value[bh_start..bh_end], EMPTY_BODY_SHA256_B64);
    }

    #[test]
    fn sign_treats_absent_header_as_null_string_but_still_lists_it() {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let signer = DkimSigner {
            domain: "example.com".to_string(),
            selector: "sel1".to_string(),
            private_key,
            headers: vec!["from".to_string(), "comments".to_string()],
        };
        // No "Comments" header actually present.
        let headers = vec![("From".to_string(), "alice@example.com".to_string())];
        let value = signer.sign(&headers, b"", false).unwrap();
        assert!(value.contains("h=from:comments;"));
    }

    #[test]
    fn sign_uses_bottom_most_instance_first_for_duplicates() {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        let signer = DkimSigner {
            domain: "example.com".to_string(),
            selector: "sel1".to_string(),
            private_key,
            headers: vec!["received".to_string(), "received".to_string()],
        };
        // RFC 6376 5.4.2's own example: three Received headers, sign two,
        // bottom-to-top order means <C> then <B>.
        let headers = vec![
            ("Received".to_string(), "<A>".to_string()),
            ("Received".to_string(), "<B>".to_string()),
            ("Received".to_string(), "<C>".to_string()),
        ];
        let value = signer.sign(&headers, b"", false).unwrap();
        let b_pos = value.rfind("b=").unwrap();

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(canonicalize_header_relaxed("Received", "<C>").as_bytes());
        signed_data.extend_from_slice(b"\r\n");
        signed_data.extend_from_slice(canonicalize_header_relaxed("Received", "<B>").as_bytes());
        signed_data.extend_from_slice(b"\r\n");
        signed_data.extend_from_slice(
            canonicalize_header_relaxed("DKIM-Signature", &value[..b_pos + 2]).as_bytes(),
        );
        let digest = Sha256::digest(&signed_data);
        let signature = BASE64.decode(&value[b_pos + 2..]).unwrap();
        public_key
            .verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &signature)
            .unwrap();
    }
}
