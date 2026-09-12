# Setting up DKIM signing

This document describes how to create a DKIM key pair, publish the public
key in DNS, and point srmilter at the private key. It covers the
operational setup only. For the API used to configure a `DkimSigner`, see
the DKIM Signing section of README.md.

srmilter signs with RSA-SHA256 and relaxed/relaxed canonicalization
against a single statically configured domain, selector, and private key.

## 1. Generate the private key

Use `openssl genpkey`, which always writes PKCS#8:

```bash
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out dkim.private.pem
```

Do not use `openssl genrsa`. On OpenSSL 3.x it usually writes PKCS#8 as
well, but with `-traditional`, or on older OpenSSL releases, it writes
PKCS#1 instead. `DkimSigner::from_pkcs8_pem` rejects PKCS#1 with:

```
invalid DKIM private key: PKCS#8 ASN.1 error: PEM error:
unexpected PEM type label: expecting "PRIVATE KEY"
```

Check the first line of the generated file. It must read

```
-----BEGIN PRIVATE KEY-----
```

and not `-----BEGIN RSA PRIVATE KEY-----`, which is the PKCS#1 form.

Use 2048 bits. 1024 bit keys are weak and are rejected by a growing
number of verifiers, while 4096 bit keys produce a DNS record large
enough that some verifiers and hosted DNS panels handle it poorly.

Install the key so that only the account the milter runs as can read it:

```bash
install -o milter -g milter -m 400 dkim.private.pem \
    /etc/srmilter/dkim.private.pem
```

The `umask 077` above protects the file during generation, before it is
installed with its final ownership.

## 2. Extract the public key

The `p=` tag of the DNS record is the base64 encoding of the DER
SubjectPublicKeyInfo:

```bash
openssl pkey -in dkim.private.pem -pubout -outform DER | base64 -w0
```

This is the same string as the body of the PEM public key with the header
and footer lines removed and the line breaks stripped, so the following is
equivalent:

```bash
openssl pkey -in dkim.private.pem -pubout -out dkim.public.pem
grep -v '^-----' dkim.public.pem | tr -d '\n'
```

## 3. Publish the DNS record

The owner name is always `<selector>._domainkey.<domain>` and the type is
TXT. With selector `sel2026` and domain `example.com`:

```dns
sel2026._domainkey.example.com. 3600 IN TXT ( "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo7IgIQdaIKrmPSUqJSnM05Nu2/C7lneRry7mvqxYT9GzPZWRRw/JyoCe7fCjJBpSCLVrXiG4dz1+2LV3JQfK5BNnj/BLPdOZpNol296J095C2CgYk5T3FXCQ5NsckXi3Rju4gIYvOLkUOfXH7NcJ/8pl9R3L"
    "Te+nFfxY3aqHb32vdaKazUftKTikDL4eLs7R+L6qulsp8EkdK4PqP0aWr2yx7d7STd9ZhttGrPt0Si+Pzkt2henYgwzhE69QJzUpyRHUmtF7ena52Rsk1aCJEvBxKoJJnFJ8VGFlnjY6o9egIYXbU5Fmty7pazRSuO9ZBYY8z6LEwtFa3qHHhM/nAQIDAQAB" )
```

The `p=` value above is example output. Substitute the one produced by
step 2.

The record must be split into several quoted strings. A single DNS
character-string holds at most 255 bytes, and the base64 of a 2048 bit
public key is 392 characters. A resolver concatenates the strings of a TXT
record without inserting anything between them, so breaking the base64 at
an arbitrary position is correct and is the usual way DKIM keys are
published.

When the zone is edited through a hosted DNS panel rather than a zone
file, the panel normally performs this split itself when a long value is
pasted. Some panels truncate at 255 bytes without reporting an error, so
verify the published record afterwards as described in step 5.

Three tags are shown and only `p=` is strictly required, but writing
`v=DKIM1; k=rsa;` explicitly is conventional and avoids relying on
defaults. Two further tags are useful:

`t=y` marks the selector as being in testing mode and asks verifiers not
to treat a failure from it as meaningful. Set it for the initial rollout
and remove it once step 5 confirms that signatures verify. The rollout
note at the end of step 5 explains why this is worth the extra edit.

`h=sha256` restricts the permitted hash algorithm, which matches what
srmilter emits.

The selector is chosen freely. Pick a value that can be rotated, such as a
year or month stamp, rather than a fixed name like `default`.

## 4. Configure srmilter

The domain and selector passed to `DkimSigner::from_pkcs8_pem` become the
`d=` and `s=` tags of the signature and tell a verifier which DNS record
to fetch. They must match the record published in step 3 exactly:

```rust
let pem = std::fs::read_to_string("/etc/srmilter/dkim.private.pem")?;
let signer = DkimSigner::from_pkcs8_pem(&pem, "example.com", "sel2026")?;
```

Two operational requirements apply.

The milter has to run on the outbound path. In Postfix that means
`smtpd_milters` on the submission service, or `non_smtpd_milters` for
locally injected mail. Signing inbound mail achieves nothing.

Body truncation has to be compatible with signing. Either accept the full
body, which is the default, or use `--truncate 0`, which produces a
signature declaring `l=0` and covering no body bytes. Any other
`--truncate` value combined with a configured signer is rejected when the
daemon starts, because a body cut at an arbitrary byte offset cannot be
covered honestly by the `l=` mechanism of RFC 6376.

## Which headers are signed

The signed header list becomes the `h=` tag of the signature and determines
what a modification in transit will break. The default is:

```
From, From, Subject, Date, Message-ID, MIME-Version, Content-Type,
Content-Transfer-Encoding
```

Override it with `DkimSigner::headers` if you have a reason to:

```rust
let signer = DkimSigner::from_pkcs8_pem(&pem, "example.com", "sel2026")?
    .headers(&["from", "from", "subject", "date", "message-id"]);
```

`From` is listed twice on purpose. RFC 6376 5.4 requires `From` to be
signed, and repeating a name claims more instances than the message
actually has. The second entry finds no further `From`, so it contributes
the null string to the hash but still appears in `h=`. A relay that adds a
second `From` header then breaks the signature rather than riding on it.
The same technique protects any header you never legitimately send: list
it, and adding one invalidates the signature.

`To` is deliberately not signed. Mailing lists and forwarders rewrite it,
and signing it gains little, since DMARC aligns on `From` and the SMTP
envelope is outside DKIM's coverage entirely. `Reply-To` is omitted for
the same reason. Adding either back is defensible if your mail flow does
not pass through such intermediaries.

Do not add headers that are written in transit. `Received`,
`Return-Path`, `Authentication-Results`, `Delivered-To`, `Precedence` and
the `List-*` family all change or appear between your milter and the
recipient, so signing them guarantees failure after one hop.

Note that header choice cannot make signatures survive mailing lists. Most
lists append a footer to the message body, which breaks the body hash
regardless of `h=`. The remedies for that are ARC (RFC 8617) at the
receiver and From-munging at the list, neither of which the signer
controls. This is also why `Subject` stays signed even though lists
commonly prepend a tag to it: the lists that rewrite `Subject` are
generally the same ones that append a footer, so dropping it would
surrender a well-known replay vector, an attacker presenting your validly
signed message under a subject of their own choosing, while still not
producing a signature that verifies.

Do not use the `l=` body length tag to survive appended footers. It lets
an attacker add arbitrary content below the signed prefix with the
signature still verifying. srmilter emits `l=` only in the `--truncate 0`
case described above, where it honestly declares zero body bytes.

None of this affects acceptance at the large providers. The Google and
Yahoo bulk sender requirements ask for a DKIM pass with DMARC alignment on
`From` and mandate no particular `h=` list.

## 5. Verify

Confirm that the record resolves and was not truncated:

```bash
dig +short TXT sel2026._domainkey.example.com
```

The reassembled value must end in the same characters as the output of
step 2, normally `AQIDAQAB` for an RSA key with the usual public exponent.

Then send a message through the milter to a mailbox under your control and
check that a `DKIM-Signature` header is present and that the receiving
side reports `dkim=pass` in its `Authentication-Results` header.

Signing is applied only when the classifier returns `Accept` or
`Quarantine`, and it is best effort. A signing failure is logged and the
message is still delivered, unsigned, rather than being blocked. An
unsigned message is therefore a reason to inspect the milter log.

DKIM alone changes little in how receivers treat mail until a DMARC policy
is published at `_dmarc.example.com` telling them what to do when
alignment fails.

### Rollout order and the testing flag

Publish the DNS record before enabling signing, not afterwards, and use
`t=y` on the record until this step succeeds.

The reason is that a signer cannot detect its own key being unpublished.
srmilter will happily emit correct signatures against a selector that does
not resolve, and nothing in the milter log will indicate a problem,
because from the signer's point of view nothing went wrong. Every verifier
will discard those signatures.

On its own that is harmless, since RFC 6376 requires a verifier to treat a
message whose signature fails as though it had never been signed. The
damage appears one layer up. Under DMARC a message passes if either DKIM
or SPF passes and aligns with the `From` domain, so an unpublished key
leaves SPF as the only remaining authentication. With no DMARC record, or
with `p=none`, mail continues to flow and the signature is merely useless.
With `p=quarantine` or `p=reject`, any delivery path where SPF does not
pass and align, forwarded mail in particular, now fails DMARC outright and
is quarantined or rejected.

`t=y` covers the window between the two states. It tells verifiers the
selector is still being tested and that a failure from it should not be
held against the domain. Remove it once `dkim=pass` has been confirmed
above, since a selector left permanently in testing mode asks receivers to
disregard its failures forever, which defeats the purpose of signing.

Note that a name that does not resolve at all and a name whose lookup
fails temporarily are not equivalent. A nonexistent record produces an
immediate permanent failure, usually reported as `dkim=permerror` with a
note such as `no key for signature`, although some verifiers report `fail`
or `neutral` instead, so do not match on one exact string. A `SERVFAIL` or
a timeout may instead be treated as a temporary error, and some receivers
will respond with a 4xx and defer the message. Delivery delays and
retries, rather than clean failures, therefore point at a broken
delegation or an unreliable nameserver rather than at a missing record.

## Key rotation

Rotation is done by selector, never by replacing the key behind an
existing one. Generate a new key pair, publish it under a new selector,
switch the milter to that selector, and only then remove the old record,
once any mail signed with the previous key has aged beyond the point where
a receiver might still verify it. A few days is generally sufficient.

Keeping the old record published during the changeover is what prevents
messages that are still in transit from failing verification.

## Troubleshooting

A `dkim=permerror` or a complaint about a missing key usually means the
record is not resolvable under `<selector>._domainkey.<domain>`, or that
the `d=` and `s=` tags of the signature do not match where the record was
published.

A `dkim=fail` on a signature that is present indicates the signed content
did not survive transit. The common cause is a mail system between
srmilter and the receiver modifying a signed header or the body, for
example a mailing list appending a footer.

A daemon that refuses to start with a message about truncation is
reporting the `--truncate` restriction described in step 4.
