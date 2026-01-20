use mail_parser::{HeaderName, MessageParser};
use std::borrow::Cow::Borrowed;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{BufRead as _, BufReader};
use std::net::IpAddr;
use std::sync::Arc;

pub mod cli;
mod daemon;
mod milter;
mod reader_extention;
pub mod spamhaus_zen;

#[derive(Default)]
struct MailInfoStorage {
    sender: String,
    recipients: Vec<String>,
    macros: HashMap<String, String>,
    id: String, // postfix queue ident
    mail_buffer: Vec<u8>,
}

/// Provides read-only access to a parsed email message.
///
/// This is the main interface for classifier functions to query information about an email.
/// It provides convenient accessors for email headers, body content, envelope information,
/// and logging utilities.
///
/// # Default Values
///
/// Accessor methods return default values (empty string `""` for text fields, `0.0` for
/// numeric fields like spam score) when the requested information is missing or unavailable.
/// This design allows classifiers to use simple expressions (e.g., string comparisons,
/// pattern matching) without needing special-case code for missing fields.
///
/// # Decision Methods
///
/// When a classifier reaches a final decision, it should use one of the decision methods:
/// [`accept`](Self::accept), [`reject`](Self::reject), or [`quarantine`](Self::quarantine).
/// These methods log the decision with a reason and return the appropriate [`ClassifyResult`].
pub struct MailInfo<'a> {
    storage: &'a MailInfoStorage,
    msg: mail_parser::Message<'a>,
}

impl MailInfo<'_> {
    /// Returns the email address from the `From:` header.
    pub fn get_from_address(&self) -> &str {
        self.msg
            .header(HeaderName::From)
            .and_then(|v| v.as_address())
            .and_then(|v| v.as_list())
            .and_then(|v| v.first())
            .and_then(|v| v.address())
            .unwrap_or("")
    }
    /// Returns the display name from the `From:` header.
    pub fn get_from_name(&self) -> &str {
        self.msg
            .header(HeaderName::From)
            .and_then(|v| v.as_address())
            .and_then(|v| v.as_list())
            .and_then(|v| v.first())
            .and_then(|v| v.name())
            .unwrap_or("")
    }
    /// Returns the email address from the `To:` header.
    pub fn get_to_address(&self) -> &str {
        self.msg
            .header(HeaderName::To)
            .and_then(|v| v.as_address())
            .and_then(|v| v.as_list())
            .and_then(|v| v.first())
            .and_then(|v| v.address())
            .unwrap_or("")
    }
    /// Returns the display name from the `To:` header.
    pub fn get_to_name(&self) -> &str {
        self.msg
            .header(HeaderName::To)
            .and_then(|v| v.as_address())
            .and_then(|v| v.as_list())
            .and_then(|v| v.first())
            .and_then(|v| v.name())
            .unwrap_or("")
    }
    /// Returns the `Subject:` header value.
    pub fn get_subject(&self) -> &str {
        self.msg
            .header(HeaderName::Subject)
            .and_then(|v| v.as_text())
            .unwrap_or("")
    }
    /// Returns the SMTP envelope sender (MAIL FROM address).
    pub fn get_sender(&self) -> &str {
        &self.storage.sender
    }
    /// Returns the first text/plain body part of the message.
    pub fn get_text(&self) -> std::borrow::Cow<'_, str> {
        self.msg.body_text(0).unwrap_or(Borrowed(""))
    }
    /// Returns all SMTP envelope recipients (RCPT TO addresses).
    pub fn get_recipients(&self) -> &[String] {
        &self.storage.recipients
    }
    /// Returns the single recipient if there is exactly one, otherwise `""`.
    pub fn get_only_recipient(&self) -> &str {
        if self.storage.recipients.len() == 1 {
            &self.storage.recipients[0]
        } else {
            ""
        }
    }
    /// Returns the Postfix queue ID (from milter macro `i`).
    pub fn get_id(&self) -> &str {
        &self.storage.id
    }
    /// Returns the full parsed message for advanced access via `mail_parser`.
    pub fn get_message(&self) -> &mail_parser::Message<'_> {
        &self.msg
    }
    /// Returns the value of any header by name.
    // Explicit lifetime required: HeaderName::Other takes Cow<'a, str> and the
    // lifetime propagates through the method chain, constraining the return type.
    pub fn get_other_header<'a>(&'a self, name: &'a str) -> &'a str {
        self.msg
            .header(HeaderName::Other(Borrowed(name)))
            .and_then(|v| v.as_text())
            .unwrap_or("")
    }
    /// Returns the parsed `X-Spam-Score` header value, or `0.0` if missing or invalid.
    pub fn get_spam_score(&self) -> f32 {
        self.msg
            .header(HeaderName::Other(Borrowed("X-Spam-Score")))
            .and_then(|v| v.as_text())
            .and_then(|v| v.parse::<f32>().ok())
            .unwrap_or(0f32)
    }
    /// Returns the email address from the `Sender:` header.
    pub fn get_header_sender_address(&self) -> &str {
        self.msg
            .header(HeaderName::Sender)
            .and_then(|v| v.as_address())
            .and_then(|v| v.as_list())
            .and_then(|v| v.first())
            .and_then(|v| v.address())
            .unwrap_or("")
    }
    /// Returns the remote hostname from the first trusted `Received:` header.
    ///
    /// The `good_domain` parameter specifies a domain suffix to identify trusted mail servers
    /// (e.g., `.mx.example.com`). Headers are scanned until one with a matching `by` field is found.
    pub fn get_remote_name(&self, good_domain: &str) -> String {
        if let Some(r) = self.get_trusted_received_header(good_domain) {
            r.from
                .as_ref()
                .map(|v| v.to_string())
                .unwrap_or("".to_string())
        } else {
            "".to_string()
        }
    }
    /// Returns `(hostname, IP, reverse_DNS)` from the first trusted `Received:` header.
    ///
    /// See [`get_remote_name`](Self::get_remote_name) for `good_domain` semantics.
    pub fn get_remote(&self, good_domain: &str) -> (String, String, String) {
        if let Some(r) = self.get_trusted_received_header(good_domain) {
            let from_name = r
                .from
                .as_ref()
                .map(|v| v.to_string())
                .unwrap_or("".to_string());
            let from_ip = r
                .from_ip
                .as_ref()
                .map(|v| v.to_string())
                .unwrap_or("".to_string());
            let from_iprev = r
                .from_iprev
                .as_ref()
                .map(|v| v.to_string())
                .unwrap_or("".to_string());
            (from_name, from_ip, from_iprev)
        } else {
            ("".to_string(), "".to_string(), "".to_string())
        }
    }
    /// Returns an iterator over all `Received:` headers in the message.
    pub fn get_received_header_iter(&self) -> impl Iterator<Item = &mail_parser::Received<'_>> {
        self.msg.headers().iter().filter_map(|h| {
            if let mail_parser::HeaderValue::Received(r) = &h.value {
                // r: &Box<Received<'_>>
                Some(r.as_ref())
            } else {
                None
            }
        })
    }
    /// Returns an iterator over `Received:` headers starting from the first trusted one.
    ///
    /// Skips headers until finding one where the `by` field ends with `good_domain`.
    pub fn get_trusted_received_header_iter(
        &self,
        good_domain: &str,
    ) -> impl Iterator<Item = &mail_parser::Received<'_>> {
        self.get_received_header_iter().skip_while(move |r| {
            if let Some(mail_parser::Host::Name(by)) = &r.by
                && by.ends_with(good_domain)
            {
                false
            } else {
                true
            }
        })
    }
    /// Returns the first trusted `Received:` header, or `None` if not found.
    pub fn get_trusted_received_header<'a>(
        &'a self,
        good_domain: &str,
    ) -> Option<&'a mail_parser::Received<'a>> {
        self.get_trusted_received_header_iter(good_domain).next()
    }

    /// Returns an iterator over all IP addresses from `Received:` headers.
    pub fn received_ip_iter(&self) -> impl Iterator<Item = IpAddr> {
        self.msg
            .header_values(HeaderName::Received)
            .filter_map(|h| {
                if let mail_parser::HeaderValue::Received(r) = h
                    && let Some(ip) = r.from_ip
                {
                    Some(ip)
                } else {
                    None
                }
            })
    }
    /// Returns an iterator over IP addresses from trusted `Received:` headers only.
    pub fn foreign_ip_iter(&self, good_domain: &str) -> impl Iterator<Item = IpAddr> {
        self.get_trusted_received_header_iter(good_domain)
            .filter_map(|r| r.from_ip)
    }

    /// Logs a message to stderr with the queue ID prefix.
    pub fn log(&self, msg: &str) {
        eprintln!("{}: {}", self.storage.id, msg);
    }

    /// Logs an acceptance message and returns [`ClassifyResult::Accept`].
    #[must_use]
    pub fn accept(&self, msg: &str) -> ClassifyResult {
        self.log(&format!("{} ({})", ClassifyResult::Accept.uc(), msg));
        ClassifyResult::Accept
    }

    /// Logs a quarantine message and returns [`ClassifyResult::Quarantine`].
    #[must_use]
    pub fn quarantine(&self, msg: &str) -> ClassifyResult {
        self.log(&format!("{} ({})", ClassifyResult::Quarantine.uc(), msg));
        ClassifyResult::Quarantine
    }

    /// Logs a rejection message and returns [`ClassifyResult::Reject`].
    #[must_use]
    pub fn reject(&self, msg: &str) -> ClassifyResult {
        self.log(&format!("{} ({})", ClassifyResult::Reject.uc(), msg));
        ClassifyResult::Reject
    }
}

/// The result of classifying an email message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassifyResult {
    /// Accept the email for delivery.
    Accept,
    /// Reject the email with a 5xx error to the sender.
    Reject,
    /// Accept but hold the email in Postfix quarantine.
    Quarantine,
}

impl ClassifyResult {
    /// Returns the uppercase string representation (`"ACCEPT"`, `"REJECT"`, or `"QUARANTINE"`).
    pub fn uc(self) -> &'static str {
        match self {
            ClassifyResult::Accept => "ACCEPT",
            ClassifyResult::Reject => "REJECT",
            ClassifyResult::Quarantine => "QUARANTINE",
        }
    }
}

/// Configuration for the milter daemon.
///
/// Use [`Config::builder()`] to create a new configuration.
pub struct Config {
    full_mail_classifier: Option<Arc<dyn ClassifyEmail + Send + Sync>>,
    fork_mode_enabled: bool,
}

impl Config {
    /// Creates a new [`ConfigBuilder`] for constructing a configuration.
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }
}

/// Builder for constructing a [`Config`].
///
/// # Example
///
/// ```ignore
/// let classifier = FullEmailFnClassifier::new(my_classify_fn);
/// let config = Config::builder()
///     .full_mail_classifier(&classifier)
///     .build();
/// ```
#[derive(Default)]
pub struct ConfigBuilder {
    full_mail_classifier: Option<Arc<dyn ClassifyEmail + Send + Sync>>,
    fork_mode_enabled: bool,
}

impl ConfigBuilder {
    pub fn full_mail_classifier_arc(
        mut self,
        classifier: Arc<dyn ClassifyEmail + Send + Sync>,
    ) -> Self {
        self.full_mail_classifier = Some(classifier);
        self
    }
    /// Enables fork mode support, allowing the `--fork` command-line option.
    ///
    /// Fork mode spawns child processes to handle milter connections. This can be
    /// efficient but has important safety considerations that require explicit opt-in.
    ///
    /// # Safety Requirements
    ///
    /// Before enabling fork mode, ensure your application does **not** do any of the following
    /// before calling [`cli::cli()`]:
    ///
    /// - **Use threads**: If the parent process has threads running, locks held by those
    ///   threads will not be released in the forked children. This can cause deadlocks
    ///   since the threads themselves are not copied—only the main thread continues in the
    ///   child.
    ///
    /// - **Hold open connections**: Database connections, network sockets, or other stateful
    ///   connections get inherited by child processes. When children exit, their drop
    ///   implementations may send protocol shutdown messages or flush buffers, causing
    ///   duplicate or corrupted communication with the remote endpoint.
    ///
    /// - **Use buffered I/O with autoflush**: Open files with buffered writers that flush
    ///   on close can cause duplicate writes when both parent and children flush the same
    ///   inherited buffer.
    ///
    /// Additionally, be aware that:
    ///
    /// - **Copy-on-write semantics apply**: Mutable data shared between classifier invocations
    ///   will not actually be shared across forked children. Each child gets its own copy,
    ///   so accumulated state (counters, caches) will not be visible to other children or
    ///   the parent.
    ///
    /// - **Signal handlers are inherited**: Any custom signal handlers set before forking
    ///   will be active in child processes, which may cause unexpected behavior.
    ///
    /// If your classifier is a pure function that only reads from immutable context data
    /// loaded at startup, fork mode is safe and can provide good isolation between
    /// connections.
    pub fn enable_fork_mode(mut self) -> Self {
        self.fork_mode_enabled = true;
        self
    }
    /// Builds the final [`Config`].
    pub fn build(self) -> Config {
        Config {
            full_mail_classifier: self.full_mail_classifier,
            fork_mode_enabled: self.fork_mode_enabled,
        }
    }
}

fn classify_mail(config: &Config, storage: &MailInfoStorage) -> ClassifyResult {
    if let Some(ref arg) = config.full_mail_classifier {
        let classifier: &dyn ClassifyEmail = arg.as_ref();
        let r = MessageParser::default().parse(&storage.mail_buffer);
        if let Some(msg) = r {
            let mail_info = MailInfo { storage, msg };
            classifier.classify(&mail_info)
        } else {
            eprintln!(
                "{}: ACCEPT (because of failure to parse message)",
                storage.id,
            );
            ClassifyResult::Accept
        }
    } else {
        eprintln!("{}: ACCEPT (no classifier configured)", storage.id);
        ClassifyResult::Accept
    }
}

type ClassifyFunctionWithCtx<C> = fn(&C, &MailInfo) -> ClassifyResult;

/// Trait for implementing email classifiers.
pub trait ClassifyEmail {
    /// Classifies the given email and returns the classification decision.
    fn classify(&self, mail_info: &MailInfo) -> ClassifyResult;
}

/// General purpose classifier
///
/// Use [`EmailClassifier::builder()`] to construct a new classifier.
pub struct EmailClassifier<C> {
    user_ctx: C,
    f: Option<ClassifyFunctionWithCtx<C>>,
}

impl<C> ClassifyEmail for EmailClassifier<C> {
    fn classify(&self, mail_info: &MailInfo) -> ClassifyResult {
        if let Some(f) = self.f {
            f(&self.user_ctx, mail_info)
        } else {
            mail_info.accept("no classifier function registered")
        }
    }
}

/// Builder for constructing a [`EmailClassifier`]
///
/// Create the builder with [`EmailClassifier::builder()`]
pub struct EmailClassifierBuilder<C> {
    user_ctx: C,
    f: Option<ClassifyFunctionWithCtx<C>>,
}

impl<C> EmailClassifierBuilder<C> {
    /// Build the final [`EmailClassifier`]
    pub fn build(self) -> EmailClassifier<C> {
        EmailClassifier {
            user_ctx: self.user_ctx,
            f: self.f,
        }
    }
    /// Register the callback function to classify the received email
    pub fn classify_fn(mut self, f: ClassifyFunctionWithCtx<C>) -> Self {
        self.f = Some(f);
        self
    }
}

impl<C> EmailClassifier<C> {
    /// Create a new [`EmailClassifierBuilder`] for constructing a new [`EmailClassifier`]
    ///
    /// `user_ctx` is moved into the builder so that the lifetime can be
    /// managed thread-safely by the library.
    ///
    /// If `user_ctx` is not really needed, the unit type (`()`) can be used.
    ///
    pub fn builder(user_ctx: C) -> EmailClassifierBuilder<C> {
        EmailClassifierBuilder { user_ctx, f: None }
    }
}

impl ConfigBuilder {
    /// Set the classifier
    pub fn email_classifier<T>(mut self, classifier: T) -> Self
    where
        T: ClassifyEmail + Send + Sync + 'static,
    {
        self.full_mail_classifier = Some(Arc::new(classifier));
        self
    }
}

/// Reads lines from a file, stripping comments and whitespace.
///
/// Lines are trimmed of leading/trailing whitespace. Content after `#` on each line
/// is treated as a comment and ignored. Empty lines are skipped.
///
/// # Example
///
/// ```ignore
/// // File contents:
/// // # This is a comment
/// // spammer@evil.com
/// // blocked@example.com  # inline comment
///
/// let blocklist = read_array("/etc/srmilter/blocklist.txt")?;
/// // blocklist = ["spammer@evil.com", "blocked@example.com"]
/// ```
pub fn read_array(filename: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let file = File::open(filename).map_err(|e| format!("{filename}: {e}"))?;
    let reader = BufReader::new(file);
    let mut out: Vec<String> = Vec::with_capacity(20);
    for line in reader.lines() {
        if let Some(s) = line?.split('#').next() {
            let s = s.trim();
            if !s.is_empty() {
                out.push(s.into());
            }
        }
    }
    Ok(out)
}

/// Checks if an exact match for `needle` exists in `haystack`.
pub fn array_contains(haystack: &[String], needle: &str) -> bool {
    haystack.iter().any(|s| s == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_001() {
        let storage = MailInfoStorage {
            mail_buffer: std::fs::read("tests/parse_001.eml").unwrap(),
            sender: "sender".to_string(),
            recipients: vec!["recipient".to_string()],
            id: "test".to_string(),
            ..Default::default()
        };

        let mail_info = MailInfo {
            storage: &storage,
            msg: MessageParser::default()
                .parse(&storage.mail_buffer)
                .unwrap(),
        };

        assert_eq!(mail_info.get_sender(), "sender");
        assert_eq!(mail_info.get_only_recipient(), "recipient");
        assert_eq!(mail_info.get_from_address(), "donald.buczek@gmail.com");
        assert_eq!(mail_info.get_from_name(), "Donald Buczek");
        assert_eq!(mail_info.get_header_sender_address(), "");
        assert_eq!(mail_info.get_spam_score(), 0f32);
        assert_eq!(mail_info.get_to_address(), "emil.erpel@entenhausen.org");
        assert_eq!(mail_info.get_to_name(), "Emil Erpel");
        assert_eq!(
            mail_info.get_subject(),
            "Test mit einer relativ langen Header-Zeile, die hoffentlich zum Wrapping führt und dann auch noch mit Umlauten und Emoji 😀"
        );
        assert_eq!(mail_info.get_text(), "😘\r\n");
        assert_eq!(
            mail_info.get_remote_name(".mx.srv.dfn.de"),
            "mail-lj1-f170.google.com"
        );
        let (name, ip, iprev) = mail_info.get_remote(".mx.srv.dfn.de");
        assert_eq!(name, "mail-lj1-f170.google.com");
        assert_eq!(ip, "209.85.208.170");
        assert_eq!(iprev, "mail-lj1-f170.google.com");
        let (name, ip, iprev) = mail_info.get_remote(".junk");
        assert_eq!(name, "");
        assert_eq!(ip, "");
        assert_eq!(iprev, "");
    }

    #[test]
    fn parse_002() {
        let storage = MailInfoStorage {
            mail_buffer: std::fs::read("tests/parse_002.eml").unwrap(),
            sender: "sender".to_string(),
            recipients: vec!["recipients".to_string()],
            id: "test".to_string(),
            ..Default::default()
        };
        let mail_info = MailInfo {
            storage: &storage,
            msg: MessageParser::default()
                .parse(&storage.mail_buffer)
                .unwrap(),
        };
        assert_eq!(
            mail_info.get_subject(),
            "New privacy policy at codeberg.org"
        );
    }

    #[test]
    fn test_only_recipients() {
        let mut storage = MailInfoStorage::default();
        {
            let mail_info = MailInfo {
                storage: &storage,
                msg: mail_parser::Message::default(),
            };
            assert_eq!(mail_info.get_only_recipient(), "");
        }
        storage.recipients.push("foobar1".to_string());
        {
            let mail_info = MailInfo {
                storage: &storage,
                msg: mail_parser::Message::default(),
            };
            assert_eq!(mail_info.get_only_recipient(), "foobar1");
        }
        storage.recipients.push("foobar2".to_string());
        {
            let mail_info = MailInfo {
                storage: &storage,
                msg: mail_parser::Message::default(),
            };
            assert_eq!(mail_info.get_only_recipient(), "");
        }
    }
}
