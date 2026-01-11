use mail_parser::{HeaderName, MessageParser};
use std::borrow::Cow::Borrowed;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader};
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
/// This struct is passed to classifier functions and provides convenient accessors
/// for email headers, body content, envelope information, and logging utilities.
/// All string accessor methods return `""` if the requested field is missing.
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
    pub fn get_recipients(&self) -> &Vec<String> {
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

    #[deprecated(since = "2.0.0", note = "please use `received_ip_iter` instead")]
    pub fn recevied_ip_iter(&self) -> impl Iterator<Item = IpAddr> {
        self.received_ip_iter()
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
#[derive(Debug)]
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

/// Trait for implementing email classifiers.
///
/// Implement this trait to create custom classification logic. The classifier
/// receives a [`MailInfo`] reference and must return a [`ClassifyResult`].
pub trait FullEmailClassifier {
    /// Classifies the given email and returns the classification decision.
    fn classify(&self, mail_info: &MailInfo) -> ClassifyResult;
}

/// Internal storage for classifier references.
pub enum ClassifierStorage<'a> {
    /// A borrowed reference to a classifier.
    Borrowed(&'a dyn FullEmailClassifier),
    /// An owned, thread-safe classifier wrapped in `Arc`.
    Owned(Arc<dyn FullEmailClassifier + Send + Sync>),
}

/// Configuration for the milter daemon.
///
/// Use [`Config::builder()`] to create a new configuration.
pub struct Config<'a> {
    full_mail_classifier: Option<ClassifierStorage<'a>>,
    fork_mode_enabled: bool,
}

impl<'a> Config<'a> {
    /// Creates a new [`ConfigBuilder`] for constructing a configuration.
    pub fn builder() -> ConfigBuilder<'static> {
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
pub struct ConfigBuilder<'a> {
    full_mail_classifier: Option<ClassifierStorage<'a>>,
    fork_mode_enabled: bool,
}

impl<'a> ConfigBuilder<'a> {
    /// Sets a borrowed classifier for single-threaded or fork mode.
    pub fn full_mail_classifier(mut self, classifier: &'a dyn FullEmailClassifier) -> Self {
        self.full_mail_classifier = Some(ClassifierStorage::Borrowed(classifier));
        self
    }
    /// Sets an `Arc`-wrapped classifier for thread mode (`--threads`).
    ///
    /// This is required when using `--threads` as the classifier must be `Send + Sync`.
    pub fn full_mail_classifier_arc(
        mut self,
        classifier: Arc<dyn FullEmailClassifier + Send + Sync>,
    ) -> Self {
        self.full_mail_classifier = Some(ClassifierStorage::Owned(classifier));
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
    pub fn build(self) -> Config<'a> {
        Config {
            full_mail_classifier: self.full_mail_classifier,
            fork_mode_enabled: self.fork_mode_enabled,
        }
    }
}

fn classify_mail(config: &Config, storage: &MailInfoStorage) -> ClassifyResult {
    if let Some(ref c) = config.full_mail_classifier {
        let classifier: &dyn FullEmailClassifier = match c {
            ClassifierStorage::Borrowed(b) => *b,
            ClassifierStorage::Owned(arc) => arc.as_ref(),
        };
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

type ClassifyFunction = fn(&MailInfo) -> ClassifyResult;

/// A classifier that wraps a simple function.
///
/// Use this for classifiers that don't need external context.
/// Compatible with single-threaded and fork modes.
///
/// # Example
///
/// ```ignore
/// fn my_classifier(mail_info: &MailInfo) -> ClassifyResult {
///     mail_info.accept("default")
/// }
///
/// let classifier = FullEmailFnClassifier::new(my_classifier);
/// ```
pub struct FullEmailFnClassifier(ClassifyFunction);

impl FullEmailFnClassifier {
    /// Creates a new classifier from the given function.
    pub fn new(f: ClassifyFunction) -> Self {
        Self(f)
    }
}

impl FullEmailClassifier for FullEmailFnClassifier {
    fn classify(&self, mail_info: &MailInfo) -> ClassifyResult {
        self.0(mail_info)
    }
}

type ClassifyFunctionWithCtx<C> = fn(&C, &MailInfo) -> ClassifyResult;

/// A classifier that wraps a function with a borrowed context.
///
/// Use this when your classifier needs access to configuration or data loaded at startup.
/// The context is borrowed, making this compatible with single-threaded and fork modes.
///
/// # Example
///
/// ```ignore
/// struct MyContext {
///     blocklist: Vec<String>,
/// }
///
/// fn my_classifier(ctx: &MyContext, mail_info: &MailInfo) -> ClassifyResult {
///     if ctx.blocklist.contains(&mail_info.get_from_address().to_string()) {
///         return mail_info.reject("blocked sender");
///     }
///     mail_info.accept("default")
/// }
///
/// let ctx = MyContext { blocklist: vec![] };
/// let classifier = FullEmailFnClassifierWithCtx::new(&ctx, my_classifier);
/// ```
pub struct FullEmailFnClassifierWithCtx<'a, C> {
    user_ctx: &'a C,
    f: ClassifyFunctionWithCtx<C>,
}

impl<'a, C> FullEmailFnClassifierWithCtx<'a, C> {
    /// Creates a new classifier with the given context and function.
    pub fn new(user_ctx: &'a C, f: ClassifyFunctionWithCtx<C>) -> Self {
        Self { user_ctx, f }
    }
}

impl<'a, C> FullEmailClassifier for FullEmailFnClassifierWithCtx<'a, C> {
    fn classify(&self, mail_info: &MailInfo) -> ClassifyResult {
        (self.f)(self.user_ctx, mail_info)
    }
}

/// Thread-safe version of [`FullEmailFnClassifierWithCtx`] that owns the context via `Arc`.
///
/// Use this with [`ConfigBuilder::full_mail_classifier_arc()`] when running with `--threads`.
/// The context type `C` must implement `Send + Sync`.
///
/// # Example
///
/// ```ignore
/// let ctx = Arc::new(MyContext::new());
/// let classifier = Arc::new(FullEmailFnClassifierWithCtxArc::new(ctx, my_classifier));
/// let config = Config::builder()
///     .full_mail_classifier_arc(classifier)
///     .build();
/// ```
pub struct FullEmailFnClassifierWithCtxArc<C> {
    user_ctx: Arc<C>,
    f: ClassifyFunctionWithCtx<C>,
}

impl<C> FullEmailFnClassifierWithCtxArc<C> {
    /// Creates a new thread-safe classifier with the given `Arc`-wrapped context.
    pub fn new(user_ctx: Arc<C>, f: ClassifyFunctionWithCtx<C>) -> Self {
        Self { user_ctx, f }
    }
}

impl<C: Send + Sync> FullEmailClassifier for FullEmailFnClassifierWithCtxArc<C> {
    fn classify(&self, mail_info: &MailInfo) -> ClassifyResult {
        (self.f)(&self.user_ctx, mail_info)
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
    for s in haystack {
        if s == needle {
            return true;
        }
    }
    false
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
