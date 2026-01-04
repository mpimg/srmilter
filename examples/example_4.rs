use srmilter::{
    ClassifyResult, Config, FullEmailFnClassifierWithCtxArc, MailInfo, array_contains, read_array,
};
use std::sync::Arc;

/// Context struct holding configuration and lists loaded at startup.
/// This is passed to the classify function on every email.
struct ClassifierContext {
    /// Domains that should always be accepted
    allowlist_domains: Vec<String>,
    /// Sender addresses that should be rejected
    blocklist_senders: Vec<String>,
    /// Keywords in subject that trigger quarantine
    quarantine_keywords: Vec<String>,
}

impl ClassifierContext {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // In a real application, these paths would come from command-line args or config
        let allowlist_domains = read_array("/etc/srmilter/allowlist_domains.txt")
            .unwrap_or_else(|_| vec!["example.com".into(), "trusted.org".into()]);

        let blocklist_senders = read_array("/etc/srmilter/blocklist_senders.txt")
            .unwrap_or_else(|_| vec!["spammer@evil.com".into()]);

        let quarantine_keywords = read_array("/etc/srmilter/quarantine_keywords.txt")
            .unwrap_or_else(|_| vec!["free money".into(), "act now".into()]);

        Ok(Self {
            allowlist_domains,
            blocklist_senders,
            quarantine_keywords,
        })
    }
}

fn main() -> impl std::process::Termination {
    // Load context at startup - this happens once, not per-email
    let ctx = match ClassifierContext::new() {
        Ok(ctx) => ctx,
        Err(e) => {
            eprintln!("Failed to initialize classifier context: {e}");
            std::process::exit(1);
        }
    };

    // Wrap context in Arc for thread-safe sharing
    let ctx = Arc::new(ctx);

    // Create thread-safe classifier with Arc-wrapped context
    // This is compatible with --threads mode
    let classifier = Arc::new(FullEmailFnClassifierWithCtxArc::new(ctx, classify));
    let config = Config::builder()
        .full_mail_classifier_arc(classifier)
        .build();
    srmilter::cli::cli(&config)
}

#[allow(unused_variables)]
fn classify(ctx: &ClassifierContext, mail_info: &MailInfo) -> ClassifyResult {
    let from_address = mail_info.get_from_address();
    let subject = mail_info.get_subject();

    // Check blocklist first - reject known bad senders
    if array_contains(&ctx.blocklist_senders, from_address) {
        return mail_info.reject("sender on blocklist");
    }

    // Check allowlist - accept trusted domains
    for domain in &ctx.allowlist_domains {
        if from_address.ends_with(&format!("@{domain}")) {
            return mail_info.accept("domain on allowlist");
        }
    }

    // Check subject for quarantine keywords
    let subject_lower = subject.to_lowercase();
    for keyword in &ctx.quarantine_keywords {
        if subject_lower.contains(&keyword.to_lowercase()) {
            return mail_info.quarantine("subject contains quarantine keyword");
        }
    }

    mail_info.accept("default")
}
