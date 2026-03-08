use srmilter::{ClassifyResult, Config, EmailClassifier, MailInfo};
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader};

fn read_array(filename: &str) -> Result<Vec<String>, Box<dyn Error>> {
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

fn read_array_nofail(filename: &str) -> Vec<String> {
    match read_array(filename) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            Vec::new()
        }
    }
}

pub fn array_contains(haystack: &[String], needle: &str) -> bool {
    haystack.iter().any(|s| s == needle)
}

struct Ctx {
    allowlist_domains: Vec<String>,
    blocklist_senders: Vec<String>,
    quarantine_keywords: Vec<String>,
}

fn main() -> impl std::process::Termination {
    let ctx = Ctx {
        allowlist_domains: read_array_nofail("/etc/srmilter/allowlist_domains.txt"),
        blocklist_senders: read_array_nofail("/etc/srmilter/blocklist_senders.txt"),
        quarantine_keywords: read_array_nofail("/etc/srmilter/quarantine_keywords.txt"),
    };

    let classifier = EmailClassifier::builder(ctx).classify_fn(classify).build();

    let config = Config::builder()
        .email_classifier(classifier)
        .enable_fork_mode()
        .build();
    srmilter::cli::cli(&config)
}

#[allow(unused_variables)]
fn classify(ctx: &Ctx, mail_info: &MailInfo) -> ClassifyResult {
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
