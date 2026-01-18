use lazy_regex::regex_is_match;
use srmilter::{ClassifyResult, Config, EmailClassifier, MailInfo};

fn main() -> impl std::process::Termination {
    let classifier = EmailClassifier::builder(()).classify_fn(classify).build();
    let config = Config::builder()
        .email_classifier(classifier)
        .enable_fork_mode()
        .build();
    srmilter::cli::cli(&config)
}

#[allow(unused_variables)]
pub fn classify(_ctx: &(), mail_info: &MailInfo) -> ClassifyResult {
    let msg = mail_info.get_message();
    let from_address = mail_info.get_from_address();
    let from_name = mail_info.get_from_name();
    let subject = mail_info.get_subject();
    let sender = mail_info.get_sender();
    let recipients = mail_info.get_recipients();
    let id = mail_info.get_id();
    let text = &mail_info.get_text();
    let spam_score = mail_info.get_spam_score();

    if regex_is_match!("Täääst", subject) {
        return mail_info.quarantine("banned subject");
    }

    if !mail_info.get_other_header("X-Mailru-Msgtype").is_empty() {
        if from_address.ends_with("@iscb.org") || from_address.ends_with("@news.arraystar.com") {
            return mail_info.accept("Mailru but whitelisted");
        }
        return mail_info.quarantine("Mailru");
    }

    if regex_is_match!("for your business", text) {
        return mail_info.quarantine("banned text in message body");
    }

    mail_info.accept("default")
}
