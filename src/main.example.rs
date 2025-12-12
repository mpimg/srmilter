use lazy_regex::regex_is_match;
use srmilter::{_result, ClassifyResult, MailInfo, accept, log, quarantine};

fn main() -> impl std::process::Termination {
    srmilter::cli::xmain(classify)
}

#[allow(unused_variables)]
pub fn classify(mail_info: &MailInfo) -> ClassifyResult {
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
        quarantine!(mail_info);
    }

    if !mail_info.get_other_header("X-Mailru-Msgtype").is_empty() {
        if from_address.ends_with("@iscb.org") || from_address.ends_with("@news.arraystar.com") {
            accept!(mail_info);
        }
        quarantine!(mail_info);
    }

    if regex_is_match!("for your business", text) {
        quarantine!(mail_info);
    }

    accept!(mail_info, "default");
}
