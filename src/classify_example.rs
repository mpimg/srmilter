/*
    file format subject to change!

    available macros:

      log!(mail_info, ...)          as println! but queue id automatically prefixed

      quarantine!(mail_info, ...)   log and return with Quarantine status. Log defaults to file and line number
      accept!(mail_info, ...)       log and return with Accept status. Log defaults to file and line number
      reject!(mail_info, ...)       log and return with Reject. Log defaults to file and line number

      regex_is_match!    from lazy_regex
*/

use crate::ClassifyResult;
use crate::MailInfo;
use lazy_regex::regex_is_match;

#[allow(unused_variables)]
pub fn classify(mail_info: &MailInfo) -> ClassifyResult {
    let msg = mail_info.get_message();
    let from_address = mail_info.get_from_address();
    let subject = mail_info.get_subject();
    let sender = mail_info.get_sender();
    let recipients = mail_info.get_recipients();
    let id = mail_info.get_id();
    let text = &mail_info.get_text();

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
