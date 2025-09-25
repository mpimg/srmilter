use mail_parser::MessageParser;
use srmilter::MailInfo;

#[test]
fn parse() {
    let mail_buffer = std::fs::read("tests/parse.eml").unwrap();
    let sender = "sender".to_string();
    let recipients = vec!["recipients".to_string()];
    let id = "test".to_string();
    let mut mail_info = MailInfo {
        sender,
        recipients,
        mail_buffer,
        id,
        ..Default::default()
    };
    let r = MessageParser::default().parse(&mail_info.mail_buffer);
    mail_info.msg = r.unwrap();
    dbg!(mail_info.get_sender());
    dbg!(mail_info.get_subject());
}
