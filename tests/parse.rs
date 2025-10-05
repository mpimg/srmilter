use mail_parser::MessageParser;
use srmilter::{MailInfo, MailInfoStorage};

#[test]
fn parse_001() {
    let mut storage = MailInfoStorage::default();
    storage.mail_buffer = std::fs::read("tests/parse_001.eml").unwrap();
    storage.sender = "sender".to_string();
    storage.recipients = vec!["recipient".to_string()];
    storage.id = "test".to_string();

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
    assert_eq!(
        mail_info.get_subject(),
        "Test mit einer relativ langen Header-Zeile, die hoffentlich zum Wrapping führt und dann auch noch mit Umlauten und Emoji 😀"
    );
    assert_eq!(mail_info.get_text(), "😘\r\n");
    assert_eq!(
        mail_info.get_remote_name(".mx.srv.dfn.de"),
        "mail-lj1-f170.google.com"
    );
}

#[test]
fn parse_002() {
    let mut storage = MailInfoStorage::default();
    storage.mail_buffer = std::fs::read("tests/parse_002.eml").unwrap();
    storage.sender = "sender".to_string();
    storage.recipients = vec!["recipients".to_string()];
    storage.id = "test".to_string();
    let mail_info = MailInfo {
        storage: &storage,
        msg: MessageParser::default()
            .parse(&storage.mail_buffer)
            .unwrap(),
    };
    dbg!(mail_info.get_sender());
    dbg!(mail_info.get_subject());
}
