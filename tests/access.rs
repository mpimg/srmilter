use srmilter::{MailInfo, MailInfoStorage};

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
