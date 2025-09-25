use mail_parser::HeaderName;
use std::borrow::Cow::Borrowed;
use std::collections::HashMap;

#[allow(dead_code)]
#[derive(Default)]
pub struct MailInfo<'a> {
    pub sender: String,
    pub recipients: Vec<String>,
    pub macros: HashMap<String, String>,
    pub id: String, // postfix queue ident
    pub mail_buffer: Vec<u8>,
    pub msg: mail_parser::Message<'a>,
}

#[allow(dead_code)]
impl MailInfo<'_> {
    pub fn get_from_address(&self) -> &str {
        self.msg
            .header(HeaderName::From)
            .and_then(|v| v.as_address())
            .and_then(|v| v.as_list())
            .and_then(|v| v.first())
            .and_then(|v| v.address())
            .unwrap_or("")
    }
    pub fn get_from_name(&self) -> &str {
        self.msg
            .header(HeaderName::From)
            .and_then(|v| v.as_address())
            .and_then(|v| v.as_list())
            .and_then(|v| v.first())
            .and_then(|v| v.name())
            .unwrap_or("")
    }
    pub fn get_subject(&self) -> &str {
        self.msg
            .header(HeaderName::Subject)
            .and_then(|v| v.as_text())
            .unwrap_or("")
    }
    pub fn get_sender(&self) -> &str {
        &self.sender
    }
    pub fn get_text(&self) -> std::borrow::Cow<'_, str> {
        self.msg.body_text(0).unwrap_or(Borrowed(""))
    }
    pub fn get_recipients(&self) -> &Vec<String> {
        &self.recipients
    }
    pub fn get_only_recipient(&self) -> &str {
        if self.recipients.len() == 1 {
            &self.recipients[0]
        } else {
            ""
        }
    }
    pub fn get_id(&self) -> &str {
        &self.id
    }
    pub fn get_message(&self) -> &mail_parser::Message<'_> {
        &self.msg
    }
    pub fn get_other_header<'a>(&'a self, name: &'a str) -> &'a str {
        self.msg
            .header(HeaderName::Other(Borrowed(name)))
            .and_then(|v| v.as_text())
            .unwrap_or("")
    }
    pub fn get_spam_score(&self) -> f32 {
        self.msg
            .header(HeaderName::Other(Borrowed("X-Spam-Score")))
            .and_then(|v| v.as_text())
            .and_then(|v| v.parse::<f32>().ok())
            .unwrap_or(0f32)
    }
    pub fn get_header_sender_address(&self) -> &str {
        self.msg
            .header(HeaderName::Sender)
            .and_then(|v| v.as_address())
            .and_then(|v| v.as_list())
            .and_then(|v| v.first())
            .and_then(|v| v.address())
            .unwrap_or("")
    }
    pub fn get_remote_name(&self, good_domain: &str) -> String {
        self.msg
            .header_values(HeaderName::Received)
            .find_map(|h| {
                if let mail_parser::HeaderValue::Received(r) = h {
                    if let Some(mail_parser::Host::Name(by)) = &r.by {
                        if by.ends_with(good_domain) {
                            let from_name = r.from.as_ref().map(|v| v.to_string());
                            return from_name;
                        }
                    }
                }
                None
            })
            .unwrap_or("".to_string())
    }
}
