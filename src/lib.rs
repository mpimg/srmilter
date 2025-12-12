use mail_parser::{HeaderName, MessageParser};
use std::borrow::Cow::Borrowed;
use std::collections::HashMap;

pub mod cli;
pub mod daemon;
mod macros;
pub mod milter;
mod reader_extention;

pub use reader_extention::*;

#[derive(Default)]
pub struct MailInfoStorage {
    pub sender: String,
    pub recipients: Vec<String>,
    pub macros: HashMap<String, String>,
    pub id: String, // postfix queue ident
    pub mail_buffer: Vec<u8>,
}

pub struct MailInfo<'a> {
    pub storage: &'a MailInfoStorage,
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
    pub fn get_to_address(&self) -> &str {
        self.msg
            .header(HeaderName::To)
            .and_then(|v| v.as_address())
            .and_then(|v| v.as_list())
            .and_then(|v| v.first())
            .and_then(|v| v.address())
            .unwrap_or("")
    }
    pub fn get_to_name(&self) -> &str {
        self.msg
            .header(HeaderName::To)
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
        &self.storage.sender
    }
    pub fn get_text(&self) -> std::borrow::Cow<'_, str> {
        self.msg.body_text(0).unwrap_or(Borrowed(""))
    }
    pub fn get_recipients(&self) -> &Vec<String> {
        &self.storage.recipients
    }
    pub fn get_only_recipient(&self) -> &str {
        if self.storage.recipients.len() == 1 {
            &self.storage.recipients[0]
        } else {
            ""
        }
    }
    pub fn get_id(&self) -> &str {
        &self.storage.id
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
        if let Some(r) = self.get_trusted_received_header(good_domain) {
            r.from
                .as_ref()
                .map(|v| v.to_string())
                .unwrap_or("".to_string())
        } else {
            "".to_string()
        }
    }
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
    pub fn get_trusted_received_header(
        &self,
        good_domain: &str,
    ) -> Option<&mail_parser::Received<'_>> {
        self.msg.header_values(HeaderName::Received).find_map(|h| {
            if let mail_parser::HeaderValue::Received(r) = h
                && let Some(mail_parser::Host::Name(by)) = &r.by
                && by.ends_with(good_domain)
            {
                Some(r.as_ref())
            } else {
                None
            }
        })
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum ClassifyResult {
    Accept,
    Reject,
    Quarantine,
}

impl ClassifyResult {
    pub fn uc(self) -> &'static str {
        match self {
            ClassifyResult::Accept => "ACCEPT",
            ClassifyResult::Reject => "REJECT",
            ClassifyResult::Quarantine => "QUARANTINE",
        }
    }
}

pub trait FullEmailClassifier {
    fn classify(&self, mail_info: &MailInfo) -> ClassifyResult;
}

pub struct Config<'a> {
    pub full_mail_classifier: &'a dyn FullEmailClassifier,
}

pub fn classify_mail(config: &Config, storage: &MailInfoStorage) -> ClassifyResult {
    let r = MessageParser::default().parse(&storage.mail_buffer);
    match r {
        Some(msg) => {
            let mail_info = MailInfo { storage, msg };
            config.full_mail_classifier.classify(&mail_info)
        }
        None => {
            println!(
                "{}: ACCEPT (because of failure to parse message)",
                storage.id,
            );
            ClassifyResult::Accept
        }
    }
}
