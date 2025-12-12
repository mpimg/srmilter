#![allow(unused_macros)]

use srmilter::cli::xmain;
use srmilter::{ClassifyResult, Config, FullEmailClassifier, MailInfo};
use std::process::ExitCode;

mod classify;
struct StaticClassifier();
impl FullEmailClassifier for StaticClassifier {
    fn classify(&self, mail_info: &MailInfo) -> ClassifyResult {
        classify::classify(mail_info)
    }
}

fn main() -> ExitCode {
    let config = Config {
        full_mail_classifier: &StaticClassifier(),
    };
    match xmain(&config) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
