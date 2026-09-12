use srmilter::{ClassifyResult, Config, DkimSigner, EmailClassifier, MailInfo};

/// Demonstrates configuring DKIM signing for outgoing mail.
///
/// Reads a PKCS#8 PEM private key from SRMILTER_DKIM_KEY_FILE, and the
/// signing domain/selector from SRMILTER_DKIM_DOMAIN / SRMILTER_DKIM_SELECTOR
/// (defaulting to "example.com" / "selector1").
fn main() -> impl std::process::Termination {
    let key_file = std::env::var("SRMILTER_DKIM_KEY_FILE")
        .expect("SRMILTER_DKIM_KEY_FILE must point to a PKCS#8 PEM private key");
    let domain =
        std::env::var("SRMILTER_DKIM_DOMAIN").unwrap_or_else(|_| "example.com".to_string());
    let selector =
        std::env::var("SRMILTER_DKIM_SELECTOR").unwrap_or_else(|_| "selector1".to_string());

    let pem = std::fs::read_to_string(&key_file).unwrap_or_else(|e| panic!("{key_file}: {e}"));
    let signer =
        DkimSigner::from_pkcs8_pem(&pem, domain, selector).unwrap_or_else(|e| panic!("{e}"));

    let classifier = EmailClassifier::builder(()).classify_fn(classify).build();
    let config = Config::builder()
        .email_classifier(classifier)
        .dkim_signer(signer)
        .build();
    srmilter::cli::cli(&config)
}

#[allow(unused_variables)]
fn classify(_ctx: &(), mail_info: &MailInfo) -> ClassifyResult {
    mail_info.accept("default")
}
