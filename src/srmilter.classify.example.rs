/* */ {

if regex_is_match!("Täääst", subject) {
    return ClassifyResult::Quarantine;
}

if msg
    .header(HeaderName::Other(Borrowed("X-Mailru-Msgtype")))
    .is_some()
{
    if from_address.ends_with("@iscb.org") || from_address.ends_with("@news.arraystar.com") {
        return ClassifyResult::Accept;
    } else {
        return ClassifyResult::Quarantine;
    }
}

/* */ }
