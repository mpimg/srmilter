{ /* bracket required */

    // file format subject to change!



    if regex_is_match!("Täääst", subject) {
        quarantine!();
    }

    if msg
        .header(HeaderName::Other(Borrowed("X-Mailru-Msgtype")))
        .is_some()
    {
        if from_address.ends_with("@iscb.org") || from_address.ends_with("@news.arraystar.com") {
            accept!();
        } else {
            quarantine!();
        }
    }

    if regex_is_match!("for your business", text) {
        quarantine!();
    }

} /* bracket required */
