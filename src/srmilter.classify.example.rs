{ /* bracket required */

/*
    file format subject to change!

    available data:

      id                 postfix queue ident or "test" or ""

      sender             envelope sender (if known) or ""
      recipients         envelope recipients ( &Vec<&String> )

      from_address       address part of first or only From Address or ""
      subject            Subject or ""
      text               message text (text/plain alternative or converted text/html)

      msg                &mail_parser::Message

    available macros:

      log!(...)          as println! but queue id automatically prefixed

      quarantine!(...)   log and return with Quarantine status. Log defaults to file and line number
      accept!(...)       log and return with Accept status. Log defaults to file and line number
      reject!(...)       log and return with Reject. Log defaults to file and line number

      regex_is_match!    from lazy_regex
*/

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
