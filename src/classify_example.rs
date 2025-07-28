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

      log!(mail_info, ...)          as println! but queue id automatically prefixed

      quarantine!(mail_info, ...)   log and return with Quarantine status. Log defaults to file and line number
      accept!(mail_info, ...)       log and return with Accept status. Log defaults to file and line number
      reject!(mail_info, ...)       log and return with Reject. Log defaults to file and line number

      regex_is_match!    from lazy_regex
*/

    if regex_is_match!("Täääst", subject) {
        quarantine!(mail_info);
    }

    if !mail_info.get_other_header("X-Mailru-Msgtype").is_empty() {
        if from_address.ends_with("@iscb.org") || from_address.ends_with("@news.arraystar.com") {
            accept!(mail_info);
        }
        quarantine!(mail_info);
    }

    if regex_is_match!("for your business", text) {
        quarantine!(mail_info);
    }

} /* bracket required */
