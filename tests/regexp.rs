use lazy_regex::regex_is_match;

#[test]
fn test_bla() {

    let subject = "[bla] ﺖﻓﺎﺼﻴﻟ ﺖﺴﺠﻴﻟ ﺎﻟﺪﺧﻮﻟ";
    let r = regex_is_match!(r"(?x)
        ^\[.+\]\ (
            Anmeldedaten
            | Login\ Details
            | Данные\ для\ входа\ на\ сайт
            | Giriş\ Detayları
            | Detalle\ de\ Acceso
            | ﺖﻓﺎﺼﻴﻟ\ ﺖﺴﺠﻴﻟ\ ﺎﻟﺪﺧﻮﻟ
            | placeholder
        )$", subject);
    assert_eq!(r, true);

}
