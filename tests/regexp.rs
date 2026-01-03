use lazy_regex::regex_is_match;

#[test]
fn test_wordpress() {
    let subject = "[Armoni Scans] Oturum açma bilgileri";
    let r = regex_is_match!(
        r"(?x)
        ^\[.+\]\ (
            Anmeldedaten
            | Login\ Details
            | Данные\ для\ входа\ на\ сайт
            | Giriş\ Detayları
            | Detalle\ de\ Acceso
            | ﺖﻓﺎﺼﻴﻟ\ ﺖﺴﺠﻴﻟ\ ﺎﻟﺪﺧﻮﻟ
            | Detalle\ de\ Acceso
            | Oturum\ açma\ bilgileri

        )$",
        subject
    );
    assert!(r);
}
