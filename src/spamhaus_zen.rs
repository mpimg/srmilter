use crate::{MailInfo, log};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::net::ToSocketAddrs;

fn nibble_to_ascii(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        10..=15 => b'a' + (n - 10), // use b'A' for uppercase
        _ => panic!("nibble_to_ascii called with value > 15"),
    }
}

const SPAMHAUS_POSTFIX: &[u8; 16] = b"zen.spamhaus.org";

fn spamhaus_v4(ip: Ipv4Addr) -> String {
    let octets = ip.octets();
    format!(
        "{}.{}.{}.{}.zen.spamhaus.org",
        octets[3], octets[2], octets[1], octets[0]
    )
}

fn spamhaus_v6(ip: Ipv6Addr) -> String {
    let octets = ip.octets();
    let mut out: Vec<u8> = Vec::with_capacity(16 * 4 + SPAMHAUS_POSTFIX.len());
    for o in octets.into_iter().rev() {
        out.push(nibble_to_ascii(o & 0x0f));
        out.push(b'.');
        out.push(nibble_to_ascii(o >> 4));
        out.push(b'.');
    }
    out.extend_from_slice(&SPAMHAUS_POSTFIX.clone());
    String::from_utf8_lossy(&out).into_owned()
}

pub fn in_spamhaus_zen(mail_info: &MailInfo) -> bool {
    let mut ret = false;
    for ip in mail_info.recevied_ip_iter() {
        let lookup = match ip {
            IpAddr::V4(ip) => spamhaus_v4(ip),
            IpAddr::V6(ip) => spamhaus_v6(ip),
        };
        if let Ok(sal) = format!("{lookup}:0").to_socket_addrs() {
            for sa in sal {
                log!(&mail_info, "Spamhaus zen: {ip}: {}", sa.ip());
                ret = true;
            }
        }
    }
    ret
}

#[test]
fn test_format() {
    assert_eq!(
        spamhaus_v4(Ipv4Addr::new(127, 0, 0, 1)),
        "1.0.0.127.zen.spamhaus.org"
    );

    let addr = Ipv6Addr::new(0x2001, 0xdb8, 0x7ca6, 0x22, 0, 0, 0, 0x45); // 2001:db8:7ca6:22::45
    assert_eq!(
        spamhaus_v6(addr),
        "5.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.2.0.0.6.a.c.7.8.b.d.0.1.0.0.2.zen.spamhaus.org"
    );
}
