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

// https://docs.spamhaus.com/datasets/docs/source/10-data-type-documentation/datasets/040-zones.html
// zone zen: SBL+, XBL+ , PBL

fn reject_on_any_ip(ip: Ipv4Addr) -> bool {
    const ZEN_2: u32 = Ipv4Addr::new(127, 0, 0, 2).to_bits();
    const ZEN_3: u32 = Ipv4Addr::new(127, 0, 0, 3).to_bits();
    const ZEN_4: u32 = Ipv4Addr::new(127, 0, 0, 4).to_bits();
    const ZEN_10: u32 = Ipv4Addr::new(127, 0, 0, 10).to_bits();
    const ZEN_11: u32 = Ipv4Addr::new(127, 0, 0, 11).to_bits();
    match ip.to_bits() {
        ZEN_2 => false,  // SBL manually maintained list of abuse-related resources
        ZEN_3 => false,  // CSS  automated sublist, listing SMTP emitters associated with a low reputation or confirmed abuse
        ZEN_4 => true,   // XBL IPs that have recently been observed hosting compromised hosts
        ZEN_10 => false, // PBL dynamic and low-security IP space, indicated directly by the ISP
        ZEN_11 => false, // PBL dynamic and low-security IP space, inferred by Spamjaus
        _ => false,
    }
}

fn reject_on_first_ip(ip: Ipv4Addr) -> bool {
    const ZEN_2: u32 = Ipv4Addr::new(127, 0, 0, 2).to_bits();
    const ZEN_3: u32 = Ipv4Addr::new(127, 0, 0, 3).to_bits();
    const ZEN_4: u32 = Ipv4Addr::new(127, 0, 0, 4).to_bits();
    const ZEN_10: u32 = Ipv4Addr::new(127, 0, 0, 10).to_bits();
    const ZEN_11: u32 = Ipv4Addr::new(127, 0, 0, 11).to_bits();
    match ip.to_bits() {
        ZEN_2 => false,  // SBL manually maintained list of abuse-related resources
        ZEN_3 => false,  // CSS  automated sublist, listing SMTP emitters associated with a low reputation or confirmed abuse
        ZEN_4 => true,   // XBL IPs that have recently been observed hosting compromised hosts
        ZEN_10 => false, // PBL dynamic and low-security IP space, indicated directly by the ISP
        ZEN_11 => false, // PBL dynamic and low-security IP space, inferred by Spamjaus
        _ => false,
    }
}

fn lookup_ip(ip: IpAddr) -> Vec<Ipv4Addr> {
    let lookup = match ip {
        IpAddr::V4(ip) => spamhaus_v4(ip),
        IpAddr::V6(ip) => spamhaus_v6(ip),
    };
    let mut out: Vec<Ipv4Addr> = Vec::new();
    if let Ok(sal) = format!("{lookup}:0").to_socket_addrs() {
        for sa in sal {
            if let IpAddr::V4(ipv4) = sa.ip() {
                out.push(ipv4);
            }
        }
    }
    out
}

pub fn ip_in_spamhaus_zen<Iter: Iterator<Item = IpAddr>>(
    mail_info: &MailInfo,
    mut ips: Iter,
) -> bool {
    let mut ret = false;
    let r = ips.next();
    if let Some(first_ip) = r {
        for response_ip in lookup_ip(first_ip) {
            if reject_on_first_ip(response_ip) {
                log!(
                    mail_info,
                    "spamhaus reject first ip {first_ip}: {response_ip}"
                );
                ret = true;
            } else {
                log!(
                    mail_info,
                    "spamhaus ignore first ip {first_ip}: {response_ip}"
                );
            }
        }
    }
    for ip in ips {
        for response_ip in lookup_ip(ip) {
            if reject_on_any_ip(response_ip) {
                log!(mail_info, "spamhaus reject ip {ip}: {response_ip}");
                ret = true;
            } else {
                log!(mail_info, "spamhaus ignore ip {ip}: {response_ip}");
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
