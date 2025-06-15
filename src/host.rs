use std::{net::Ipv4Addr, sync::OnceLock};

use crate::types::MacAddr;

pub(crate) static HOST_MAC: OnceLock<MacAddr> = OnceLock::new();
pub(crate) static HOST_IP: OnceLock<Ipv4Addr> = OnceLock::new();
pub(crate) static NETMASK: OnceLock<Ipv4Addr> = OnceLock::new();
pub(crate) static GATEWAY: OnceLock<Ipv4Addr> = OnceLock::new();

pub(crate) fn init(mac_addr: MacAddr, host_ip: Ipv4Addr, netmask: Ipv4Addr, gateway: Ipv4Addr) {
    HOST_MAC.get_or_init(|| mac_addr);
    HOST_IP.get_or_init(|| host_ip);
    NETMASK.get_or_init(|| netmask);
    GATEWAY.get_or_init(|| gateway);
}

pub(crate) fn netmask_from_prefix(prefix_len: u8) -> Ipv4Addr {
    if prefix_len > 32 {
        panic!("`prefix_len` must be between 0 and 32");
    }

    if prefix_len == 0 {
        Ipv4Addr::from(0)
    } else if prefix_len == 32 {
        Ipv4Addr::from([255, 255, 255, 255])
    } else {
        Ipv4Addr::from(u32::max_value() << (32 - prefix_len))
    }
}

fn _check_if_within_netwok(ip: &Ipv4Addr, gateway: &Ipv4Addr, netmask: &Ipv4Addr) -> bool {
    let from_gateway = gateway.to_bits() & netmask.to_bits();
    let from_ip = ip.to_bits() & netmask.to_bits();
    from_gateway == from_ip
}

/// This function is only exposed within the crate and assumes that
/// init() has been called before execution
pub(crate) fn check_if_within_network(ip: &Ipv4Addr) -> bool {
    _check_if_within_netwok(ip, GATEWAY.get().unwrap(), NETMASK.get().unwrap())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_netmask_from_prefix() {
        assert_eq!(netmask_from_prefix(0), Ipv4Addr::from([0, 0, 0, 0]));
        assert_eq!(netmask_from_prefix(8), Ipv4Addr::from([255, 0, 0, 0]));
        assert_eq!(netmask_from_prefix(16), Ipv4Addr::from([255, 255, 0, 0]));
        assert_eq!(netmask_from_prefix(20), Ipv4Addr::from([255, 255, 240, 0]));
        assert_eq!(netmask_from_prefix(24), Ipv4Addr::from([255, 255, 255, 0]));
        assert_eq!(
            netmask_from_prefix(32),
            Ipv4Addr::from([255, 255, 255, 255])
        );
    }

    #[test]
    fn test_check_if_within_netwok() {
        assert_eq!(
            _check_if_within_netwok(
                &Ipv4Addr::from([192, 168, 10, 10]),
                &Ipv4Addr::from([192, 168, 10, 1]),
                &Ipv4Addr::from([255, 255, 255, 0])
            ),
            true
        );

        assert_eq!(
            _check_if_within_netwok(
                &Ipv4Addr::from([8, 8, 8, 8]),
                &Ipv4Addr::from([192, 168, 10, 1]),
                &Ipv4Addr::from([255, 255, 255, 0])
            ),
            false
        );

        assert_eq!(
            _check_if_within_netwok(
                &Ipv4Addr::from([172, 16, 18, 3]),
                &Ipv4Addr::from([172, 16, 0, 1]),
                &Ipv4Addr::from([255, 255, 0, 0])
            ),
            true
        );

        // 20 bits mask
        assert_eq!(
            _check_if_within_netwok(
                &Ipv4Addr::from([172, 16, 200, 3]),
                &Ipv4Addr::from([172, 16, 201, 1]),
                &Ipv4Addr::from([255, 255, 240, 0])
            ),
            true
        );
    }
}
