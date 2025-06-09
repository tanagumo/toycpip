use std::{net::Ipv4Addr, sync::OnceLock};

use crate::types::MacAddr;

pub static HOST_MAC: OnceLock<MacAddr> = OnceLock::new();
pub static HOST_IP: OnceLock<Ipv4Addr> = OnceLock::new();
pub static HOST_GATEWAY: OnceLock<Ipv4Addr> = OnceLock::new();

pub fn init(host_mac: MacAddr, host_ip: Ipv4Addr, host_gateway: Ipv4Addr) {
    HOST_MAC.get_or_init(|| host_mac);
    HOST_IP.get_or_init(|| host_ip);
    HOST_GATEWAY.get_or_init(|| host_gateway);
}
