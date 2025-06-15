mod arp;
mod ethernet;
mod host;
mod icmp;
mod ip;
mod types;
mod utils;

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::mpsc,
};

use pnet::datalink::{self, NetworkInterface};
use thiserror;

use crate::ethernet::EthernetLayer;
use crate::icmp::PingResult;
use crate::types::MacAddr;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InterfaceError {
    #[error("MAC address not available for interface")]
    MacNotFound,
    #[error("IPv4 address not found for interface")]
    Ipv4NotFound,
    #[error("specified network interface not found")]
    InterfaceNotFound,
}

fn extract_interface_info_detailed(
    interface: &NetworkInterface,
) -> Result<(MacAddr, Ipv4Addr, Ipv4Addr), InterfaceError> {
    let mac_addr = interface.mac.ok_or(InterfaceError::MacNotFound)?;

    let mac_addr = MacAddr::new([
        mac_addr.0, mac_addr.1, mac_addr.2, mac_addr.3, mac_addr.4, mac_addr.5,
    ]);

    let (ipv4_addr, netmask) = interface
        .ips
        .iter()
        .find_map(|ip_network| match ip_network.ip() {
            IpAddr::V4(ipv4) if !ipv4.is_loopback() => {
                let prefix_len = ip_network.prefix();
                Some((ipv4, host::netmask_from_prefix(prefix_len)))
            }
            _ => None,
        })
        .ok_or(InterfaceError::Ipv4NotFound)?;

    Ok((mac_addr, ipv4_addr, netmask))
}

fn make_ethernet_sender(
    ethernet_layer: &'static EthernetLayer,
) -> impl Fn(ip::IpPacket) -> Result<(), ip::SendError> {
    |ip_packet: ip::IpPacket| {
        let frame = ip::make_ethernet_frame(&ip_packet)?;
        ethernet_layer.send(frame)?;
        Ok(())
    }
}

pub fn setup(
    interface: NetworkInterface,
    gateway: impl Into<Ipv4Addr>,
) -> Result<(), InterfaceError> {
    let (mac_addr, ip, netmask) = extract_interface_info_detailed(&interface)?;

    host::init(mac_addr, ip, netmask, gateway.into());
    let ethernet_layer = ethernet::setup(&interface);

    let (tx, rx) = mpsc::channel();
    ethernet_layer.add_observer(tx);
    ip::setup(make_ethernet_sender(ethernet_layer), rx);

    Ok(())
}

pub fn arp_request(
    ip: impl Into<Ipv4Addr>,
    timeout: Option<u8>,
) -> Result<MacAddr, Box<dyn std::error::Error>> {
    Ok(arp::arp_request(ip.into(), timeout).map_err(|e| format!("{}", e))?)
}

pub fn get_network_interface(name: &str) -> Result<NetworkInterface, InterfaceError> {
    Ok(datalink::interfaces()
        .into_iter()
        .filter(|iface: &NetworkInterface| iface.name == name)
        .next()
        .ok_or(InterfaceError::InterfaceNotFound)?)
}

pub fn send_icmp_request(
    dst_ip: impl Into<Ipv4Addr>,
    sequence: u16,
) -> Result<PingResult, Box<dyn std::error::Error>> {
    let dst_ip = dst_ip.into();
    Ok(icmp::send_icmp_echo_request(dst_ip, sequence, None, None).map_err(|e| format!("{}", e))?)
}
