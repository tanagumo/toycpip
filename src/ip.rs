use std::borrow::Cow;
use std::fmt::Display;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use fastrand;
use log::{debug, error, info, warn};
use thiserror::Error;

use crate::arp::{self, ArpRequestError};
use crate::ethernet::{self, EtherType, EthernetFrame};
use crate::host;
use crate::utils;

pub(crate) static IP_LAYER: OnceLock<IpLayer> = OnceLock::new();

#[derive(Debug, Error)]
#[non_exhaustive]
pub(crate) enum IpPacketError {
    #[error("malformed ip packet: {0}")]
    Malformed(Cow<'static, str>),
    #[error("checksum mismatch: calculated: {0}, actual: {1}")]
    ChecksumMismatch(u16, u16),
    #[error("ihl must be greater than or equal to 5, but got {0}")]
    IhlTooSmall(u8),
    #[error("ttl must be greater than 0")]
    TtlTooSmall,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum Protocol {
    ICMP,
    TCP,
    UDP,
    Other(u8),
}

impl Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Protocol::ICMP => Cow::Borrowed("ICMP"),
            Protocol::TCP => Cow::Borrowed("TCP"),
            Protocol::UDP => Cow::Borrowed("UDP"),
            Protocol::Other(n) => Cow::Owned(format!("Other({})", n)),
        };
        write!(f, "{}", value)
    }
}

impl Into<u8> for Protocol {
    fn into(self) -> u8 {
        match self {
            Protocol::ICMP => 1,
            Protocol::TCP => 6,
            Protocol::UDP => 17,
            Protocol::Other(n) => n,
        }
    }
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            1 => Protocol::ICMP,
            6 => Protocol::TCP,
            17 => Protocol::UDP,
            n => Protocol::Other(n),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct Version(u8);

impl Version {
    fn new(value: u8) -> Self {
        if value >= 0x10 {
            panic!(
                "The value of `version` must be smaller than 0x10, but got 0x{:02x}",
                value
            );
        }
        Self(value)
    }

    fn as_u8(&self) -> u8 {
        self.0
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct Ihl(u8);

impl Ihl {
    /// Ihl instances are only created from IpPacket with the assumption that
    /// constraint violations for Ihl, specifically cases where the value is less than 5,
    /// are considered program bugs and will cause a panic
    fn new(value: u8) -> Self {
        if value < 5 {
            panic!(
                "the value of `ihl` must be greater than or equal to 0x05, but got 0x{:02x}",
                value
            );
        }
        if value >= 0x10 {
            panic!(
                "the value of `ihl` must be smaller than 0x10, but got 0x{:02x}",
                value
            );
        }
        Self(value)
    }

    fn as_u8(&self) -> u8 {
        self.0
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct Flag(u8);

impl Flag {
    fn new(value: u8) -> Self {
        if value >= 0x08 {
            panic!(
                "the value of `flag` must be smaller than 0x08, but got 0x{:02x}",
                value
            );
        }
        Self(value)
    }

    fn as_u8(&self) -> u8 {
        self.0
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct FragmentOffset(u16);

impl FragmentOffset {
    fn new(value: u16) -> Self {
        if value >= 0x2000 {
            panic!(
                "the value of `fragment_offset` must be smaller than 0x2000, but got 0x{:04x}",
                value
            );
        }
        Self(value)
    }

    fn as_u16(&self) -> u16 {
        self.0
    }

    fn as_array(&self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

#[derive(Debug)]
pub(crate) struct IpPacket {
    version: Version,
    ihl: Ihl,
    type_of_service: u8,
    total_length: u16,
    identification: u16,
    flag: Flag,
    fragment_offset: FragmentOffset,
    ttl: u8,
    protocol: Protocol,
    header_checksum: u16,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    padding: Vec<u8>,
    payload: Vec<u8>,
}

impl IpPacket {
    fn new(
        version: Version,
        ihl: Ihl,
        type_of_service: u8,
        total_length: u16,
        identification: u16,
        flag: Flag,
        fragment_offset: FragmentOffset,
        ttl: u8,
        protocol: Protocol,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        payload: Vec<u8>,
    ) -> Self {
        if version.as_u8() != 4 {
            panic!(
                "the value of `version` must be 0x04, but got 0x{:02x}",
                version.as_u8()
            );
        }
        if ihl.as_u8() != 5 {
            panic!(
                "the value of ihl must be 0x05, but got 0x{:02x}",
                ihl.as_u8()
            );
        }
        if total_length as usize != 20 + payload.len() {
            panic!(
                "the value of `total_length` must be {}, but got {}",
                20 + payload.len(),
                total_length
            );
        }
        if ttl == 0 {
            panic!("TTL must be greater than 0, but got {}", ttl);
        }

        let mut ip_packet = Self {
            version,
            ihl,
            type_of_service,
            total_length,
            identification,
            flag,
            fragment_offset,
            ttl,
            protocol,
            header_checksum: 0,
            src_ip,
            dst_ip,
            padding: vec![],
            payload,
        };

        ip_packet.header_checksum = ip_packet.calc_checksum();
        ip_packet
    }

    fn calc_checksum(&self) -> u16 {
        let total_length_array = self.total_length.to_be_bytes();
        let identification_array = self.identification.to_be_bytes();
        let flag_and_fragment_offset_array = {
            let value = (self.flag.as_u8() as u16) << 13
                | self.fragment_offset.as_u16() & 0b00011111_11111111;
            value.to_be_bytes()
        };
        let header_checksum_array = self.header_checksum.to_be_bytes();
        let src_ip_array = self.src_ip.octets();
        let dst_ip_array = self.dst_ip.octets();

        let array = [
            (self.version.as_u8() << 4) | (self.ihl.as_u8() & 0b0000_1111),
            self.type_of_service,
            total_length_array[0],
            total_length_array[1],
            identification_array[0],
            identification_array[1],
            flag_and_fragment_offset_array[0],
            flag_and_fragment_offset_array[1],
            self.ttl,
            self.protocol.into(),
            header_checksum_array[0],
            header_checksum_array[1],
            src_ip_array[0],
            src_ip_array[1],
            src_ip_array[2],
            src_ip_array[3],
            dst_ip_array[0],
            dst_ip_array[1],
            dst_ip_array[2],
            dst_ip_array[3],
        ];

        utils::calculate_checksum(&array, Some(10)).unwrap()
    }

    pub(crate) fn version(&self) -> Version {
        self.version
    }

    pub(crate) fn ihl(&self) -> Ihl {
        self.ihl
    }

    pub(crate) fn type_of_service(&self) -> u8 {
        self.type_of_service
    }

    pub(crate) fn total_length(&self) -> u16 {
        self.total_length
    }

    pub(crate) fn identification(&self) -> u16 {
        self.identification
    }

    pub(crate) fn flag(&self) -> Flag {
        self.flag
    }

    pub(crate) fn fragment_offset(&self) -> FragmentOffset {
        self.fragment_offset
    }

    pub(crate) fn ttl(&self) -> u8 {
        self.ttl
    }

    pub(crate) fn protocol(&self) -> Protocol {
        self.protocol
    }

    pub(crate) fn header_checksum(&self) -> u16 {
        self.header_checksum
    }

    pub(crate) fn src_ip(&self) -> Ipv4Addr {
        self.src_ip
    }

    pub(crate) fn dst_ip(&self) -> Ipv4Addr {
        self.dst_ip
    }

    pub(crate) fn padding(&self) -> &[u8] {
        &self.padding
    }

    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let capacity = 20 + self.padding.len() + self.payload.len();

        let mut v = Vec::with_capacity(capacity);

        let total_length_array = self.total_length.to_be_bytes();
        let ident_array = self.identification.to_be_bytes();
        let flag_and_offset_array = ((self.flag.as_u8() as u16) << 13
            | self.fragment_offset.as_u16() & 0b00011111_11111111)
            .to_be_bytes();
        let header_checksum_array = self.header_checksum.to_be_bytes();
        let src_ip_array = self.src_ip.to_bits().to_be_bytes();
        let dst_ip_array = self.dst_ip.to_bits().to_be_bytes();

        // Minimize the number of extend calls for performance optimization
        v.extend([
            (self.version.as_u8() << 4) | (self.ihl.as_u8() & 0b0000_1111),
            self.type_of_service,
            total_length_array[0],
            total_length_array[1],
            ident_array[0],
            ident_array[1],
            flag_and_offset_array[0],
            flag_and_offset_array[1],
            self.ttl,
            self.protocol.into(),
            header_checksum_array[0],
            header_checksum_array[1],
            src_ip_array[0],
            src_ip_array[1],
            src_ip_array[2],
            src_ip_array[3],
            dst_ip_array[0],
            dst_ip_array[1],
            dst_ip_array[2],
            dst_ip_array[3],
        ]);
        v.extend(self.padding());
        v.extend(self.payload());
        v
    }
}

impl Display for IpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "IPv{} {} -> {} ({})",
            self.version.as_u8(),
            self.src_ip,
            self.dst_ip,
            self.protocol,
        )
    }
}

impl TryFrom<&EthernetFrame> for IpPacket {
    type Error = IpPacketError;

    fn try_from(value: &EthernetFrame) -> Result<Self, Self::Error> {
        if value.ether_type() != EtherType::IpV4 {
            return Err(IpPacketError::Malformed(Cow::Borrowed(
                "this ethernet frame is not ip packet",
            )));
        }

        let payload = value.payload();
        if payload.len() < 20 {
            return Err(IpPacketError::Malformed(Cow::Owned(format!(
                "this ip packet length is too short: {}",
                payload.len()
            ))));
        }

        let version = Version::new(payload[0] >> 4);
        let ihl_value = payload[0] & 0b00001111;
        if ihl_value < 5 {
            return Err(IpPacketError::IhlTooSmall(ihl_value));
        }
        let ihl = Ihl::new(ihl_value);
        let type_of_service = payload[1];
        let header_length = (ihl_value as usize) * 4;

        let total_length = u16::from_be_bytes([payload[2], payload[3]]);
        let identification = u16::from_be_bytes([payload[4], payload[5]]);

        // flag and fragment_offset are in consecutive 2 bytes,
        // where the first 3 bits are flag and the remaining 13 bits are fragment_offset
        let flag = Flag::new(payload[6] >> 5);
        let fragment_offset =
            FragmentOffset::new(u16::from_be_bytes([payload[6], payload[7]]) & 0b00011111_11111111);

        let ttl = payload[8];
        let protocol = Protocol::from(payload[9]);

        let header_checksum = u16::from_be_bytes([payload[10], payload[11]]);

        let src_ip = Ipv4Addr::from([payload[12], payload[13], payload[14], payload[15]]);
        let dst_ip = Ipv4Addr::from([payload[16], payload[17], payload[18], payload[19]]);

        let calculated_checksum =
            utils::calculate_checksum(&payload[..header_length], Some(10)).unwrap();

        if calculated_checksum != header_checksum {
            return Err(IpPacketError::ChecksumMismatch(
                calculated_checksum,
                header_checksum,
            ));
        }

        Ok(Self {
            version,
            ihl,
            type_of_service,
            total_length,
            identification,
            flag,
            fragment_offset,
            ttl,
            protocol,
            header_checksum,
            src_ip,
            dst_ip,
            padding: payload[20..header_length].to_vec(),
            payload: payload[header_length..].to_vec(),
        })
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub(crate) enum SendError {
    #[error("failed to send packet")]
    SendError(#[from] mpsc::SendError<EthernetFrame>),
    #[error("failed to arp request: {0}")]
    ArpRequest(#[from] ArpRequestError),
}

#[derive(Debug)]
pub(crate) struct IpLayer {
    sender: Sender<IpPacket>,
    observers: Arc<Mutex<Vec<Sender<Arc<IpPacket>>>>>,
    running: Arc<AtomicBool>,
    observe_thread_handle: Option<JoinHandle<()>>,
    send_thread_handle: Option<JoinHandle<()>>,
}

impl Drop for IpLayer {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);

        if let Some(observe_thread_handle) = self.observe_thread_handle.take() {
            observe_thread_handle.join().unwrap();
        }
        if let Some(send_thread_handle) = self.send_thread_handle.take() {
            send_thread_handle.join().unwrap();
        }
    }
}

impl IpLayer {
    pub(crate) fn start(
        ethernet_sender: impl Fn(IpPacket) -> Result<(), SendError> + Send + 'static,
        receiver: Receiver<Arc<EthernetFrame>>,
    ) -> Self {
        info!("Starting IP layer");
        let observers = Arc::new(Mutex::new(Vec::<Sender<Arc<IpPacket>>>::new()));
        let cloned_observers = Arc::clone(&observers);
        let running = Arc::new(AtomicBool::new(true));
        let r = Arc::clone(&running);

        let observe_thread_handle = thread::Builder::new()
            .name("ip_observe_tx".into())
            .spawn(move || {
                debug!("IP receive thread started");

                while r.load(Ordering::Relaxed) {
                    if let Ok(frame) = receiver.recv_timeout(Duration::from_millis(100)) {
                        debug!("Processing Ethernet frame for IP packet extraction");

                        if frame.ether_type() != EtherType::IpV4 {
                            continue;
                        }

                        let packet = match IpPacket::try_from(&*frame) {
                            Ok(packet) => {
                                debug!(
                                    "IP packet parsed successfully: src={}, dst={}, protocol={}",
                                    packet.src_ip(),
                                    packet.dst_ip(),
                                    packet.protocol()
                                );
                                packet
                            }
                            Err(e) => {
                                warn!("Failed to parse IP packet: {}", e);
                                continue;
                            }
                        };
                        let packet = Arc::new(packet);
                        let mut guard = cloned_observers.lock().unwrap();
                        guard.retain(|sender| sender.send(Arc::clone(&packet)).is_ok());
                    }
                }
            })
            .unwrap();

        let r = Arc::clone(&running);
        let (tx, rx) = mpsc::channel::<IpPacket>();
        let send_thread_handle = thread::Builder::new()
            .name("ip_send_tx".into())
            .spawn(move || {
                debug!("IP send thread started");

                while r.load(Ordering::Relaxed) {
                    if let Ok(packet) = rx.recv_timeout(Duration::from_millis(100)) {
                        debug!(
                            "Sending IP packet: src={}, dst={}, protocol={}",
                            packet.src_ip(),
                            packet.dst_ip(),
                            packet.protocol()
                        );
                        match ethernet_sender(packet) {
                            Ok(_) => {
                                debug!("IP packet sent successfully");
                            }
                            Err(e) => {
                                error!("Failed to send IP packet: {}", e);
                            }
                        }
                    }
                }
            })
            .unwrap();

        Self {
            sender: tx,
            observers,
            running,
            observe_thread_handle: Some(observe_thread_handle),
            send_thread_handle: Some(send_thread_handle),
        }
    }

    pub(crate) fn add_observer(&self, observer: Sender<Arc<IpPacket>>) {
        let mut guard = self.observers.lock().unwrap();
        guard.push(observer);
        debug!("Added IP observer: total_count={}", guard.len());
    }

    pub(crate) fn send(&self, packet: IpPacket) -> Result<(), mpsc::SendError<IpPacket>> {
        self.sender.send(packet)
    }
}

pub(crate) fn setup(
    ethernet_sender: impl Fn(IpPacket) -> Result<(), SendError> + Send + 'static,
    receiver: Receiver<Arc<EthernetFrame>>,
) -> &'static IpLayer {
    IP_LAYER.get_or_init(|| IpLayer::start(ethernet_sender, receiver))
}

pub(crate) fn make_ethernet_frame(ip_packet: &IpPacket) -> Result<EthernetFrame, ArpRequestError> {
    let dst_ip = ip_packet.dst_ip();
    let dst_mac = if host::check_if_within_network(&dst_ip) {
        arp::arp_request(dst_ip, Some(1))?
    } else {
        let gateway = host::GATEWAY.get().unwrap();
        arp::arp_request(*gateway, Some(1))?
    };

    Ok(ethernet::make_frame(
        dst_mac,
        EtherType::IpV4,
        ip_packet.to_bytes(),
    ))
}

pub(crate) fn make_ip_packet(
    ttl: u8,
    protocol: Protocol,
    dst_ip: impl Into<Ipv4Addr>,
    payload: Vec<u8>,
) -> Result<IpPacket, IpPacketError> {
    if ttl == 0 {
        Err(IpPacketError::TtlTooSmall)
    } else {
        Ok(IpPacket::new(
            Version::new(4),
            Ihl::new(5),
            0,
            20 + payload.len() as u16,
            fastrand::u16(..),
            Flag::new(2),
            FragmentOffset::new(0),
            ttl,
            protocol,
            *host::HOST_IP.get().unwrap(),
            dst_ip.into(),
            payload,
        ))
    }
}
