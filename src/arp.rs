use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use std::{fmt::Display, net::Ipv4Addr};

use log::{debug, error, info, warn};
use thiserror::Error;

use crate::ethernet::{self, EtherType, EthernetFrame, WithDstMacAddr};
use crate::host::{self, HOST_IP, HOST_MAC};
use crate::types::MacAddr;

pub(crate) static ARP_LAYER: OnceLock<ArpLayer> = OnceLock::new();

#[derive(Debug)]
#[non_exhaustive]
pub(crate) enum ArpPacketField {
    HardwareType,
    ProtocolType,
    HardwareSize,
    ProtocolSize,
    OpCode,
}

impl Display for ArpPacketField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let field = match self {
            ArpPacketField::HardwareType => "HardwareType",
            ArpPacketField::ProtocolType => "ProtocolType",
            ArpPacketField::HardwareSize => "HardwareSize",
            ArpPacketField::ProtocolSize => "ProtocolSize",
            ArpPacketField::OpCode => "OpCode",
        };
        write!(f, "{}", field)
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub(crate) enum ArpPacketError {
    #[error("malformed arp packet field: {0}: {1}")]
    MalformedField(ArpPacketField, Cow<'static, str>),
    #[error("malformed arp packet: {0}")]
    Malformed(Cow<'static, str>),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum OpCode {
    Request,
    Response,
}

impl Display for OpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpCode::Request => write!(f, "request"),
            OpCode::Response => write!(f, "response"),
        }
    }
}

impl From<OpCode> for u16 {
    fn from(value: OpCode) -> Self {
        match value {
            OpCode::Request => 0x0001,
            OpCode::Response => 0x0002,
        }
    }
}

impl TryFrom<u16> for OpCode {
    type Error = ArpPacketError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(OpCode::Request),
            0x0002 => Ok(OpCode::Response),
            _ => Err(ArpPacketError::MalformedField(
                ArpPacketField::OpCode,
                Cow::Owned(format!("0x{:04x}", value)),
            )),
        }
    }
}

impl TryFrom<[u8; 2]> for OpCode {
    type Error = ArpPacketError;

    fn try_from(value: [u8; 2]) -> Result<Self, Self::Error> {
        Self::try_from(u16::from_be_bytes(value))
    }
}

#[derive(Debug)]
pub(crate) struct ArpPacket {
    hardware_type: u16,
    protocol_type: u16,
    hardware_size: u8,
    protocol_size: u8,
    op_code: OpCode,
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
}

impl Display for ArpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ArpPacket(hardware_type={}, protocol_type={}, hardware_size={}, protocol_size={}, op_code={}, sender_mac={}, sender_ip={}, target_mac={}, target_ip={})",
            self.hardware_type,
            self.protocol_type,
            self.hardware_size,
            self.protocol_size,
            self.op_code,
            self.sender_mac,
            self.sender_ip,
            self.target_mac,
            self.target_ip
        )
    }
}

impl ArpPacket {
    fn new(
        hardware_type: u16,
        protocol_type: u16,
        hardware_size: u8,
        protocol_size: u8,
        op_code: OpCode,
        sender_mac: MacAddr,
        sender_ip: Ipv4Addr,
        target_mac: MacAddr,
        target_ip: Ipv4Addr,
    ) -> Self {
        if !host::check_if_within_network(&target_ip) {
            panic!("`target_ip` must be local network address");
        }

        if op_code == OpCode::Request && target_mac != MacAddr::zero() {
            panic!("`target_mac` must be zero");
        }

        Self {
            hardware_type,
            protocol_type,
            hardware_size,
            protocol_size,
            op_code,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        }
    }

    pub(crate) const SIZE: usize = 28;

    pub(crate) fn hardware_type(&self) -> u16 {
        self.hardware_type
    }

    pub(crate) fn protocol_type(&self) -> u16 {
        self.protocol_type
    }

    pub(crate) fn hardware_size(&self) -> u8 {
        self.hardware_size
    }

    pub(crate) fn protocol_size(&self) -> u8 {
        self.protocol_size
    }

    pub(crate) fn op_code(&self) -> &OpCode {
        &self.op_code
    }

    pub(crate) fn sender_mac(&self) -> &MacAddr {
        &self.sender_mac
    }

    pub(crate) fn sender_ip(&self) -> &Ipv4Addr {
        &self.sender_ip
    }

    pub(crate) fn target_mac(&self) -> &MacAddr {
        &self.target_mac
    }

    pub(crate) fn target_ip(&self) -> &Ipv4Addr {
        &self.target_ip
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut ret = Vec::with_capacity(Self::SIZE);
        ret.extend(u16::to_be_bytes(self.hardware_type));
        ret.extend(u16::to_be_bytes(self.protocol_type));
        ret.extend([self.hardware_size]);
        ret.extend([self.protocol_size]);
        ret.extend(u16::from(self.op_code).to_be_bytes());
        ret.extend(self.sender_mac.octets());
        ret.extend(self.sender_ip.octets());
        ret.extend(self.target_mac.octets());
        ret.extend(self.target_ip.octets());
        ret
    }
}

impl TryFrom<&EthernetFrame> for ArpPacket {
    type Error = ArpPacketError;

    fn try_from(value: &EthernetFrame) -> Result<Self, Self::Error> {
        if value.ether_type() != EtherType::Arp {
            return Err(ArpPacketError::Malformed(Cow::Borrowed(
                "this ethernet frame is not arp packet",
            )));
        }

        let payload = value.payload();
        if payload.len() < 28 {
            return Err(ArpPacketError::Malformed(Cow::Owned(format!(
                "this arp packet length is too short: {}",
                payload.len()
            ))));
        }

        let hardware_type = {
            let val = u16::from_be_bytes([payload[0], payload[1]]);
            if val != 0x0001 {
                return Err(ArpPacketError::MalformedField(
                    ArpPacketField::HardwareType,
                    Cow::Owned(format!(
                        "expected hardware_type for arp is 0x0001, but got 0x{:04x}",
                        val
                    )),
                ));
            }
            val
        };

        let protocol_type = {
            let val = u16::from_be_bytes([payload[2], payload[3]]);
            if val != 0x0800 {
                return Err(ArpPacketError::MalformedField(
                    ArpPacketField::ProtocolType,
                    Cow::Owned(format!(
                        "expected protocol_type for arp is 0x0800, but got 0x{:04x}",
                        val
                    )),
                ));
            }
            val
        };

        let hardware_size = match payload[4] {
            0x06 => 0x06,
            v => {
                return Err(ArpPacketError::MalformedField(
                    ArpPacketField::HardwareSize,
                    Cow::Owned(format!(
                        "expected hardware_size for arp is 0x06, but got 0x{:02x}",
                        v
                    )),
                ));
            }
        };

        let protocol_size = match payload[5] {
            0x04 => 0x04,
            v => {
                return Err(ArpPacketError::MalformedField(
                    ArpPacketField::ProtocolSize,
                    Cow::Owned(format!(
                        "expected protocol_size for arp is 0x04, but got 0x{:02x}",
                        v
                    )),
                ));
            }
        };

        let op_code = OpCode::try_from([payload[6], payload[7]])?;

        let sender_mac = MacAddr::from([
            payload[8],
            payload[9],
            payload[10],
            payload[11],
            payload[12],
            payload[13],
        ]);

        let sender_ip = Ipv4Addr::from([payload[14], payload[15], payload[16], payload[17]]);

        let target_mac = MacAddr::from([
            payload[18],
            payload[19],
            payload[20],
            payload[21],
            payload[22],
            payload[23],
        ]);

        let target_ip = Ipv4Addr::from([payload[24], payload[25], payload[26], payload[27]]);

        Ok(Self {
            hardware_type,
            protocol_type,
            hardware_size,
            protocol_size,
            op_code,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        })
    }
}

#[derive(Debug, Error)]
pub(crate) enum ArpRequestError {
    #[error("timeout: {0} seconds")]
    Timeout(u8),
    #[error("send error: {0}")]
    SendError(#[from] mpsc::SendError<ArpPacket>),
    #[error("target_ip is not in the local network address")]
    NotLocalAddress,
}

pub(crate) fn arp_request(
    target_ip: Ipv4Addr,
    timeout: Option<u8>,
) -> Result<MacAddr, ArpRequestError> {
    if !host::check_if_within_network(&target_ip) {
        return Err(ArpRequestError::NotLocalAddress);
    }

    let host_mac = *HOST_MAC.get().unwrap();
    let host_ip = *HOST_IP.get().unwrap();

    if target_ip == host_ip {
        return Ok(host_mac);
    }

    let arp_packet = ArpPacket::new(
        0x0001,
        0x0800,
        0x06,
        0x04,
        OpCode::Request,
        host_mac,
        host_ip,
        MacAddr::new([0x00; 6]),
        target_ip,
    );

    let (tx, rx) = mpsc::channel();

    let layer = ARP_LAYER.get().unwrap();
    layer.add_observer(tx);
    layer.send(arp_packet)?;

    let start = Instant::now();
    let result = loop {
        if let Some(secs) = timeout {
            if start.elapsed() > Duration::from_secs(secs as u64) {
                break Err(ArpRequestError::Timeout(secs));
            }
        }

        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(packet) => {
                if packet.op_code() == &OpCode::Response && packet.sender_ip == target_ip {
                    return Ok(packet.sender_mac);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => continue,
        }
    };

    result
}

#[derive(Debug)]
pub(crate) struct ArpLayer {
    sender: Sender<ArpPacket>,
    observers: Arc<Mutex<Vec<Sender<Arc<ArpPacket>>>>>,
    running: Arc<AtomicBool>,
    receive_thread_handle: Option<JoinHandle<()>>,
    send_thread_handle: Option<JoinHandle<()>>,
}

impl Drop for ArpLayer {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);

        if let Some(receive_thread_handle) = self.receive_thread_handle.take() {
            receive_thread_handle.join().unwrap();
        }
        if let Some(send_thread_handle) = self.send_thread_handle.take() {
            send_thread_handle.join().unwrap();
        }
    }
}

impl ArpLayer {
    pub(crate) fn start(
        ethernet_sender: impl Fn(
            WithDstMacAddr<ArpPacket>,
        ) -> Result<(), mpsc::SendError<EthernetFrame>>
        + Send
        + 'static,
        receiver: Receiver<Arc<EthernetFrame>>,
    ) -> Self {
        info!("Starting ARP layer");
        let observers = Arc::new(Mutex::new(Vec::<Sender<Arc<ArpPacket>>>::new()));
        let cloned_observers = Arc::clone(&observers);
        let running = Arc::new(AtomicBool::new(true));
        let r = Arc::clone(&running);

        let receive_thread_handle = thread::Builder::new()
            .name("arp_receive_tx".into())
            .spawn(move || {
                debug!("ARP receive thread started");

                while r.load(Ordering::Relaxed) {
                    if let Ok(frame) = receiver.recv_timeout(Duration::from_millis(100)) {
                        debug!("Processing Ethernet frame for ARP packet extraction");

                        if frame.ether_type() != EtherType::Arp {
                            continue;
                        }

                        let packet = match ArpPacket::try_from(&*frame) {
                            Ok(packet) => {
                                debug!("ARP packet parsed successfully: {}", packet);
                                packet
                            }
                            Err(e) => {
                                warn!("Failed to parse ARP packet: {}", e);
                                continue;
                            }
                        };

                        if *packet.op_code() == OpCode::Request {
                            continue;
                        }

                        let packet = Arc::new(packet);
                        let mut guard = cloned_observers.lock().unwrap();
                        guard.retain(|sender| sender.send(Arc::clone(&packet)).is_ok());

                        if packet.target_ip() == HOST_IP.get().unwrap() {
                            let reply = ArpPacket::new(
                                0x0001,
                                0x0800,
                                0x06,
                                0x04,
                                OpCode::Response,
                                *HOST_MAC.get().unwrap(),
                                *HOST_IP.get().unwrap(),
                                *packet.sender_mac(),
                                *packet.sender_ip(),
                            );

                            if let Err(e) = ARP_LAYER.get().unwrap().send(reply) {
                                warn!("Failed to ARP reply: {}", e);
                            }
                        }
                    }
                }
            })
            .unwrap();

        let r = Arc::clone(&running);
        let (tx, rx) = mpsc::channel::<ArpPacket>();
        let send_thread_handle = thread::Builder::new()
            .name("arp_send_tx".into())
            .spawn(move || {
                debug!("ARP send thread started");

                while r.load(Ordering::Relaxed) {
                    if let Ok(packet) = rx.recv_timeout(Duration::from_millis(100)) {
                        debug!("Sending ARP packet: {}", packet);
                        match ethernet_sender(WithDstMacAddr::new([0xff; 6].into(), packet)) {
                            Ok(_) => {
                                debug!("ARP packet sent successfully");
                            }
                            Err(e) => {
                                error!("Failed to send ARP packet: {}", e);
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
            receive_thread_handle: Some(receive_thread_handle),
            send_thread_handle: Some(send_thread_handle),
        }
    }

    pub(crate) fn add_observer(&self, observer: Sender<Arc<ArpPacket>>) {
        let mut guard = self.observers.lock().unwrap();
        guard.push(observer);
        debug!("Added ARP observer: total_count={}", guard.len());
    }

    pub(crate) fn send(&self, packet: ArpPacket) -> Result<(), mpsc::SendError<ArpPacket>> {
        self.sender.send(packet)
    }
}

pub(crate) fn make_ethernet_frame(arp_packet: &WithDstMacAddr<ArpPacket>) -> EthernetFrame {
    let dst_mac = arp_packet.dst_mac();
    ethernet::make_frame(dst_mac, EtherType::Arp, arp_packet.value().to_bytes())
}

pub(crate) fn setup(
    ethernet_sender: impl Fn(WithDstMacAddr<ArpPacket>) -> Result<(), mpsc::SendError<EthernetFrame>>
    + Send
    + 'static,
    receiver: Receiver<Arc<EthernetFrame>>,
) -> &'static ArpLayer {
    ARP_LAYER.get_or_init(|| ArpLayer::start(ethernet_sender, receiver))
}
