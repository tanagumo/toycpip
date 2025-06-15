use std::borrow::Cow;
use std::sync::mpsc::{self, SendError};
use std::time::{Duration, Instant};
use std::{fmt::Display, net::Ipv4Addr};

use thiserror::Error;

use crate::ethernet::{ETHERNET_LAYER, EtherType, EthernetFrame};
use crate::host::{HOST_IP, HOST_MAC};
use crate::types::MacAddr;

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

impl ArpPacket {
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
    SendError(#[from] SendError<EthernetFrame>),
}

pub(crate) fn arp_request(
    target_ip: Ipv4Addr,
    timeout: Option<u8>,
) -> Result<MacAddr, ArpRequestError> {
    let host_mac = *HOST_MAC.get().unwrap();
    let host_ip = *HOST_IP.get().unwrap();

    let packet = ArpPacket {
        hardware_type: 0x0001,
        protocol_type: 0x0800,
        hardware_size: 0x06,
        protocol_size: 0x04,
        op_code: OpCode::Request,
        sender_mac: host_mac,
        sender_ip: host_ip,
        target_mac: MacAddr::new([0x00; 6]),
        target_ip,
    };

    let frame = EthernetFrame::new(
        MacAddr::new([0xff; 6]),
        host_mac,
        EtherType::Arp,
        packet.to_bytes(),
    );

    let (tx, rx) = mpsc::channel();

    let layer = ETHERNET_LAYER.get().unwrap();
    layer.add_observer(tx);
    layer.send(frame)?;

    let start = Instant::now();
    let result = loop {
        if let Some(secs) = timeout {
            if start.elapsed() > Duration::from_secs(secs as u64) {
                break Err(ArpRequestError::Timeout(secs));
            }
        }

        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(frame) => {
                if let Ok(packet) = TryInto::<ArpPacket>::try_into(&*frame) {
                    if packet.op_code() == &OpCode::Response && packet.sender_ip == target_ip {
                        return Ok(packet.sender_mac);
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => continue,
        }
    };

    result
}
