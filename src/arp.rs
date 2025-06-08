use std::borrow::Cow;
use std::{fmt::Display, net::Ipv4Addr};

use thiserror::Error;

use crate::ethernet::{EtherType, EthernetFrame};
use crate::types::MacAddr;

#[derive(Debug)]
#[non_exhaustive]
pub enum ArpPacketField {
    HardwareType,
    ProtocolType,
    HardwareSize,
    ProtocolSize,
    OpCode,
    SenderMac,
    SenderIp,
    TargetMac,
    TargetIp,
}

impl Display for ArpPacketField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let field = match self {
            ArpPacketField::HardwareType => "HardwareType",
            ArpPacketField::ProtocolType => "ProtocolType",
            ArpPacketField::HardwareSize => "HardwareSize",
            ArpPacketField::ProtocolSize => "ProtocolSize",
            ArpPacketField::OpCode => "OpCode",
            ArpPacketField::SenderMac => "SenderMac",
            ArpPacketField::SenderIp => "SenderIp",
            ArpPacketField::TargetMac => "TargetMac",
            ArpPacketField::TargetIp => "TargetIp",
        };
        write!(f, "{}", field)
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ArpPacketError {
    #[error("malformed arp packet field: {0}: {1}")]
    MalformedField(ArpPacketField, Cow<'static, str>),
    #[error("malformed arp packet: {0}")]
    Malformed(Cow<'static, str>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum OpCode {
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

#[derive(Debug)]
pub struct ArpPacket {
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
    fn hardware_type(&self) -> u16 {
        self.hardware_type
    }
    fn protocol_type(&self) -> u16 {
        self.protocol_type
    }
    fn hardware_size(&self) -> u8 {
        self.hardware_size
    }
    fn protocol_size(&self) -> u8 {
        self.protocol_size
    }
    fn op_code(&self) -> &OpCode {
        &self.op_code
    }
    fn sender_mac(&self) -> &MacAddr {
        &self.sender_mac
    }
    fn sender_ip(&self) -> &Ipv4Addr {
        &self.sender_ip
    }
    fn target_mac(&self) -> &MacAddr {
        &self.target_mac
    }
    fn target_ip(&self) -> &Ipv4Addr {
        &self.target_ip
    }
}

impl TryFrom<EthernetFrame> for ArpPacket {
    type Error = ArpPacketError;

    fn try_from(value: EthernetFrame) -> Result<Self, Self::Error> {
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
            let bytes = TryInto::<[u8; 2]>::try_into(&payload[..2]).map_err(|_| {
                ArpPacketError::MalformedField(
                    ArpPacketField::HardwareType,
                    Cow::Borrowed("invalid hardware_type"),
                )
            })?;
            let val = u16::from_be_bytes(bytes);
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
            let bytes = TryInto::<[u8; 2]>::try_into(&payload[2..4]).map_err(|_| {
                ArpPacketError::MalformedField(
                    ArpPacketField::ProtocolType,
                    Cow::Borrowed("invalid protocol_type"),
                )
            })?;
            let val = u16::from_be_bytes(bytes);
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

        let op_code = TryInto::<[u8; 2]>::try_into(&payload[6..8])
            .map_err(|_| {
                ArpPacketError::MalformedField(
                    ArpPacketField::OpCode,
                    Cow::Borrowed("failed to extract op_code for arp"),
                )
            })
            .and_then(|array| OpCode::try_from(u16::from_be_bytes(array)))?;

        let sender_mac =
            MacAddr::from(TryInto::<[u8; 6]>::try_into(&payload[8..14]).map_err(|_| {
                ArpPacketError::MalformedField(
                    ArpPacketField::SenderMac,
                    Cow::Borrowed("failed to extract sender_mac for arp"),
                )
            })?);

        let sender_ip =
            Ipv4Addr::from(TryInto::<[u8; 4]>::try_into(&payload[14..18]).map_err(|_| {
                ArpPacketError::MalformedField(
                    ArpPacketField::SenderIp,
                    Cow::Borrowed("failed to extract sender_ip for arp"),
                )
            })?);

        let target_mac =
            MacAddr::from(TryInto::<[u8; 6]>::try_into(&payload[18..24]).map_err(|_| {
                ArpPacketError::MalformedField(
                    ArpPacketField::TargetMac,
                    Cow::Borrowed("failed to extract target_mac for arp"),
                )
            })?);

        let target_ip =
            Ipv4Addr::from(TryInto::<[u8; 4]>::try_into(&payload[24..28]).map_err(|_| {
                ArpPacketError::MalformedField(
                    ArpPacketField::TargetIp,
                    Cow::Borrowed("failed to extract target_ip for arp"),
                )
            })?);

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
