use std::net::Ipv4Addr;
use std::sync::mpsc::{self, SendError};
use std::time::Duration;
use std::{borrow::Cow, fmt::Display, process, time::Instant};

use thiserror::Error;

use crate::ip::{self, IP_LAYER, IpPacket, IpPacketError, Protocol};
use crate::utils;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum IcmpType {
    EchoRequest,
    EchoReply,
    Other(u8),
}

impl Display for IcmpType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            IcmpType::EchoRequest => Cow::Borrowed("EchoRequest"),
            IcmpType::EchoReply => Cow::Borrowed("EchoReply"),
            IcmpType::Other(n) => Cow::Owned(format!("Other({})", n)),
        };
        write!(f, "{}", value)
    }
}

impl Into<u8> for IcmpType {
    fn into(self) -> u8 {
        match self {
            IcmpType::EchoRequest => 8,
            IcmpType::EchoReply => 0,
            IcmpType::Other(n) => n,
        }
    }
}

impl From<u8> for IcmpType {
    fn from(value: u8) -> Self {
        match value {
            0 => IcmpType::EchoReply,
            8 => IcmpType::EchoRequest,
            n => IcmpType::Other(n),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct Code(u8);

impl Display for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Code({})", self.as_u8())
    }
}

impl Code {
    /// Code instances are only created from IcmpPacket with the assumption that
    /// constraint violations for Code, specifically cases where the value is not 0,
    /// are considered program bugs and will cause a panic
    fn new(value: u8) -> Self {
        if value != 0 {
            panic!("the value of code must be 0, but got {}", value);
        }
        Self(value)
    }

    fn as_u8(&self) -> u8 {
        self.0
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub(crate) enum IcmpPacketError {
    #[error("malformed icmp packet: {0}")]
    Malformed(Cow<'static, str>),
    #[error("the value of code must be 0, but got {0}")]
    InvalidCode(u8),
    #[error("checksum mismatch: expected: {0}, actual: {1}")]
    ChecksumMismatch(u16, u16),
}

#[derive(Debug)]
pub(crate) struct IcmpPacket {
    icmp_type: IcmpType,
    code: Code,
    checksum: u16,
    identifier: u16,
    sequence: u16,
    payload: Vec<u8>,
}

impl Display for IcmpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Icmp(type={}, code={}, checksum={}, identifier={}, sequence={})",
            self.icmp_type, self.code, self.checksum, self.identifier, self.sequence,
        )
    }
}

impl IcmpPacket {
    fn new(
        icmp_type: IcmpType,
        code: Code,
        identifier: u16,
        sequence: u16,
        payload: Vec<u8>,
    ) -> Self {
        if icmp_type == IcmpType::EchoRequest && code.as_u8() != 0 {
            panic!("Echo Request code must be 0, but got {}", code.as_u8());
        }

        let mut icmp = Self {
            icmp_type,
            code,
            checksum: 0,
            identifier,
            sequence,
            payload,
        };

        let checksum = icmp.calc_checksum();
        icmp.checksum = checksum;
        icmp
    }

    fn calc_checksum(&self) -> u16 {
        let identifier_array = self.identifier.to_be_bytes();
        let sequence_array = self.sequence.to_be_bytes();
        let mut v = Vec::with_capacity(8 + self.payload.len());
        v.extend([
            self.icmp_type.into(),
            self.code.as_u8(),
            0,
            0,
            identifier_array[0],
            identifier_array[1],
            sequence_array[0],
            sequence_array[1],
        ]);
        v.extend(self.payload());

        if v.len() % 2 != 0 {
            v.push(0);
        }

        utils::calculate_checksum(&v, Some(2)).unwrap()
    }

    pub(crate) fn icmp_type(&self) -> IcmpType {
        self.icmp_type
    }

    pub(crate) fn code(&self) -> Code {
        self.code
    }

    pub(crate) fn checksum(&self) -> u16 {
        self.checksum
    }

    pub(crate) fn identifier(&self) -> u16 {
        self.identifier
    }

    pub(crate) fn sequence(&self) -> u16 {
        self.sequence
    }

    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let capacity = 8 + self.payload.len();
        let checksum_array = self.checksum.to_be_bytes();
        let ident_array = self.identifier.to_be_bytes();
        let seq_no_array = self.sequence.to_be_bytes();

        let mut v = Vec::with_capacity(capacity);

        // Minimize the number of extend calls for performance optimization
        v.extend([
            self.icmp_type.into(),
            self.code.as_u8(),
            checksum_array[0],
            checksum_array[1],
            ident_array[0],
            ident_array[1],
            seq_no_array[0],
            seq_no_array[1],
        ]);
        v.extend(&self.payload);
        v
    }
}

impl TryFrom<&IpPacket> for IcmpPacket {
    type Error = IcmpPacketError;

    fn try_from(value: &IpPacket) -> Result<Self, Self::Error> {
        let mut payload = value.payload().to_vec();
        if payload.len() < 8 {
            return Err(IcmpPacketError::Malformed(Cow::Owned(format!(
                "this icmp packet length is too short: {}",
                payload.len()
            ))));
        }

        let code = {
            if payload[1] != 0 {
                return Err(IcmpPacketError::InvalidCode(payload[1]));
            }
            Code::new(payload[1])
        };

        let checksum = u16::from_be_bytes([payload[2], payload[3]]);
        let payload_is_odd = {
            if payload.len() % 2 != 0 {
                payload.push(0);
                true
            } else {
                false
            }
        };
        let calculated_checksum = utils::calculate_checksum(&payload, Some(2)).unwrap();
        if checksum != calculated_checksum {
            return Err(IcmpPacketError::ChecksumMismatch(
                checksum,
                calculated_checksum,
            ));
        }

        if payload_is_odd {
            payload.pop();
        }

        Ok(Self {
            icmp_type: IcmpType::from(payload[0]),
            code,
            checksum,
            identifier: u16::from_be_bytes([payload[4], payload[5]]),
            sequence: u16::from_be_bytes([payload[6], payload[7]]),
            payload: payload[8..].to_vec(),
        })
    }
}

pub(crate) fn make_icmp_request(sequence: u16) -> IcmpPacket {
    if sequence == 0 {
        panic!("the value of `sequence` must be greater than 0");
    }

    IcmpPacket::new(
        IcmpType::EchoRequest,
        Code::new(0),
        process::id() as u16,
        sequence,
        vec![],
    )
}

#[derive(Debug, Error)]
pub(crate) enum IcmpRequestError {
    #[error("timeout: {0} seconds")]
    Timeout(u8),
    #[error("send error: {0}")]
    SendError(#[from] SendError<IpPacket>),
    #[error("ip packet error: {0}")]
    IpPacket(#[from] IpPacketError),
}

pub(crate) fn send_icmp_echo_request(
    dst_ip: impl Into<Ipv4Addr>,
    sequence: u16,
    ttl: Option<u8>,
    timeout: Option<u8>,
) -> Result<IcmpPacket, IcmpRequestError> {
    let icmp_packet = make_icmp_request(sequence);
    let identifier = icmp_packet.identifier();

    let ip_packet = ip::make_ip_packet(
        ttl.unwrap_or(64),
        Protocol::ICMP,
        dst_ip.into(),
        icmp_packet.to_bytes(),
    )?;

    let (tx, rx) = mpsc::channel();
    let ip_layer = IP_LAYER.get().unwrap();
    ip_layer.add_observer(tx);
    ip_layer.send(ip_packet)?;

    let start = Instant::now();
    let result = loop {
        if let Some(secs) = timeout {
            if start.elapsed() > Duration::from_secs(secs as u64) {
                break Err(IcmpRequestError::Timeout(secs));
            }
        }

        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(ip_packet) => {
                if let Ok(icmp_packet) = TryInto::<IcmpPacket>::try_into(&*ip_packet) {
                    if icmp_packet.icmp_type() == IcmpType::EchoReply
                        && icmp_packet.identifier() == identifier
                        && icmp_packet.sequence() == sequence
                    {
                        return Ok(icmp_packet);
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => continue,
        }
    };

    result
}
