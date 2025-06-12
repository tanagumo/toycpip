use std::borrow::Cow;
use std::sync::mpsc::{self, Receiver, SendError, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::{fmt::Display, net::Ipv4Addr};

use thiserror::Error;

use crate::ethernet::{EtherType, EthernetFrame};

#[derive(Debug)]
#[non_exhaustive]
pub enum IpPacketField {
    Version,
    Ihl,
    TypeOfService,
    TotalLength,
    Identification,
    Flags,
    FragmentOffset,
    Ttl,
    Protocol,
    HeaderChecksum,
    SourceIpAddress,
    DestinationIpAddress,
}

impl Display for IpPacketField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let field = match self {
            IpPacketField::Version => "Version",
            IpPacketField::Ihl => "Ihl",
            IpPacketField::TypeOfService => "TypeOfService",
            IpPacketField::TotalLength => "TotalLength",
            IpPacketField::Identification => "Identification",
            IpPacketField::Flags => "Flags",
            IpPacketField::FragmentOffset => "FragmentOffset",
            IpPacketField::Ttl => "Ttl",
            IpPacketField::Protocol => "Protocol",
            IpPacketField::HeaderChecksum => "HeaderChecksum",
            IpPacketField::SourceIpAddress => "SourceIpAddress",
            IpPacketField::DestinationIpAddress => "DestinationIpAddress",
        };
        write!(f, "{}", field)
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum IpPacketError {
    #[error("malformed ip packet field: {0}: {1}")]
    MalformedField(IpPacketField, Cow<'static, str>),
    #[error("malformed ip packet: {0}")]
    Malformed(Cow<'static, str>),
    #[error("checksum mismatch: expected: {0}, actual: {1}")]
    ChecksumMismatch(u16, u16),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Protocol {
    ICMP,
    TCP,
    UDP,
    Other(u8),
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

#[derive(Debug)]
pub struct IpPacket {
    version_and_ihl: u8,
    type_of_service: u8,
    total_length: u16,
    identification: u16,
    flags_and_fragment_offset: u16,
    ttl: u8,
    protocol: Protocol,
    header_checksum: u16,
    source_ip_addr: Ipv4Addr,
    destination_ip_addr: Ipv4Addr,
    padding: Vec<u8>,
    payload: Vec<u8>,
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

        let version_and_ihl = payload[0];
        let ihl = version_and_ihl & 0b00001111;
        if ihl < 5 {
            return Err(IpPacketError::MalformedField(
                IpPacketField::Ihl,
                Cow::Owned(format!("ihl must be greater than 5, but got {}", ihl)),
            ));
        }
        let type_of_service = payload[1];
        let header_length = (ihl as usize) * 4;

        let total_length = {
            let bytes = TryInto::<[u8; 2]>::try_into(&payload[2..4]).map_err(|_| {
                IpPacketError::MalformedField(
                    IpPacketField::TotalLength,
                    Cow::Borrowed("invalid total_length"),
                )
            })?;
            u16::from_be_bytes(bytes)
        };

        let identification = {
            let bytes = TryInto::<[u8; 2]>::try_into(&payload[4..6]).map_err(|_| {
                IpPacketError::MalformedField(
                    IpPacketField::Identification,
                    Cow::Borrowed("invalid identification"),
                )
            })?;
            u16::from_be_bytes(bytes)
        };

        let flags = payload[6] >> 5;
        let fragment_offset = (((payload[6] & 0b00011111) as u16) << 8) | payload[7] as u16;
        let flags_and_fragment_offset = (flags as u16) << 13 | fragment_offset;
        let ttl = payload[8];
        let protocol = payload[9];

        let header_checksum = {
            let bytes = TryInto::<[u8; 2]>::try_into(&payload[10..12]).map_err(|_| {
                IpPacketError::MalformedField(
                    IpPacketField::HeaderChecksum,
                    Cow::Borrowed("invalid header_checksum"),
                )
            })?;
            u16::from_be_bytes(bytes)
        };

        let source_ip_addr = {
            let bytes = TryInto::<[u8; 4]>::try_into(&payload[12..16]).map_err(|_| {
                IpPacketError::MalformedField(
                    IpPacketField::SourceIpAddress,
                    Cow::Borrowed("invalid source ip address"),
                )
            })?;
            Ipv4Addr::from(bytes)
        };

        let destination_ip_addr = {
            let bytes = TryInto::<[u8; 4]>::try_into(&payload[16..20]).map_err(|_| {
                IpPacketError::MalformedField(
                    IpPacketField::DestinationIpAddress,
                    Cow::Borrowed("invalid destination ip address"),
                )
            })?;
            Ipv4Addr::from(bytes)
        };

        let mut calculated_checksum: u16 = 0;
        for i in (0..header_length).step_by(2) {
            let value = {
                let bytes = TryInto::<[u8; 2]>::try_into(&payload[i..i + 2]).unwrap();
                u16::from_be_bytes(bytes)
            };
            let (sum, carry) = calculated_checksum.overflowing_add(value);
            calculated_checksum = sum;
            if carry {
                calculated_checksum += 1;
            }
        }

        calculated_checksum = !calculated_checksum;
        if calculated_checksum != header_checksum {
            return Err(IpPacketError::ChecksumMismatch(
                header_checksum,
                calculated_checksum,
            ));
        }

        let padding = payload[20..header_length].to_vec();
        let payload = payload[header_length..].to_vec();

        Ok(Self {
            version_and_ihl,
            type_of_service,
            total_length,
            identification,
            flags_and_fragment_offset,
            ttl,
            protocol: Protocol::from(protocol),
            header_checksum,
            source_ip_addr,
            destination_ip_addr,
            padding,
            payload,
        })
    }
}

#[derive(Debug)]
pub struct IpLayer {
    sender: Sender<IpPacket>,
    observers: Arc<Mutex<Vec<Sender<Arc<IpPacket>>>>>,
}

impl IpLayer {
    pub fn start(
        ethernet_sender: impl Fn(IpPacket) -> Result<(), SendError<EthernetFrame>> + Send + 'static,
        receiver: Receiver<Arc<EthernetFrame>>,
    ) -> Self {
        let observers = Arc::new(Mutex::new(Vec::<Sender<Arc<IpPacket>>>::new()));
        let cloned_observers = Arc::clone(&observers);

        thread::Builder::new()
            .name("ip_observe_tx".into())
            .spawn(move || {
                loop {
                    if let Ok(frame) = receiver.recv() {
                        let packet = match IpPacket::try_from(&*frame) {
                            Ok(packet) => packet,
                            Err(e) => {
                                eprintln!("{}", e);
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

        let (tx, rx) = mpsc::channel::<IpPacket>();
        thread::Builder::new()
            .name("ip_send_tx".into())
            .spawn(move || {
                for packet in rx {
                    match ethernet_sender(packet) {
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("{}", e);
                        }
                    }
                }
            })
            .unwrap();

        Self {
            sender: tx,
            observers,
        }
    }

    pub fn add_observer(&self, observer: Sender<Arc<IpPacket>>) {
        let mut guard = self.observers.lock().unwrap();
        guard.push(observer);
    }

    pub fn send(&self, packet: IpPacket) -> Result<(), SendError<IpPacket>> {
        self.sender.send(packet)
    }
}
