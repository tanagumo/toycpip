use std::{
    borrow::Cow,
    fmt::{Debug, Display},
    sync::{
        Arc, Mutex,
        mpsc::{self, SendError, Sender},
    },
    thread,
};

use pnet::datalink::{self, Channel::Ethernet, NetworkInterface};
use thiserror::Error;

use crate::types::{HexStringExt, MacAddr};

#[derive(Debug)]
#[non_exhaustive]
pub enum EthernetFrameField {
    DstMacAddr,
    SrcMacAddr,
    EtherType,
}

impl Display for EthernetFrameField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let field = match self {
            EthernetFrameField::DstMacAddr => "DstMacAddr",
            EthernetFrameField::SrcMacAddr => "SrcMacAddr",
            EthernetFrameField::EtherType => "EtherType",
        };
        write!(f, "{}", field)
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EthernetFrameError {
    #[error("ethernet frame too short: {0} bytes")]
    TooShort(usize),
    #[error("malformed ethernet frame field: {0}: {1}")]
    MalformedField(EthernetFrameField, Cow<'static, str>),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EtherType {
    IpV4,
    Arp,
    Other(u16),
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        match value {
            0x0800 => EtherType::IpV4,
            0x0806 => EtherType::Arp,
            _ => EtherType::Other(value),
        }
    }
}

impl Into<[u8; 2]> for EtherType {
    fn into(self) -> [u8; 2] {
        let value = match self {
            EtherType::Arp => 0x0806,
            EtherType::IpV4 => 0x0800,
            EtherType::Other(v) => v,
        };

        value.to_be_bytes()
    }
}

impl Display for EtherType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            EtherType::IpV4 => Cow::Borrowed("ipv4"),
            EtherType::Arp => Cow::Borrowed("arp"),
            EtherType::Other(v) => Cow::Owned(format!("other({:04x})", v)),
        };
        write!(f, "{}", value)
    }
}

impl EtherType {
    pub const BYTES: u8 = 2;
}

#[derive(Debug)]
pub struct EthernetFrame {
    dst_mac: MacAddr,
    src_mac: MacAddr,
    ether_type: EtherType,
    payload: Vec<u8>,
}

impl Display for EthernetFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dst_mac = self.dst_mac.hex_string();
        let src_mac = self.src_mac.hex_string();
        write!(
            f,
            "EthernetFrame(dst_mac: {}, src_mac: {}, ether_type: {})",
            dst_mac, src_mac, self.ether_type
        )
    }
}

impl TryFrom<&[u8]> for EthernetFrame {
    type Error = EthernetFrameError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 60 {
            return Err(EthernetFrameError::TooShort(value.len()));
        }

        let dst_mac = TryInto::<[u8; 6]>::try_into(&value[..6])
            .map_err(|_| {
                EthernetFrameError::MalformedField(
                    EthernetFrameField::DstMacAddr,
                    Cow::Borrowed("Failed to extract `dst_mac` from the raw data"),
                )
            })?
            .into();

        let src_mac = TryInto::<[u8; 6]>::try_into(&value[6..12])
            .map_err(|_| {
                EthernetFrameError::MalformedField(
                    EthernetFrameField::SrcMacAddr,
                    Cow::Borrowed("Failed to extract `src_mac` from the raw data"),
                )
            })?
            .into();

        let ether_type = EtherType::from(u16::from_be_bytes(
            TryInto::<[u8; 2]>::try_into(&value[12..14]).map_err(|_| {
                EthernetFrameError::MalformedField(
                    EthernetFrameField::EtherType,
                    Cow::Borrowed("Failed to extract `ether_type` from the raw data"),
                )
            })?,
        ));

        let payload = value[14..].to_vec();

        Ok(Self {
            dst_mac,
            src_mac,
            ether_type,
            payload,
        })
    }
}

impl EthernetFrame {
    pub fn dst_mac(&self) -> MacAddr {
        self.dst_mac
    }

    pub fn src_mac(&self) -> MacAddr {
        self.src_mac
    }

    pub fn ether_type(&self) -> EtherType {
        self.ether_type
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn len(&self) -> usize {
        MacAddr::BYTES as usize * 2 + EtherType::BYTES as usize + self.payload.len()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.len());
        bytes.extend(&*self.dst_mac);
        bytes.extend(&*self.src_mac);
        bytes.extend(Into::<[u8; 2]>::into(self.ether_type));
        bytes.extend(&self.payload);
        bytes
    }
}

#[derive(Debug)]
pub struct EthernetLayer {
    sender: Sender<EthernetFrame>,
    observers: Arc<Mutex<Vec<Sender<Arc<EthernetFrame>>>>>,
}

impl EthernetLayer {
    pub fn start(interface: &NetworkInterface) -> Self {
        let (mut _tx, mut _rx) = match datalink::channel(interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unhandled channel type"),
            Err(e) => panic!(
                "An error occurred when creating the datalink channel: {}",
                e
            ),
        };

        let observers = Arc::new(Mutex::new(Vec::<Sender<Arc<EthernetFrame>>>::new()));
        let cloned_observers = Arc::clone(&observers);

        thread::Builder::new()
            .name("ethernet_observe_tx".into())
            .spawn(move || {
                loop {
                    if let Ok(raw) = _rx.next() {
                        let frame = match EthernetFrame::try_from(raw) {
                            Ok(frame) => frame,
                            Err(e) => {
                                eprintln!("{}", e);
                                continue;
                            }
                        };
                        let frame = Arc::new(frame);
                        match cloned_observers.lock() {
                            Ok(mut guard) => {
                                guard.retain(|sender| sender.send(Arc::clone(&frame)).is_ok());
                            }
                            Err(e) => {
                                let mut observers = e.into_inner();
                                observers.clear();
                                cloned_observers.clear_poison();
                            }
                        }
                    }
                }
            })
            .unwrap();

        let (tx, rx) = mpsc::channel::<EthernetFrame>();
        thread::Builder::new()
            .name("ethernet_send_tx".into())
            .spawn(move || {
                for frame in rx {
                    if let Some(ret) = _tx.send_to(&frame.to_bytes(), None) {
                        match ret {
                            Ok(_) => {}
                            Err(e) => {
                                eprintln!("{}", e);
                            }
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

    pub fn add_observer(&self, observer: Sender<Arc<EthernetFrame>>) {
        let mut guard = self.observers.lock().unwrap_or_else(|e| e.into_inner());
        guard.push(observer);
        self.observers.clear_poison();
    }

    pub fn send(&self, packet: EthernetFrame) -> Result<(), SendError<EthernetFrame>> {
        self.sender.send(packet)
    }
}
