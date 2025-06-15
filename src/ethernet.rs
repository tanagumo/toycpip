use std::{
    borrow::Cow,
    fmt::{Debug, Display},
    sync::{
        Arc, Mutex, OnceLock,
        mpsc::{self, SendError, Sender},
    },
    thread,
};

use log::{debug, error, info, warn};
use pnet::datalink::{self, Channel::Ethernet, NetworkInterface};
use thiserror::Error;

use crate::host;
use crate::types::{HexStringExt, MacAddr};

pub(crate) static ETHERNET_LAYER: OnceLock<EthernetLayer> = OnceLock::new();

#[derive(Debug, Error)]
#[non_exhaustive]
pub(crate) enum EthernetFrameError {
    #[error("ethernet frame too short: {0} bytes")]
    TooShort(usize),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum EtherType {
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

impl From<[u8; 2]> for EtherType {
    fn from(value: [u8; 2]) -> Self {
        Self::from(u16::from_be_bytes(value))
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
    pub(crate) const SIZE: usize = 2;
}

#[derive(Debug)]
pub(crate) struct EthernetFrame {
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
        if value.len() < MacAddr::SIZE * 2 + EtherType::SIZE {
            return Err(EthernetFrameError::TooShort(value.len()));
        }

        let dst_mac = MacAddr::from([value[0], value[1], value[2], value[3], value[4], value[5]]);
        let src_mac = MacAddr::from([value[6], value[7], value[8], value[9], value[10], value[11]]);
        let ether_type = EtherType::from([value[12], value[13]]);
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
    fn new(dst_mac: MacAddr, src_mac: MacAddr, ether_type: EtherType, payload: Vec<u8>) -> Self {
        Self {
            dst_mac,
            src_mac,
            ether_type,
            payload,
        }
    }

    pub(crate) fn dst_mac(&self) -> MacAddr {
        self.dst_mac
    }

    pub(crate) fn src_mac(&self) -> MacAddr {
        self.src_mac
    }

    pub(crate) fn ether_type(&self) -> EtherType {
        self.ether_type
    }

    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub(crate) fn len(&self) -> usize {
        MacAddr::SIZE * 2 + EtherType::SIZE + self.payload.len()
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.len());
        bytes.extend(&*self.dst_mac);
        bytes.extend(&*self.src_mac);
        bytes.extend(Into::<[u8; 2]>::into(self.ether_type));
        bytes.extend(&self.payload);
        bytes
    }
}

#[derive(Debug)]
pub(crate) struct EthernetLayer {
    sender: Sender<EthernetFrame>,
    observers: Arc<Mutex<Vec<Sender<Arc<EthernetFrame>>>>>,
}

impl EthernetLayer {
    pub(crate) fn start(interface: &NetworkInterface) -> Self {
        let (mut _tx, mut _rx) = match datalink::channel(interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unhandled channel type"),
            Err(e) => panic!(
                "An error occurred when creating the datalink channel: {}",
                e
            ),
        };

        info!("Starting Ethernet layer");
        let observers = Arc::new(Mutex::new(Vec::<Sender<Arc<EthernetFrame>>>::new()));
        let cloned_observers = Arc::clone(&observers);

        thread::Builder::new()
            .name("ethernet_observe_tx".into())
            .spawn(move || {
                debug!("Ethernet receive thread started");
                loop {
                    if let Ok(raw) = _rx.next() {
                        let frame = match EthernetFrame::try_from(raw) {
                            Ok(frame) => {
                                debug!("Ethernet frame parsed successfully: {}", frame);
                                frame
                            }
                            Err(e) => {
                                warn!("Failed to parse Ethernet frame: {}", e);
                                continue;
                            }
                        };
                        let frame = Arc::new(frame);
                        let mut guard = cloned_observers.lock().unwrap();
                        let observer_count = guard.len();
                        guard.retain(|sender| sender.send(Arc::clone(&frame)).is_ok());
                        let retained_count = guard.len();
                        if observer_count != retained_count {
                            debug!(
                                "Removed invalid observers: {} -> {}",
                                observer_count, retained_count
                            );
                        }
                    }
                }
            })
            .unwrap();

        let (tx, rx) = mpsc::channel::<EthernetFrame>();
        thread::Builder::new()
            .name("ethernet_send_tx".into())
            .spawn(move || {
                debug!("Ethernet send thread started");
                for frame in rx {
                    debug!("Sending Ethernet frame: {}", frame);
                    let frame_bytes = frame.to_bytes();
                    if let Some(ret) = _tx.send_to(&frame_bytes, None) {
                        match ret {
                            Ok(_) => {
                                debug!(
                                    "Ethernet frame sent successfully: {} bytes",
                                    frame_bytes.len()
                                );
                            }
                            Err(e) => {
                                error!("Failed to send Ethernet frame: {}", e);
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

    pub(crate) fn add_observer(&self, observer: Sender<Arc<EthernetFrame>>) {
        let mut guard = self.observers.lock().unwrap();
        guard.push(observer);
        debug!("Added Ethernet observer: total_count={}", guard.len());
    }

    pub(crate) fn send(&self, frame: EthernetFrame) -> Result<(), SendError<EthernetFrame>> {
        self.sender.send(frame)
    }
}

pub(crate) fn setup(interface: &NetworkInterface) -> &'static EthernetLayer {
    ETHERNET_LAYER.get_or_init(|| EthernetLayer::start(interface))
}

pub(crate) fn make_frame(
    dst_mac: MacAddr,
    ether_type: EtherType,
    payload: Vec<u8>,
) -> EthernetFrame {
    let src_mac = host::HOST_MAC.get().unwrap();
    EthernetFrame::new(dst_mac, *src_mac, ether_type, payload)
}
