use std::{
    borrow::Cow,
    fmt::{Debug, Display},
};

use thiserror::Error;

use crate::types::{HexStringExt, MacAddr};

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EthernetFrameError {
    #[error("ethernet frame too short: {0} bytes")]
    TooShort(usize),
    #[error("malformed ethernet frame: {0}")]
    Malformed(Cow<'static, str>),
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
                EthernetFrameError::Malformed(Cow::Borrowed(
                    "Failed to extract `dst_mac` from the raw data",
                ))
            })?
            .into();

        let src_mac = TryInto::<[u8; 6]>::try_into(&value[6..12])
            .map_err(|_| {
                EthernetFrameError::Malformed(Cow::Borrowed(
                    "Failed to extract `src_mac` from the raw data",
                ))
            })?
            .into();

        let ether_type = EtherType::from(u16::from_be_bytes(
            TryInto::<[u8; 2]>::try_into(&value[12..14]).map_err(|_| {
                EthernetFrameError::Malformed(Cow::Borrowed(
                    "Failed to extract `ether_type` from the raw data",
                ))
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
