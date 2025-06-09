use std::{fmt::Display, ops::Deref};

fn to_hex_string(data: &[u8]) -> String {
    format!(
        "{}",
        data.iter()
            .map(|v| format!("{:02x}", v))
            .collect::<Vec<_>>()
            .join(":")
    )
}

pub trait HexStringExt {
    fn hex_string(&self) -> String;
}

impl HexStringExt for [u8] {
    fn hex_string(&self) -> String {
        to_hex_string(&self)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    pub const BYTES: u8 = 6;

    pub fn new(value: [u8; 6]) -> Self {
        Self(value)
    }
}

impl Display for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", to_hex_string(&self.0))
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(value: [u8; 6]) -> Self {
        Self(value)
    }
}

impl From<MacAddr> for [u8; 6] {
    fn from(value: MacAddr) -> Self {
        value.0
    }
}

impl Deref for MacAddr {
    type Target = [u8; 6];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
