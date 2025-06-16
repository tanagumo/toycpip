use std::borrow::Cow;

use thiserror::Error;

use crate::ip::{IpPacket, Protocol};
use crate::utils;

#[derive(Debug, Error)]
pub enum TcpPacketError {
    #[error("malformed tcp packet: {0}")]
    Malformed(Cow<'static, str>),
    #[error("checksum mismatch: calculated: {0}, actual: {1}")]
    ChecksumMismatch(u16, u16),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct Offset(u8);

impl Offset {
    /// Offset instances are only created from TcpPacket with the assumption that
    /// constraint violations for Offset, specifically cases where the value is less than 5,
    /// are considered program bugs and will cause a panic
    fn new(value: u8) -> Self {
        if value < 5 {
            panic!(
                "the value of `offset` must be greater than or equal to 0x05, but got 0x{:02x}",
                value
            );
        }
        if value >= 0x10 {
            panic!(
                "The value of `offset` must be smaller than 0x10, but got 0x{:02x}",
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
pub(crate) struct Flags(u8);

impl Flags {
    fn new(value: u8) -> Self {
        if value >= 0x40 {
            panic!(
                "The value of `flags` must be smaller than 0x40, but got 0x{:02x}",
                value
            );
        }
        Self(value)
    }

    fn as_u8(&self) -> u8 {
        self.0
    }

    fn is_fin_flag_on(&self) -> bool {
        self.0 & 0x01 == 1
    }

    fn is_syn_flag_on(&self) -> bool {
        (self.0 >> 1) & 0x01 == 1
    }

    fn is_rst_flag_on(&self) -> bool {
        (self.0 >> 2) & 0x01 == 1
    }

    fn is_psh_flag_on(&self) -> bool {
        (self.0 >> 3) & 0x01 == 1
    }

    fn is_ack_flag_on(&self) -> bool {
        (self.0 >> 4) & 0x01 == 1
    }

    fn is_urg_flag_on(&self) -> bool {
        (self.0 >> 5) & 0x01 == 1
    }
}

#[derive(Debug)]
pub(crate) struct TcpPacket {
    src_port: u16,
    dst_port: u16,
    sequence: u32,
    ack_no: u32,
    offset: Offset,
    flags: Flags,
    window_size: u16,
    checksum: u16,
    urgent_ptr: u16,
    payload: Vec<u8>,
}

impl TryFrom<&IpPacket> for TcpPacket {
    type Error = TcpPacketError;

    fn try_from(ip_packet: &IpPacket) -> Result<Self, Self::Error> {
        if ip_packet.protocol() != Protocol::TCP {
            return Err(TcpPacketError::Malformed(Cow::Borrowed(
                "the protocol of the ip packet is not tcp",
            )));
        }

        let ip_payload = ip_packet.payload();
        if ip_payload.len() < 20 {
            return Err(TcpPacketError::Malformed(Cow::Owned(format!(
                "this tcp packet length is too short: {}",
                ip_payload.len(),
            ))));
        }
        let offset = Offset::new(ip_payload[12] >> 4);
        let tcp_option = &ip_payload[20..offset.as_u8() as usize * 4];
        let tcp_payload = &ip_payload[offset.as_u8() as usize * 4..];

        // `32` is [the length of the ip pseudo header] + [the length of the tcp header]
        let mut vec_to_calc_checksum =
            Vec::with_capacity(32 + tcp_option.len() + tcp_payload.len());

        let ip_packet_src_ip_array = ip_packet.src_ip().octets();
        let ip_packet_dst_ip_array = ip_packet.dst_ip().octets();
        let tcp_len_array = (offset.as_u8() as u16 * 4 + tcp_payload.len() as u16).to_be_bytes();

        vec_to_calc_checksum.extend([
            // ip pseudo header
            ip_packet_src_ip_array[0],
            ip_packet_src_ip_array[1],
            ip_packet_src_ip_array[2],
            ip_packet_src_ip_array[3],
            ip_packet_dst_ip_array[0],
            ip_packet_dst_ip_array[1],
            ip_packet_dst_ip_array[2],
            ip_packet_dst_ip_array[3],
            0,
            ip_packet.protocol().into(),
            tcp_len_array[0],
            tcp_len_array[1],
            // tcp_header
            ip_payload[0],
            ip_payload[1],
            ip_payload[2],
            ip_payload[3],
            ip_payload[4],
            ip_payload[5],
            ip_payload[6],
            ip_payload[7],
            ip_payload[8],
            ip_payload[9],
            ip_payload[10],
            ip_payload[11],
            ip_payload[12],
            ip_payload[13],
            ip_payload[14],
            ip_payload[15],
            0,
            0,
            ip_payload[18],
            ip_payload[19],
        ]);
        vec_to_calc_checksum.extend(tcp_option);
        vec_to_calc_checksum.extend(tcp_payload);

        let calculated_checksum = utils::calculate_checksum(&vec_to_calc_checksum, None).unwrap();
        let actual_checksum = u16::from_be_bytes([ip_payload[16], ip_payload[17]]);
        if actual_checksum != calculated_checksum {
            return Err(TcpPacketError::ChecksumMismatch(
                calculated_checksum,
                actual_checksum,
            ));
        }

        Ok(Self {
            src_port: u16::from_be_bytes([ip_payload[0], ip_payload[1]]),
            dst_port: u16::from_be_bytes([ip_payload[2], ip_payload[3]]),
            sequence: u32::from_be_bytes([
                ip_payload[4],
                ip_payload[5],
                ip_payload[6],
                ip_payload[7],
            ]),
            ack_no: u32::from_be_bytes([
                ip_payload[8],
                ip_payload[9],
                ip_payload[10],
                ip_payload[11],
            ]),
            offset: Offset::new(ip_payload[12] >> 4),
            flags: Flags::new(ip_payload[13] & 0x3f),
            window_size: u16::from_be_bytes([ip_payload[14], ip_payload[15]]),
            checksum: actual_checksum,
            urgent_ptr: u16::from_be_bytes([ip_payload[18], ip_payload[19]]),
            payload: tcp_payload.to_vec(),
        })
    }
}
