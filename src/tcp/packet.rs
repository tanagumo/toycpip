use std::any::type_name;
use std::borrow::Cow;
use std::fmt::Display;
use std::net::Ipv4Addr;

use log::error;
use thiserror::Error;

use crate::ip::{self, IpPacket, IpPacketError, Protocol};
use crate::utils;

#[derive(Debug, Error)]
pub enum TcpPacketError {
    #[error("malformed tcp packet: {0}")]
    Malformed(Cow<'static, str>),
    #[error("checksum mismatch: calculated: {0}, actual: {1}")]
    ChecksumMismatch(u16, u16),
    #[error("offset must be greater than or equal to 5, but got {0}")]
    OffsetTooSmall(u8),
    #[error("flags must not be greater than or equal to 0x40, but got {0}")]
    FlagsTooLarge(u8),
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
        self.fin_flag() == 1
    }

    fn fin_flag(&self) -> u8 {
        self.0 & 0x01
    }

    fn is_syn_flag_on(&self) -> bool {
        self.syn_flag() == 1
    }

    fn syn_flag(&self) -> u8 {
        (self.0 >> 1) & 0x01
    }

    fn is_rst_flag_on(&self) -> bool {
        self.rst_flag() == 1
    }

    fn rst_flag(&self) -> u8 {
        (self.0 >> 2) & 0x01
    }

    fn is_psh_flag_on(&self) -> bool {
        self.psh_flag() == 1
    }

    fn psh_flag(&self) -> u8 {
        (self.0 >> 3) & 0x01
    }

    fn is_ack_flag_on(&self) -> bool {
        self.ack_flag() == 1
    }

    fn ack_flag(&self) -> u8 {
        (self.0 >> 4) & 0x01
    }

    fn is_urg_flag_on(&self) -> bool {
        self.urg_flag() == 1
    }

    fn urg_flag(&self) -> u8 {
        (self.0 >> 5) & 0x01
    }
}

impl Display for Flags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut flags = vec![];
        if self.is_fin_flag_on() {
            flags.push("FIN");
        }
        if self.is_syn_flag_on() {
            flags.push("SYN");
        }
        if self.is_rst_flag_on() {
            flags.push("RST");
        }
        if self.is_psh_flag_on() {
            flags.push("PSH");
        }
        if self.is_ack_flag_on() {
            flags.push("ACK");
        }
        if self.is_urg_flag_on() {
            flags.push("URG");
        }
        write!(f, "Flags({})", flags.join("+"))
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
    option: Vec<u8>,
    payload: Vec<u8>,
}

impl Display for TcpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TcpPacket(src_port={}, dst_port={}, sequence={}, ack_no={}, flags={})",
            self.src_port, self.dst_port, self.sequence, self.ack_no, self.flags,
        )
    }
}

impl TcpPacket {
    fn new(
        src_port: u16,
        dst_port: u16,
        sequence: u32,
        ack_no: u32,
        offset: Offset,
        flags: Flags,
        window_size: u16,
        checksum: u16,
        urgent_ptr: u16,
        option: Vec<u8>,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            src_port,
            dst_port,
            sequence,
            ack_no,
            offset,
            flags,
            window_size,
            checksum,
            urgent_ptr,
            option,
            payload,
        }
    }

    fn calc_checksum(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        protocol: Protocol,
        src_port: u16,
        dst_port: u16,
        sequence: u32,
        ack_no: u32,
        offset: Offset,
        flags: Flags,
        window_size: u16,
        urgent_ptr: u16,
        option: &[u8],
        payload: &[u8],
    ) -> u16 {
        if option.len() % 4 != 0 {
            panic!(
                "the length of `option` must be multiple of 4, but got {}",
                option.len()
            );
        }

        let header_len = option.len() + 20;
        if header_len > 60 {
            panic!(
                "TCP header length exceeds maximum (60 bytes), got {}",
                header_len
            );
        }

        if offset.as_u8() * 4 != (option.len() as u8 + 20) {
            panic!(
                "the expected offset value is {}, but got {}",
                (option.len() + 20) / 4,
                offset.as_u8()
            );
        }
        let src_ip_array = src_ip.octets();
        let dst_ip_array = dst_ip.octets();
        let tcp_payload_len_array =
            (offset.as_u8() as u16 * 4 + payload.len() as u16).to_be_bytes();

        let src_port_array = src_port.to_be_bytes();
        let dst_port_array = dst_port.to_be_bytes();
        let sequence_array = sequence.to_be_bytes();
        let ack_no_array = ack_no.to_be_bytes();
        let byte_at_17: u8 = offset.as_u8() << 4;
        let byte_at_18: u8 = (flags.urg_flag() << 5)
            | (flags.ack_flag() << 4)
            | (flags.psh_flag() << 3)
            | (flags.rst_flag() << 2)
            | (flags.syn_flag() << 1)
            | flags.fin_flag();
        let window_size_array = window_size.to_be_bytes();
        let urgent_ptr_array = urgent_ptr.to_be_bytes();

        let mut vec_to_calc_checksum =
            Vec::with_capacity(offset.as_u8() as usize * 4 + payload.len());
        vec_to_calc_checksum.extend([
            // ip pseudo header
            src_ip_array[0],
            src_ip_array[1],
            src_ip_array[2],
            src_ip_array[3],
            dst_ip_array[0],
            dst_ip_array[1],
            dst_ip_array[2],
            dst_ip_array[3],
            0,
            protocol.into(),
            tcp_payload_len_array[0],
            tcp_payload_len_array[1],
            // tpc_header
            src_port_array[0],
            src_port_array[1],
            dst_port_array[0],
            dst_port_array[1],
            sequence_array[0],
            sequence_array[1],
            sequence_array[2],
            sequence_array[3],
            ack_no_array[0],
            ack_no_array[1],
            ack_no_array[2],
            ack_no_array[3],
            byte_at_17,
            byte_at_18,
            window_size_array[0],
            window_size_array[1],
            0,
            0,
            urgent_ptr_array[0],
            urgent_ptr_array[1],
        ]);
        vec_to_calc_checksum.extend(option);
        vec_to_calc_checksum.extend(payload);

        if vec_to_calc_checksum.len() % 2 != 0 {
            vec_to_calc_checksum.push(0);
        }
        utils::calculate_checksum(&vec_to_calc_checksum, None).unwrap()
    }

    pub(crate) fn src_port(&self) -> u16 {
        self.src_port
    }

    pub(crate) fn dst_port(&self) -> u16 {
        self.dst_port
    }

    pub(crate) fn sequence(&self) -> u32 {
        self.sequence
    }

    pub(crate) fn ack_no(&self) -> u32 {
        self.ack_no
    }

    pub(crate) fn offset(&self) -> Offset {
        self.offset
    }

    pub(crate) fn flags(&self) -> Flags {
        self.flags
    }

    pub(crate) fn window_size(&self) -> u16 {
        self.window_size
    }

    pub(crate) fn checksum(&self) -> u16 {
        self.checksum
    }

    pub(crate) fn urgent_ptr(&self) -> u16 {
        self.urgent_ptr
    }

    pub(crate) fn option(&self) -> &[u8] {
        &self.option
    }

    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(20 + self.option.len() + self.payload.len());
        let src_port_array = self.src_port.to_be_bytes();
        let dst_port_array = self.dst_port.to_be_bytes();
        let sequence_array = self.sequence.to_be_bytes();
        let ack_no_array = self.ack_no.to_be_bytes();
        let window_size_array = self.window_size.to_be_bytes();
        let checksum_array = self.checksum.to_be_bytes();
        let urgent_ptr_array = self.urgent_ptr.to_be_bytes();

        v.extend([
            src_port_array[0],
            src_port_array[1],
            dst_port_array[0],
            dst_port_array[1],
            sequence_array[0],
            sequence_array[1],
            sequence_array[2],
            sequence_array[3],
            ack_no_array[0],
            ack_no_array[1],
            ack_no_array[2],
            ack_no_array[3],
            self.offset.as_u8() << 4,
            self.flags.as_u8(),
            window_size_array[0],
            window_size_array[1],
            checksum_array[0],
            checksum_array[1],
            urgent_ptr_array[0],
            urgent_ptr_array[1],
        ]);
        v.extend(self.option());
        v.extend(self.payload());
        v
    }
}

#[derive(Debug)]
pub(crate) struct WithPeerIp<T> {
    ip_addr: Ipv4Addr,
    value: T,
}

impl<T> Display for WithPeerIp<T>
where
    T: Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let type_name = type_name::<T>().split("::").last().unwrap_or("Unknown");
        write!(
            f,
            "WithPeerIP<{}>(ip_addr={}, value={})",
            type_name, self.ip_addr, self.value
        )
    }
}

impl<T> WithPeerIp<T> {
    pub(crate) fn ip_addr(&self) -> Ipv4Addr {
        self.ip_addr
    }

    pub(crate) fn value(&self) -> &T {
        &self.value
    }

    pub(crate) fn into_value(self) -> T {
        self.value
    }
}

impl WithPeerIp<TcpPacket> {
    pub(crate) fn to_ip_packet(self, ttl: Option<u8>) -> Result<IpPacket, IpPacketError> {
        let ttl = ttl.unwrap_or(64);
        let dst_ip = self.ip_addr();
        let tcp_packet = self.into_value();
        ip::make_ip_packet(ttl, Protocol::TCP, dst_ip, tcp_packet.to_bytes())
    }
}

impl TryFrom<&IpPacket> for WithPeerIp<TcpPacket> {
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
        let offset_value = ip_payload[12] >> 4;
        if offset_value < 5 {
            return Err(TcpPacketError::OffsetTooSmall(offset_value));
        }
        let offset = Offset::new(offset_value);
        let tcp_option = &ip_payload[20..offset.as_u8() as usize * 4];
        let tcp_payload = &ip_payload[offset.as_u8() as usize * 4..];

        // `32` is [the length of the ip pseudo header] + [the length of the tcp header]
        let mut vec_to_calc_checksum =
            Vec::with_capacity(32 + tcp_option.len() + tcp_payload.len());

        let ip_packet_src_ip_array = ip_packet.src_ip().octets();
        let ip_packet_dst_ip_array = ip_packet.dst_ip().octets();
        let tcp_len_array = (offset.as_u8() as u16 * 4 + tcp_payload.len() as u16).to_be_bytes();

        let flags_value = ip_payload[13] & 0x3f;
        if flags_value >= 0x40 {
            return Err(TcpPacketError::FlagsTooLarge(flags_value));
        }
        let flags = Flags::new(flags_value);

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

        let src_port = u16::from_be_bytes([ip_payload[0], ip_payload[1]]);
        let dst_port = u16::from_be_bytes([ip_payload[2], ip_payload[3]]);
        let sequence =
            u32::from_be_bytes([ip_payload[4], ip_payload[5], ip_payload[6], ip_payload[7]]);
        let ack_no =
            u32::from_be_bytes([ip_payload[8], ip_payload[9], ip_payload[10], ip_payload[11]]);

        let window_size = u16::from_be_bytes([ip_payload[14], ip_payload[15]]);
        let urgent_ptr = u16::from_be_bytes([ip_payload[18], ip_payload[19]]);

        let calculated_checksum = TcpPacket::calc_checksum(
            ip_packet.src_ip(),
            ip_packet.dst_ip(),
            ip_packet.protocol(),
            src_port,
            dst_port,
            sequence,
            ack_no,
            offset,
            flags,
            window_size,
            urgent_ptr,
            tcp_option,
            tcp_payload,
        );
        let actual_checksum = u16::from_be_bytes([ip_payload[16], ip_payload[17]]);
        if actual_checksum != calculated_checksum {
            return Err(TcpPacketError::ChecksumMismatch(
                calculated_checksum,
                actual_checksum,
            ));
        }

        Ok(Self {
            ip_addr: ip_packet.src_ip(),
            value: TcpPacket::new(
                src_port,
                dst_port,
                sequence,
                ack_no,
                offset,
                flags,
                window_size,
                calculated_checksum,
                urgent_ptr,
                tcp_option.to_vec(),
                tcp_payload.to_vec(),
            ),
        })
    }
}
