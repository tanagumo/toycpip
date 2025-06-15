pub(crate) fn calculate_checksum(
    payload: &[u8],
    zero_offset: Option<usize>,
) -> Result<u16, &'static str> {
    if payload.len() % 2 != 0 {
        return Err("the length of the payload must be even");
    }
    if let Some(offset) = zero_offset {
        if offset % 2 != 0 {
            return Err("the value of `zero_offset` must be even");
        }
    }

    let mut calculated_checksum: u16 = 0;
    for (idx, chunk) in payload.chunks(2).enumerate() {
        let chunk = if zero_offset.is_some() && zero_offset.unwrap() == idx * 2 {
            [0, 0]
        } else {
            [chunk[0], chunk[1]]
        };
        let value = u16::from_be_bytes([chunk[0], chunk[1]]);
        let (sum, carry) = calculated_checksum.overflowing_add(value);
        calculated_checksum = sum;
        if carry {
            calculated_checksum += 1;
        }
    }
    Ok(!calculated_checksum)
}
