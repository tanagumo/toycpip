pub(crate) fn calculate_checksum(payload: &[u8]) -> Result<u16, &'static str> {
    if payload.len() % 2 != 0 {
        return Err("the length of the payload must be even");
    }

    let mut calculated_checksum: u16 = 0;
    for chunk in payload.chunks(2) {
        let value = u16::from_be_bytes([chunk[0], chunk[1]]);
        let (sum, carry) = calculated_checksum.overflowing_add(value);
        calculated_checksum = sum;
        if carry {
            calculated_checksum += 1;
        }
    }
    Ok(!calculated_checksum)
}
