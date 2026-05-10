//! [`EnergyLtRecord`] decoder — same binary layout as [`super::energy`].

use srum_core::EnergyLtRecord;

use crate::SrumError;

pub fn decode_energy_lt_record(
    data: &[u8],
    page: u32,
    tag: usize,
) -> Result<EnergyLtRecord, SrumError> {
    super::energy::decode_energy_record(data, page, tag)
}

#[cfg(test)]
mod tests {
    use super::*;
    use srum_core::ENERGY_RECORD_SIZE;

    #[test]
    fn decode_energy_lt_too_short_returns_err() {
        let data = vec![0u8; ENERGY_RECORD_SIZE - 1];
        let result = decode_energy_lt_record(&data, 1, 0);
        assert!(result.is_err(), "short data must return Err");
    }

    #[test]
    fn decode_energy_lt_exact_size_returns_ok() {
        let data = vec![0u8; ENERGY_RECORD_SIZE];
        let result = decode_energy_lt_record(&data, 1, 0);
        assert!(result.is_ok(), "exact-size data must decode successfully");
    }
}
