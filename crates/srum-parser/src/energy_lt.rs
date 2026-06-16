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
