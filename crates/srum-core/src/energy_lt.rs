//! Energy Usage Long-Term record — same schema as [`crate::EnergyUsageRecord`].
//!
//! Source table: `{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT` in SRUDB.dat.
//!
//! Windows maintains two energy tables: the standard table records ~1-hour
//! intervals; the LT (Long-Term) table accumulates the same metrics over longer
//! windows (typically 24 h).  Column layout is identical.

/// One SRUM Energy Usage Long-Term record.
pub type EnergyLtRecord = crate::energy::EnergyUsageRecord;
