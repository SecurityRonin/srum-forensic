//! ESE record decoding — column definitions and value types.

use crate::EseError;

/// JET column type codes (coltyp field in MSysObjects).
pub mod coltyp {
    pub const BIT: u8 = 1;
    pub const UNSIGNED_BYTE: u8 = 2;
    pub const SHORT: u8 = 3;
    pub const LONG: u8 = 4;
    pub const CURRENCY: u8 = 5;
    pub const IEEE_SINGLE: u8 = 6;
    pub const IEEE_DOUBLE: u8 = 7;
    pub const DATE_TIME: u8 = 8;
    pub const BINARY: u8 = 9;
    pub const TEXT: u8 = 10;
    pub const LONG_BINARY: u8 = 11;
    pub const LONG_TEXT: u8 = 12;
    pub const GUID: u8 = 16;
    pub const UNSIGNED_SHORT: u8 = 17;
    pub const UNSIGNED_LONG: u8 = 14;
    pub const LONG_LONG: u8 = 15;
    pub const UNSIGNED_LONG_LONG: u8 = 18;
}

/// A column definition from the ESE catalog.
#[derive(Debug, Clone)]
pub struct ColumnDef {
    /// 1-based column identifier (matches ESE catalog column_id).
    pub column_id: u32,
    /// Human-readable column name.
    pub name: String,
    /// JET column type code (see [`coltyp`] constants).
    pub coltyp: u8,
}

/// A decoded ESE column value.
#[derive(Debug, Clone, serde::Serialize)]
pub enum EseValue {
    Null,
    Bool(bool),
    U8(u8),
    I16(i16),
    I32(i32),
    I64(i64),
    U16(u16),
    U32(u32),
    U64(u64),
    F32(f32),
    F64(f64),
    /// OLE Automation Date: days since 1899-12-30 as a floating-point number.
    DateTime(f64),
    Binary(Vec<u8>),
    Text(String),
    Guid([u8; 16]),
}

/// Return the fixed byte size for a fixed-length coltyp, or `None` for
/// variable-length (Binary, Text) and tagged (LongBinary, LongText) types.
pub fn fixed_col_size(coltyp: u8) -> Option<usize> {
    match coltyp {
        coltyp::BIT | coltyp::UNSIGNED_BYTE => Some(1),
        coltyp::SHORT | coltyp::UNSIGNED_SHORT => Some(2),
        coltyp::LONG | coltyp::UNSIGNED_LONG | coltyp::IEEE_SINGLE => Some(4),
        coltyp::CURRENCY | coltyp::IEEE_DOUBLE | coltyp::DATE_TIME
        | coltyp::LONG_LONG | coltyp::UNSIGNED_LONG_LONG => Some(8),
        coltyp::GUID => Some(16),
        _ => None, // variable or tagged
    }
}

/// Decode one fixed-length column value from `data` (exactly `fixed_col_size` bytes).
fn decode_fixed(data: &[u8], coltyp: u8) -> EseValue {
    match coltyp {
        coltyp::BIT => EseValue::Bool(data[0] != 0),
        coltyp::UNSIGNED_BYTE => EseValue::U8(data[0]),
        coltyp::SHORT => EseValue::I16(i16::from_le_bytes([data[0], data[1]])),
        coltyp::UNSIGNED_SHORT => EseValue::U16(u16::from_le_bytes([data[0], data[1]])),
        coltyp::LONG => EseValue::I32(i32::from_le_bytes([data[0], data[1], data[2], data[3]])),
        coltyp::UNSIGNED_LONG => {
            EseValue::U32(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
        }
        coltyp::IEEE_SINGLE => {
            EseValue::F32(f32::from_le_bytes([data[0], data[1], data[2], data[3]]))
        }
        coltyp::CURRENCY | coltyp::LONG_LONG => EseValue::I64(i64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ])),
        coltyp::UNSIGNED_LONG_LONG => EseValue::U64(u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ])),
        coltyp::IEEE_DOUBLE => EseValue::F64(f64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ])),
        coltyp::DATE_TIME => EseValue::DateTime(f64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ])),
        coltyp::GUID => {
            let mut g = [0u8; 16];
            g.copy_from_slice(&data[..16]);
            EseValue::Guid(g)
        }
        _ => EseValue::Binary(data.to_vec()),
    }
}

/// Decode an ESE data record into named column values.
///
/// # Record format (Vista+)
///
/// ```text
/// Offset 0:  last_fixed_col_id   (u8)  — highest fixed column ID in this record
/// Offset 1:  last_var_col_idx    (u8)  — count of variable columns in this record
/// Offset 2:  var_data_offset     (u16) — offset from record start to variable data
/// Offset 4…: fixed column data (packed, column_id 1 through last_fixed_col_id)
/// var_data_offset…end-of-var: variable column data
/// (var_data_offset - 4 - fixed_size) / 2 entries before var data: end offsets
/// ```
///
/// Fixed-column data is packed contiguously in column_id order starting at byte 4.
/// Each column occupies exactly [`fixed_col_size`] bytes regardless of nullity
/// (null fixed columns are stored as zero bytes in their normal slot).
///
/// Variable columns follow: a 2-byte per-column end-offset array immediately
/// before the variable data (end offsets relative to `var_data_offset`).
/// High bit of an offset entry indicates a NULL variable column.
///
/// # Errors
///
/// Returns `EseError::Corrupt` if the header cannot be read or an offset is out
/// of bounds. Unknown coltypes are returned as `EseValue::Binary`.
pub fn decode_record(data: &[u8], columns: &[ColumnDef]) -> Result<Vec<(String, EseValue)>, EseError> {
    // RED STUB: always returns empty vec so decode tests fail.
    let _ = (data, columns);
    Ok(Vec::new())
}
