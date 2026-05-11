//! Per-table SRUM column schema definitions.
//!
//! Column IDs match the ESE catalog column_id values observed in real SRUDB.dat files.
//! Columns 1-4 are shared across all SRUM extension tables (base schema).
//! Table-specific columns start at 5.

use forensicnomicon::srum::{
    TABLE_APP_RESOURCE_USAGE, TABLE_APP_TIMELINE, TABLE_ENERGY_USAGE, TABLE_ENERGY_USAGE_LT,
    TABLE_ID_MAP, TABLE_NETWORK_CONNECTIVITY, TABLE_NETWORK_USAGE, TABLE_PUSH_NOTIFICATIONS,
};

/// A single SRUM column definition (compile-time static data).
pub struct SrumColumnDef {
    /// 1-based column identifier matching the ESE catalog column_id.
    pub column_id: u32,
    /// Column name as it appears in MSysObjects.
    pub name: &'static str,
    /// JET column type code (see ese-core coltyp constants).
    ///
    /// Common values: 4=LONG(i32), 15=LONG_LONG(i64), 18=UNSIGNED_LONG_LONG(u64),
    /// 8=DATE_TIME(f64 OLE), 2=UNSIGNED_BYTE, 11=LONG_BINARY, 17=UNSIGNED_SHORT.
    pub coltyp: u8,
}

// ── shared base columns (present on all extension tables) ─────────────────────

const BASE: &[SrumColumnDef] = &[
    SrumColumnDef { column_id: 1, name: "AutoIncId",  coltyp: 4  }, // LONG
    SrumColumnDef { column_id: 2, name: "TimeStamp",  coltyp: 8  }, // DATE_TIME
    SrumColumnDef { column_id: 3, name: "AppId",      coltyp: 4  }, // LONG
    SrumColumnDef { column_id: 4, name: "UserId",     coltyp: 4  }, // LONG
];

// ── Network Data Usage ────────────────────────────────────────────────────────

static NETWORK_USAGE_COLS: &[SrumColumnDef] = &[
    SrumColumnDef { column_id: 1, name: "AutoIncId",       coltyp: 4  },
    SrumColumnDef { column_id: 2, name: "TimeStamp",       coltyp: 8  },
    SrumColumnDef { column_id: 3, name: "AppId",           coltyp: 4  },
    SrumColumnDef { column_id: 4, name: "UserId",          coltyp: 4  },
    SrumColumnDef { column_id: 5, name: "InterfaceLuid",   coltyp: 15 }, // LONG_LONG
    SrumColumnDef { column_id: 6, name: "L2ProfileId",     coltyp: 4  },
    SrumColumnDef { column_id: 7, name: "L2ProfileFlags",  coltyp: 4  },
    SrumColumnDef { column_id: 8, name: "BytesSent",       coltyp: 15 },
    SrumColumnDef { column_id: 9, name: "BytesRecvd",      coltyp: 15 },
];

// ── App Resource Usage ────────────────────────────────────────────────────────

static APP_USAGE_COLS: &[SrumColumnDef] = &[
    SrumColumnDef { column_id: 1,  name: "AutoIncId",                     coltyp: 4  },
    SrumColumnDef { column_id: 2,  name: "TimeStamp",                     coltyp: 8  },
    SrumColumnDef { column_id: 3,  name: "AppId",                         coltyp: 4  },
    SrumColumnDef { column_id: 4,  name: "UserId",                        coltyp: 4  },
    SrumColumnDef { column_id: 5,  name: "ForegroundCycleTime",           coltyp: 18 }, // UNSIGNED_LONG_LONG
    SrumColumnDef { column_id: 6,  name: "BackgroundCycleTime",           coltyp: 18 },
    SrumColumnDef { column_id: 7,  name: "FaceTime",                      coltyp: 15 }, // LONG_LONG
    SrumColumnDef { column_id: 8,  name: "ForegroundContextSwitches",     coltyp: 4  },
    SrumColumnDef { column_id: 9,  name: "BackgroundContextSwitches",     coltyp: 4  },
    SrumColumnDef { column_id: 10, name: "ForegroundBytesRead",           coltyp: 15 },
    SrumColumnDef { column_id: 11, name: "ForegroundBytesWritten",        coltyp: 15 },
    SrumColumnDef { column_id: 12, name: "ForegroundNumReadOperations",   coltyp: 4  },
    SrumColumnDef { column_id: 13, name: "ForegroundNumWriteOperations",  coltyp: 4  },
    SrumColumnDef { column_id: 14, name: "ForegroundNumberOfFlushes",     coltyp: 4  },
    SrumColumnDef { column_id: 15, name: "BackgroundBytesRead",           coltyp: 15 },
    SrumColumnDef { column_id: 16, name: "BackgroundBytesWritten",        coltyp: 15 },
    SrumColumnDef { column_id: 17, name: "BackgroundNumReadOperations",   coltyp: 4  },
    SrumColumnDef { column_id: 18, name: "BackgroundNumWriteOperations",  coltyp: 4  },
    SrumColumnDef { column_id: 19, name: "BackgroundNumberOfFlushes",     coltyp: 4  },
];

// ── Network Connectivity ──────────────────────────────────────────────────────

static NETWORK_CONN_COLS: &[SrumColumnDef] = &[
    SrumColumnDef { column_id: 1, name: "AutoIncId",         coltyp: 4  },
    SrumColumnDef { column_id: 2, name: "TimeStamp",         coltyp: 8  },
    SrumColumnDef { column_id: 3, name: "AppId",             coltyp: 4  },
    SrumColumnDef { column_id: 4, name: "UserId",            coltyp: 4  },
    SrumColumnDef { column_id: 5, name: "InterfaceLuid",     coltyp: 15 },
    SrumColumnDef { column_id: 6, name: "L2ProfileId",       coltyp: 4  },
    SrumColumnDef { column_id: 7, name: "ConnectedTime",     coltyp: 4  },
    SrumColumnDef { column_id: 8, name: "ConnectStartTime",  coltyp: 8  },
    SrumColumnDef { column_id: 9, name: "L2ProfileFlags",    coltyp: 4  },
];

// ── Energy Usage (shared schema for both tables) ──────────────────────────────

static ENERGY_USAGE_COLS: &[SrumColumnDef] = &[
    SrumColumnDef { column_id: 1,  name: "AutoIncId",              coltyp: 4  },
    SrumColumnDef { column_id: 2,  name: "TimeStamp",              coltyp: 8  },
    SrumColumnDef { column_id: 3,  name: "AppId",                  coltyp: 4  },
    SrumColumnDef { column_id: 4,  name: "UserId",                 coltyp: 4  },
    SrumColumnDef { column_id: 5,  name: "EventTimestamp",         coltyp: 8  },
    SrumColumnDef { column_id: 6,  name: "StateTransition",        coltyp: 4  },
    SrumColumnDef { column_id: 7,  name: "FullChargedCapacity",    coltyp: 4  },
    SrumColumnDef { column_id: 8,  name: "DesignedCapacity",       coltyp: 4  },
    SrumColumnDef { column_id: 9,  name: "ChargeLevel",            coltyp: 4  },
    SrumColumnDef { column_id: 10, name: "ActiveAcTime",           coltyp: 4  },
    SrumColumnDef { column_id: 11, name: "CsAcTime",               coltyp: 4  },
    SrumColumnDef { column_id: 12, name: "ActiveDcOnBatteryTime",  coltyp: 4  },
    SrumColumnDef { column_id: 13, name: "CsDcOnBatteryTime",      coltyp: 4  },
    SrumColumnDef { column_id: 14, name: "ActiveDischargeTime",    coltyp: 4  },
    SrumColumnDef { column_id: 15, name: "CsDischargeTime",        coltyp: 4  },
    SrumColumnDef { column_id: 16, name: "ActiveEnergy",           coltyp: 4  },
    SrumColumnDef { column_id: 17, name: "CsEnergy",               coltyp: 4  },
];

// ── Push Notifications ────────────────────────────────────────────────────────

static PUSH_NOTIF_COLS: &[SrumColumnDef] = &[
    SrumColumnDef { column_id: 1, name: "AutoIncId",         coltyp: 4 },
    SrumColumnDef { column_id: 2, name: "TimeStamp",         coltyp: 8 },
    SrumColumnDef { column_id: 3, name: "AppId",             coltyp: 4 },
    SrumColumnDef { column_id: 4, name: "UserId",            coltyp: 4 },
    SrumColumnDef { column_id: 5, name: "NotificationType",  coltyp: 4 },
    SrumColumnDef { column_id: 6, name: "PayloadSize",       coltyp: 4 },
    SrumColumnDef { column_id: 7, name: "NetworkType",       coltyp: 4 },
];

// ── Application Timeline ──────────────────────────────────────────────────────

static APP_TIMELINE_COLS: &[SrumColumnDef] = &[
    SrumColumnDef { column_id: 1,  name: "AutoIncId",               coltyp: 4  },
    SrumColumnDef { column_id: 2,  name: "TimeStamp",               coltyp: 8  },
    SrumColumnDef { column_id: 3,  name: "AppId",                   coltyp: 4  },
    SrumColumnDef { column_id: 4,  name: "UserId",                  coltyp: 4  },
    SrumColumnDef { column_id: 5,  name: "DurationMS",              coltyp: 4  },
    SrumColumnDef { column_id: 6,  name: "SpanMS",                  coltyp: 4  },
    SrumColumnDef { column_id: 7,  name: "TimelineEnd",             coltyp: 8  },
    SrumColumnDef { column_id: 8,  name: "InFocusDurationMS",       coltyp: 4  },
    SrumColumnDef { column_id: 9,  name: "UserInputMS",             coltyp: 4  },
    SrumColumnDef { column_id: 10, name: "CompRenderedDuration",    coltyp: 4  },
    SrumColumnDef { column_id: 11, name: "CompDirtyDuration",       coltyp: 4  },
    SrumColumnDef { column_id: 12, name: "CompPropagatedDuration",  coltyp: 4  },
    SrumColumnDef { column_id: 13, name: "AudioInDuration",         coltyp: 4  },
    SrumColumnDef { column_id: 14, name: "AudioOutDuration",        coltyp: 4  },
    SrumColumnDef { column_id: 15, name: "NetworkBytesRaw",         coltyp: 15 },
    SrumColumnDef { column_id: 16, name: "MBBBytesRaw",             coltyp: 15 },
    SrumColumnDef { column_id: 17, name: "NetworkTailBytesRaw",     coltyp: 15 },
    SrumColumnDef { column_id: 18, name: "MBBTailBytesRaw",         coltyp: 15 },
    SrumColumnDef { column_id: 19, name: "MBBBytesSent",            coltyp: 15 },
];

// ── ID Map ────────────────────────────────────────────────────────────────────

static ID_MAP_COLS: &[SrumColumnDef] = &[
    SrumColumnDef { column_id: 1, name: "IdType",   coltyp: 2  }, // UNSIGNED_BYTE
    SrumColumnDef { column_id: 2, name: "IdIndex",  coltyp: 4  }, // LONG
    SrumColumnDef { column_id: 3, name: "IdBlob",   coltyp: 11 }, // LONG_BINARY
];

// ── dispatch ─────────────────────────────────────────────────────────────────

pub fn column_defs_for(guid: &str) -> Option<&'static [SrumColumnDef]> {
    // Suppress "unused" warnings for BASE until a future story uses it.
    let _ = BASE;
    match guid {
        x if x == TABLE_NETWORK_USAGE         => Some(NETWORK_USAGE_COLS),
        x if x == TABLE_APP_RESOURCE_USAGE    => Some(APP_USAGE_COLS),
        x if x == TABLE_NETWORK_CONNECTIVITY  => Some(NETWORK_CONN_COLS),
        x if x == TABLE_ENERGY_USAGE          => Some(ENERGY_USAGE_COLS),
        x if x == TABLE_ENERGY_USAGE_LT       => Some(ENERGY_USAGE_COLS),
        x if x == TABLE_PUSH_NOTIFICATIONS    => Some(PUSH_NOTIF_COLS),
        x if x == TABLE_APP_TIMELINE          => Some(APP_TIMELINE_COLS),
        x if x == TABLE_ID_MAP                => Some(ID_MAP_COLS),
        _ => None,
    }
}
