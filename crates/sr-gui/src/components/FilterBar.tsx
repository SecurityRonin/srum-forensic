import { COLORS } from '../colors';

interface Props {
  appFilter: string;
  tableFilter: string;
  flagFilter: string;
  tables: string[];
  onAppFilter: (v: string) => void;
  onTableFilter: (v: string) => void;
  onFlagFilter: (v: string) => void;
  onClear: () => void;
  totalRecords: number;
  filteredRecords: number;
}

const INPUT_STYLE: React.CSSProperties = {
  background: '#25262B',
  border: `1px solid ${COLORS.border}`,
  borderRadius: 4,
  color: COLORS.textPrimary,
  padding: '4px 10px',
  fontSize: 12,
  outline: 'none',
};

const FLAG_OPTIONS = [
  '', 'automated_execution', 'beaconing', 'background_cpu_dominant',
  'exfil_signal', 'suspicious_path', 'masquerade_candidate',
  'phantom_foreground', 'notification_c2', 'selective_gap',
];

export function FilterBar({
  appFilter, tableFilter, flagFilter, tables,
  onAppFilter, onTableFilter, onFlagFilter, onClear,
  totalRecords, filteredRecords,
}: Props) {
  return (
    <div style={{
      display: 'flex',
      gap: 12,
      alignItems: 'center',
      padding: '8px 16px',
      background: COLORS.bgCard,
      borderBottom: `1px solid ${COLORS.border}`,
      flexShrink: 0,
    }}>
      <input
        placeholder="App name…"
        value={appFilter}
        onChange={e => onAppFilter(e.target.value)}
        style={{ ...INPUT_STYLE, width: 180 }}
      />
      <select value={tableFilter} onChange={e => onTableFilter(e.target.value)} style={{ ...INPUT_STYLE, width: 130 }}>
        <option value="">All tables</option>
        {tables.map(t => <option key={t} value={t}>{t}</option>)}
      </select>
      <select value={flagFilter} onChange={e => onFlagFilter(e.target.value)} style={{ ...INPUT_STYLE, width: 200 }}>
        {FLAG_OPTIONS.map(f => (
          <option key={f} value={f}>{f ? f.replace(/_/g, ' ') : 'All flags'}</option>
        ))}
      </select>
      {(appFilter || tableFilter || flagFilter) && (
        <button onClick={onClear} style={{
          background: 'transparent',
          border: `1px solid ${COLORS.border}`,
          color: COLORS.textSecondary,
          borderRadius: 4,
          padding: '4px 10px',
          cursor: 'pointer',
          fontSize: 12,
        }}>Clear</button>
      )}
      <span style={{ marginLeft: 'auto', color: COLORS.meta, fontSize: 11 }}>
        {filteredRecords === totalRecords
          ? `${totalRecords} records`
          : `${filteredRecords} of ${totalRecords} records`}
      </span>
    </div>
  );
}
