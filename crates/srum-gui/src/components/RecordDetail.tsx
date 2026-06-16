import { TimelineRecord } from '../types';
import { SignalChart } from './SignalChart';
import { COLORS, severityColor, sourceColor } from '../colors';

interface Props {
  record: TimelineRecord;
  onClose: () => void;
}

export function RecordDetail({ record, onClose }: Props) {
  const color = severityColor(record.severity);

  return (
    <div style={{
      width: 380,
      height: '100%',
      background: COLORS.bgCard,
      borderLeft: `1px solid ${COLORS.border}`,
      display: 'flex',
      flexDirection: 'column',
      overflow: 'hidden',
      flexShrink: 0,
    }}>
      {/* Header */}
      <div style={{
        padding: '12px 16px',
        borderBottom: `1px solid ${COLORS.border}`,
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
      }}>
        <span style={{ color: COLORS.textPrimary, fontWeight: 600, fontSize: 13 }}>
          {record.app_name ?? `ID ${record.app_id}`}
        </span>
        <button onClick={onClose} style={{
          background: 'transparent',
          border: 'none',
          color: COLORS.meta,
          cursor: 'pointer',
          fontSize: 18,
          lineHeight: 1,
        }}>×</button>
      </div>

      <div style={{ flex: 1, overflowY: 'auto', padding: '16px' }}>
        {/* Metadata */}
        <Row label="Timestamp" value={record.timestamp.replace('T', ' ').replace('Z', ' UTC')} />
        <Row label="Source" value={record.source_table} valueColor={sourceColor(record.source_table)} />
        <Row label="Key metric" value={`${record.key_metric_label}: ${record.key_metric_value.toLocaleString()}`} />

        {/* Interpretation */}
        {record.interpretation && (
          <div style={{
            margin: '16px 0',
            padding: 12,
            background: `${color}15`,
            borderLeft: `3px solid ${color}`,
            borderRadius: 4,
          }}>
            <p style={{ margin: 0, color: COLORS.textPrimary, fontSize: 12, lineHeight: 1.6 }}>
              {record.interpretation}
            </p>
          </div>
        )}

        {/* 4-way signal */}
        <div style={{ margin: '16px 0' }}>
          <SignalChart
            backgroundCycles={record.background_cycles}
            foregroundCycles={record.foreground_cycles}
            focusTimeMs={record.focus_time_ms}
            userInputTimeMs={record.user_input_time_ms}
          />
        </div>

        {/* Flags */}
        {record.flags.length > 0 && (
          <div style={{ marginBottom: 16 }}>
            <p style={{ color: COLORS.meta, fontSize: 11, margin: '0 0 8px', textTransform: 'uppercase', letterSpacing: 1 }}>
              Heuristic Flags
            </p>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {record.flags.map(f => (
                <span key={f} style={{
                  padding: '3px 8px',
                  background: `${color}22`,
                  color,
                  borderRadius: 4,
                  fontSize: 11,
                  fontWeight: 600,
                  textTransform: 'uppercase',
                }}>{f.replace(/_/g, ' ')}</span>
              ))}
            </div>
          </div>
        )}

        {/* MITRE */}
        {record.mitre_techniques.length > 0 && (
          <div style={{ marginBottom: 16 }}>
            <p style={{ color: COLORS.meta, fontSize: 11, margin: '0 0 8px', textTransform: 'uppercase', letterSpacing: 1 }}>
              MITRE ATT&amp;CK
            </p>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {record.mitre_techniques.map(t => (
                <span key={t} style={{
                  padding: '3px 8px',
                  background: '#373A40',
                  color: COLORS.textSecondary,
                  borderRadius: 4,
                  fontSize: 11,
                }}>{t}</span>
              ))}
            </div>
          </div>
        )}

        {/* Raw fields */}
        <details style={{ marginTop: 8 }}>
          <summary style={{ color: COLORS.meta, fontSize: 11, cursor: 'pointer', textTransform: 'uppercase', letterSpacing: 1 }}>
            Raw Fields
          </summary>
          <pre style={{
            marginTop: 8,
            padding: 10,
            background: '#1A1B1E',
            borderRadius: 4,
            fontSize: 10,
            color: COLORS.textSecondary,
            overflowX: 'auto',
            maxHeight: 300,
          }}>
            {JSON.stringify(record.raw, null, 2)}
          </pre>
        </details>
      </div>
    </div>
  );
}

function Row({ label, value, valueColor }: { label: string; value: string; valueColor?: string }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
      <span style={{ color: COLORS.meta, fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.5 }}>{label}</span>
      <span style={{ color: valueColor ?? COLORS.textPrimary, fontSize: 12, textAlign: 'right', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>{value}</span>
    </div>
  );
}
