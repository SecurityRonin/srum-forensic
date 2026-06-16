import { FindingCard } from '../types';
import { COLORS, severityColor } from '../colors';

interface Props {
  findings: FindingCard[];
  activeFlag: string | null;
  onFilter: (flag: string | null) => void;
}

export function Dashboard({ findings, activeFlag, onFilter }: Props) {
  if (findings.length === 0) {
    return (
      <div style={{
        height: 120,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        borderBottom: `1px solid ${COLORS.border}`,
        color: COLORS.clean,
        fontWeight: 600,
        flexShrink: 0,
      }}>
        No suspicious activity detected
      </div>
    );
  }

  return (
    <div style={{
      height: 140,
      borderBottom: `1px solid ${COLORS.border}`,
      display: 'flex',
      alignItems: 'center',
      gap: 12,
      padding: '0 16px',
      overflowX: 'auto',
      flexShrink: 0,
    }}>
      {findings.map(card => (
        <FindingCardComponent
          key={card.filter_flag}
          card={card}
          active={activeFlag === card.filter_flag}
          onClick={() => onFilter(activeFlag === card.filter_flag ? null : card.filter_flag)}
        />
      ))}
    </div>
  );
}

function FindingCardComponent({
  card,
  active,
  onClick,
}: {
  card: FindingCard;
  active: boolean;
  onClick: () => void;
}) {
  const color = severityColor(card.severity);

  return (
    <button
      onClick={onClick}
      style={{
        minWidth: 220,
        maxWidth: 260,
        height: 108,
        background: active ? `${color}22` : COLORS.bgCard,
        border: `1px solid ${active ? color : COLORS.border}`,
        borderLeft: `4px solid ${color}`,
        borderRadius: 6,
        padding: '10px 14px',
        cursor: 'pointer',
        textAlign: 'left',
        flexShrink: 0,
        display: 'flex',
        flexDirection: 'column',
        gap: 4,
      }}
    >
      <div style={{ color, fontSize: 11, fontWeight: 700, letterSpacing: 1 }}>
        {card.title}
      </div>
      <div style={{ color: COLORS.textPrimary, fontSize: 13, fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {card.app_name}
      </div>
      <div style={{ color: COLORS.textSecondary, fontSize: 11, flex: 1 }}>
        {card.description}
      </div>
      {card.mitre_techniques.length > 0 && (
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {card.mitre_techniques.slice(0, 3).map(t => (
            <span key={t} style={{
              fontSize: 9,
              background: '#373A40',
              color: COLORS.textSecondary,
              padding: '1px 5px',
              borderRadius: 3,
            }}>{t}</span>
          ))}
        </div>
      )}
    </button>
  );
}
