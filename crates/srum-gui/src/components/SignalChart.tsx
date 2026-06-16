import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { COLORS } from '../colors';

interface Props {
  backgroundCycles: number | null;
  foregroundCycles: number | null;
  focusTimeMs: number | null;
  userInputTimeMs: number | null;
}

export function SignalChart({ backgroundCycles, foregroundCycles, focusTimeMs, userInputTimeMs }: Props) {
  const hasAnyData = [backgroundCycles, foregroundCycles, focusTimeMs, userInputTimeMs].some(v => v !== null);

  if (!hasAnyData) {
    return <p style={{ color: COLORS.meta, fontSize: 12 }}>4-way signal data not available for this record.</p>;
  }

  const data = [
    { name: 'BG CPU',  value: backgroundCycles ?? 0,  color: COLORS.critical,      label: 'Background CPU cycles' },
    { name: 'FG CPU',  value: foregroundCycles ?? 0,  color: COLORS.suspicious,    label: 'Foreground CPU cycles' },
    { name: 'Focus',   value: focusTimeMs ?? 0,        color: COLORS.informational, label: 'Focus time (ms)' },
    { name: 'Input',   value: userInputTimeMs ?? 0,    color: COLORS.clean,         label: 'User input time (ms)' },
  ];

  return (
    <div>
      <p style={{ color: COLORS.meta, fontSize: 11, margin: '0 0 8px', letterSpacing: 1, textTransform: 'uppercase' }}>
        Activity Signal
      </p>
      <ResponsiveContainer width="100%" height={120}>
        <BarChart data={data} layout="vertical" margin={{ left: 0, right: 16 }}>
          <XAxis type="number" hide />
          <YAxis type="category" dataKey="name" width={55} tick={{ fill: COLORS.meta, fontSize: 11 }} />
          <Tooltip
            formatter={(value: number, _name: string, entry: any) => [
              value.toLocaleString(),
              entry.payload.label,
            ]}
            contentStyle={{ background: COLORS.bgCard, border: `1px solid ${COLORS.border}`, borderRadius: 4 }}
          />
          <Bar dataKey="value" radius={[0, 3, 3, 0]}>
            {data.map(entry => (
              <Cell key={entry.name} fill={entry.color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
      <p style={{ color: COLORS.meta, fontSize: 10, marginTop: 6 }}>
        Red = background (automated) · Amber = foreground (visible) · Blue = focus (user present) · Green = input (user active)
      </p>
    </div>
  );
}
