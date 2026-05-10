export const COLORS = {
  // Severity
  critical:      '#FF4757',
  suspicious:    '#FFA502',
  informational: '#1E90FF',
  clean:         '#2ED573',
  meta:          '#747D8C',

  // Backgrounds
  bg:            '#1A1B1E',
  bgCard:        '#25262B',
  bgHover:       '#2C2D32',
  border:        '#373A40',

  // Text
  textPrimary:   '#C1C2C5',
  textSecondary: '#909296',

  // Table source labels
  sources: {
    network:        '#5352ED',
    apps:           '#2ED573',
    energy:         '#FFA502',
    'energy-lt':    '#FFD43B',
    'app-timeline': '#FF6B81',
    notifications:  '#70A1FF',
    connectivity:   '#ECCC68',
    idmap:          '#747D8C',
  } as Record<string, string>,
} as const;

export function severityColor(s: string): string {
  switch (s) {
    case 'critical':      return COLORS.critical;
    case 'suspicious':    return COLORS.suspicious;
    case 'informational': return COLORS.informational;
    default:              return COLORS.clean;
  }
}

export function sourceColor(table: string): string {
  return COLORS.sources[table] ?? COLORS.meta;
}
