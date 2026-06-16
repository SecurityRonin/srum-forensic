export type Severity = 'critical' | 'suspicious' | 'informational' | 'clean';

export interface TimelineRecord {
  timestamp: string;
  source_table: string;
  app_id: number;
  app_name: string | null;
  key_metric_label: string;
  key_metric_value: number;
  flags: string[];
  severity: Severity;
  raw: Record<string, unknown>;
  background_cycles: number | null;
  foreground_cycles: number | null;
  focus_time_ms: number | null;
  user_input_time_ms: number | null;
  interpretation: string | null;
  mitre_techniques: string[];
}

export interface FindingCard {
  title: string;
  app_name: string;
  description: string;
  mitre_techniques: string[];
  severity: Severity;
  filter_flag: string;
  count: number;
}

export interface TemporalSpan {
  first: string;
  last: string;
}

export interface SrumFile {
  path: string;
  timeline: TimelineRecord[];
  findings: FindingCard[];
  record_count: number;
  temporal_span: TemporalSpan | null;
  table_names: string[];
}
