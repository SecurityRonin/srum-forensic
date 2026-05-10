import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  flexRender,
  createColumnHelper,
  SortingState,
} from '@tanstack/react-table';
import { useState } from 'react';
import { TimelineRecord } from '../types';
import { COLORS, severityColor, sourceColor } from '../colors';

const col = createColumnHelper<TimelineRecord>();

const columns = [
  col.accessor('timestamp', {
    header: 'Timestamp',
    size: 180,
    cell: info => (
      <span style={{ color: COLORS.meta, fontFamily: 'monospace' }}>
        {info.getValue().replace('T', ' ').replace('Z', '')}
      </span>
    ),
  }),
  col.accessor('source_table', {
    header: 'Source',
    size: 110,
    cell: info => (
      <span style={{
        color: sourceColor(info.getValue()),
        fontWeight: 600,
        fontSize: 11,
        textTransform: 'uppercase',
        letterSpacing: 0.5,
      }}>
        {info.getValue()}
      </span>
    ),
  }),
  col.accessor('app_name', {
    header: 'Application',
    size: 200,
    cell: info => (
      <span style={{ color: COLORS.textPrimary }}>
        {info.getValue() ?? `ID ${info.row.original.app_id}`}
      </span>
    ),
  }),
  col.display({
    id: 'key_metric',
    header: 'Key Metric',
    size: 160,
    cell: info => {
      const r = info.row.original;
      return (
        <span style={{ color: COLORS.textSecondary }}>
          {r.key_metric_label}: {r.key_metric_value.toLocaleString()}
        </span>
      );
    },
  }),
  col.accessor('flags', {
    header: 'Flags',
    size: 200,
    cell: info => {
      const flags = info.getValue();
      if (!flags.length) return null;
      const severity = info.row.original.severity;
      return (
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {flags.slice(0, 3).map(f => (
            <span key={f} style={{
              fontSize: 9,
              background: `${severityColor(severity)}33`,
              color: severityColor(severity),
              padding: '2px 6px',
              borderRadius: 3,
              fontWeight: 600,
              textTransform: 'uppercase',
              letterSpacing: 0.5,
            }}>{f.replace(/_/g, ' ')}</span>
          ))}
        </div>
      );
    },
  }),
];

interface Props {
  records: TimelineRecord[];
  onSelect: (record: TimelineRecord) => void;
}

export function Timeline({ records, onSelect }: Props) {
  const [sorting, setSorting] = useState<SortingState>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const table = useReactTable({
    data: records,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  return (
    <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
      {/* Header */}
      <div style={{
        display: 'flex',
        borderBottom: `1px solid ${COLORS.border}`,
        background: COLORS.bgCard,
        flexShrink: 0,
      }}>
        {table.getHeaderGroups().map(hg =>
          hg.headers.map(header => (
            <div
              key={header.id}
              onClick={header.column.getToggleSortingHandler()}
              style={{
                width: header.getSize(),
                padding: '8px 12px',
                color: COLORS.meta,
                fontSize: 11,
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: 1,
                cursor: header.column.getCanSort() ? 'pointer' : 'default',
                userSelect: 'none',
                flexShrink: 0,
              }}
            >
              {flexRender(header.column.columnDef.header, header.getContext())}
              {header.column.getIsSorted() === 'asc' ? ' ↑' : header.column.getIsSorted() === 'desc' ? ' ↓' : ''}
            </div>
          ))
        )}
      </div>

      {/* Body */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {table.getRowModel().rows.map(row => {
          const rec = row.original;
          const isSelected = selectedId === row.id;
          const color = severityColor(rec.severity);
          const hasFlags = rec.flags.length > 0;

          return (
            <div
              key={row.id}
              onClick={() => {
                setSelectedId(row.id);
                onSelect(rec);
              }}
              style={{
                display: 'flex',
                alignItems: 'center',
                borderLeft: hasFlags ? `4px solid ${color}` : '4px solid transparent',
                background: isSelected ? `${color}15` : 'transparent',
                borderBottom: `1px solid ${COLORS.border}`,
                cursor: 'pointer',
              }}
              onMouseEnter={e => {
                if (!isSelected) (e.currentTarget as HTMLDivElement).style.background = COLORS.bgHover;
              }}
              onMouseLeave={e => {
                if (!isSelected) (e.currentTarget as HTMLDivElement).style.background = 'transparent';
              }}
            >
              {row.getVisibleCells().map(cell => (
                <div
                  key={cell.id}
                  style={{
                    width: cell.column.getSize(),
                    padding: '7px 12px',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    flexShrink: 0,
                  }}
                >
                  {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </div>
              ))}
            </div>
          );
        })}
      </div>
    </div>
  );
}
