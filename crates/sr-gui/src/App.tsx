import { useState } from 'react';
import { SrumFile, TimelineRecord, FindingCard } from './types';

export default function App() {
  const [srumFile, setSrumFile] = useState<SrumFile | null>(null);
  const [flagFilter, setFlagFilter] = useState<string | null>(null);
  const [_selectedRecord, setSelectedRecord] = useState<TimelineRecord | null>(null);

  const filtered = srumFile
    ? flagFilter
      ? srumFile.timeline.filter(r => r.flags.includes(flagFilter))
      : srumFile.timeline
    : [];

  return (
    <div style={{ height: '100vh', display: 'flex', flexDirection: 'column', background: '#1A1B1E' }}>
      {!srumFile ? (
        <DropZonePlaceholder onFile={setSrumFile} />
      ) : (
        <>
          <DashboardPlaceholder findings={srumFile.findings} onFilter={setFlagFilter} />
          <TimelinePlaceholder records={filtered} onSelect={setSelectedRecord} />
        </>
      )}
    </div>
  );
}

function DropZonePlaceholder({ onFile }: { onFile: (f: SrumFile) => void }) {
  void onFile;
  return (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <p style={{ color: '#747D8C' }}>SRUM Examiner — open a SRUDB.dat to begin</p>
    </div>
  );
}

function DashboardPlaceholder({ findings, onFilter }: { findings: FindingCard[]; onFilter: (flag: string | null) => void }) {
  void onFilter;
  return (
    <div style={{ height: 140, borderBottom: '1px solid #373A40', display: 'flex', alignItems: 'center', padding: '0 16px', color: '#747D8C' }}>
      Dashboard ({findings.length} findings)
    </div>
  );
}

function TimelinePlaceholder({ records, onSelect }: { records: TimelineRecord[]; onSelect: (r: TimelineRecord) => void }) {
  void onSelect;
  return (
    <div style={{ flex: 1, padding: 16, color: '#C1C2C5' }}>
      Timeline ({records.length} records)
    </div>
  );
}
