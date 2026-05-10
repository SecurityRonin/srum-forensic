import { useState } from 'react';
import { SrumFile, TimelineRecord } from './types';
import { DropZone } from './components/DropZone';
import { Dashboard } from './components/Dashboard';

export default function App() {
  const [srumFile, setSrumFile] = useState<SrumFile | null>(null);
  const [flagFilter, setFlagFilter] = useState<string | null>(null);
  const [_selectedRecord, _setSelectedRecord] = useState<TimelineRecord | null>(null);

  const filtered = srumFile
    ? flagFilter
      ? srumFile.timeline.filter(r => r.flags.includes(flagFilter))
      : srumFile.timeline
    : [];

  return (
    <div style={{ height: '100vh', display: 'flex', flexDirection: 'column', background: '#1A1B1E' }}>
      {!srumFile ? (
        <DropZone onFile={setSrumFile} />
      ) : (
        <>
          <Dashboard
            findings={srumFile.findings}
            activeFlag={flagFilter}
            onFilter={setFlagFilter}
          />
          <div style={{ flex: 1, padding: 16, color: '#C1C2C5' }}>
            {srumFile.path} — {filtered.length} records
          </div>
        </>
      )}
    </div>
  );
}
