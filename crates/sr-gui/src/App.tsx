import { useState } from 'react';
import { SrumFile, TimelineRecord } from './types';
import { DropZone } from './components/DropZone';
import { Dashboard } from './components/Dashboard';
import { Timeline } from './components/Timeline';

export default function App() {
  const [srumFile, setSrumFile] = useState<SrumFile | null>(null);
  const [flagFilter, setFlagFilter] = useState<string | null>(null);
  const [selectedRecord, setSelectedRecord] = useState<TimelineRecord | null>(null);

  const filtered = srumFile
    ? flagFilter
      ? srumFile.timeline.filter(r => r.flags.includes(flagFilter))
      : srumFile.timeline
    : [];

  void selectedRecord; // used in Task 12 (RecordDetail panel)

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
          <Timeline records={filtered} onSelect={setSelectedRecord} />
        </>
      )}
    </div>
  );
}
