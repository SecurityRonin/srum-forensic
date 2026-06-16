import { useState } from 'react';
import { SrumFile, TimelineRecord } from './types';
import { DropZone } from './components/DropZone';
import { Dashboard } from './components/Dashboard';
import { FilterBar } from './components/FilterBar';
import { Timeline } from './components/Timeline';
import { RecordDetail } from './components/RecordDetail';

export default function App() {
  const [srumFile, setSrumFile] = useState<SrumFile | null>(null);
  const [flagFilter, setFlagFilter] = useState<string | null>(null);
  const [appFilter, setAppFilter] = useState('');
  const [tableFilter, setTableFilter] = useState('');
  const [filterBarFlag, setFilterBarFlag] = useState('');
  const [selectedRecord, setSelectedRecord] = useState<TimelineRecord | null>(null);

  const filtered = srumFile
    ? srumFile.timeline.filter(r => {
        if (appFilter && !r.app_name?.toLowerCase().includes(appFilter.toLowerCase())) return false;
        if (tableFilter && r.source_table !== tableFilter) return false;
        if (flagFilter && !r.flags.includes(flagFilter)) return false;
        if (filterBarFlag && !r.flags.includes(filterBarFlag)) return false;
        return true;
      })
    : [];

  function clearFilters() {
    setFlagFilter(null);
    setAppFilter('');
    setTableFilter('');
    setFilterBarFlag('');
  }

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
          <FilterBar
            appFilter={appFilter}
            tableFilter={tableFilter}
            flagFilter={filterBarFlag}
            tables={srumFile.table_names}
            onAppFilter={setAppFilter}
            onTableFilter={setTableFilter}
            onFlagFilter={setFilterBarFlag}
            onClear={clearFilters}
            totalRecords={srumFile.record_count}
            filteredRecords={filtered.length}
          />
          {/* Main content: Timeline + optional RecordDetail side panel */}
          <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
            <Timeline records={filtered} onSelect={setSelectedRecord} />
            {selectedRecord && (
              <RecordDetail
                record={selectedRecord}
                onClose={() => setSelectedRecord(null)}
              />
            )}
          </div>
        </>
      )}
    </div>
  );
}
