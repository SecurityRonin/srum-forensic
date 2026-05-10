import { useState } from 'react';
import { SrumFile, TimelineRecord } from './types';
import { DropZone } from './components/DropZone';
import { Dashboard } from './components/Dashboard';
import { FilterBar } from './components/FilterBar';
import { Timeline } from './components/Timeline';

export default function App() {
  const [srumFile, setSrumFile] = useState<SrumFile | null>(null);
  const [flagFilter, setFlagFilter] = useState<string | null>(null);  // from Dashboard card click
  const [appFilter, setAppFilter] = useState('');
  const [tableFilter, setTableFilter] = useState('');
  const [filterBarFlag, setFilterBarFlag] = useState('');  // from FilterBar dropdown
  const [selectedRecord, setSelectedRecord] = useState<TimelineRecord | null>(null);

  void selectedRecord; // used in Task 12

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
          <Timeline records={filtered} onSelect={setSelectedRecord} />
        </>
      )}
    </div>
  );
}
