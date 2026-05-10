import { useState } from 'react';
import { open } from '@tauri-apps/plugin-dialog';
import { invoke } from '@tauri-apps/api/core';
import { SrumFile } from '../types';
import { COLORS } from '../colors';

interface Props {
  onFile: (f: SrumFile) => void;
}

export function DropZone({ onFile }: Props) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function openFile() {
    const selected = await open({
      title: 'Open SRUDB.dat',
      filters: [{ name: 'SRUM Database', extensions: ['dat', 'DAT'] }],
      multiple: false,
    });
    if (!selected || typeof selected !== 'string') return;
    await parseFile(selected);
  }

  async function parseFile(path: string) {
    setLoading(true);
    setError(null);
    try {
      const result = await invoke<SrumFile>('open_file', { path });
      onFile(result);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div
      style={{
        flex: 1,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 24,
      }}
    >
      <h1 style={{ color: COLORS.textPrimary, fontSize: 28, fontWeight: 700, margin: 0 }}>
        SRUM Examiner
      </h1>
      <p style={{ color: COLORS.textSecondary, margin: 0 }}>
        Forensic analysis of Windows SRUM activity databases
      </p>
      <button
        onClick={openFile}
        disabled={loading}
        style={{
          padding: '12px 32px',
          background: COLORS.informational,
          color: '#fff',
          border: 'none',
          borderRadius: 6,
          cursor: loading ? 'not-allowed' : 'pointer',
          fontSize: 14,
          fontWeight: 600,
        }}
      >
        {loading ? 'Parsing…' : 'Open SRUDB.dat'}
      </button>
      {error && (
        <p style={{ color: COLORS.critical, maxWidth: 480, textAlign: 'center' }}>{error}</p>
      )}
    </div>
  );
}
