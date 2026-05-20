import { useEffect, useState } from 'react';
import { open } from '@tauri-apps/plugin-dialog';
import { invoke } from '@tauri-apps/api/core';
import { getCurrentWebview } from '@tauri-apps/api/webview';
import { SrumFile } from '../types';
import { COLORS } from '../colors';

interface Props {
  onFile: (f: SrumFile) => void;
}

export function DropZone({ onFile }: Props) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);

  useEffect(() => {
    const webview = getCurrentWebview();
    let unlisten: (() => void) | undefined;

    webview.onDragDropEvent((event) => {
      if (event.payload.type === 'enter' || event.payload.type === 'over') {
        setDragOver(true);
      } else if (event.payload.type === 'leave') {
        setDragOver(false);
      } else if (event.payload.type === 'drop') {
        setDragOver(false);
        const paths: string[] = event.payload.paths;
        const dat = paths.find(p => /\.(dat|DAT)$/.test(p) || p.toLowerCase().endsWith('srudb.dat'));
        if (dat) {
          parseFile(dat);
        } else if (paths.length > 0) {
          parseFile(paths[0]);
        }
      }
    }).then(fn => { unlisten = fn; });

    return () => { unlisten?.(); };
  }, []);

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
        outline: dragOver ? `2px dashed ${COLORS.informational}` : '2px dashed transparent',
        outlineOffset: -12,
        borderRadius: 12,
        transition: 'outline-color 120ms ease',
        background: dragOver ? 'rgba(66,153,225,0.06)' : 'transparent',
      }}
    >
      <h1 style={{ color: COLORS.textPrimary, fontSize: 28, fontWeight: 700, margin: 0 }}>
        SRUM Examiner
      </h1>
      <p style={{ color: COLORS.textSecondary, margin: 0 }}>
        {dragOver ? 'Drop to open' : 'Drop SRUDB.dat here, or click below'}
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
          opacity: loading ? 0.6 : 1,
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
