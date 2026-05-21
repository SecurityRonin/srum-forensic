import { useEffect, useRef, useState } from 'react';
import { open } from '@tauri-apps/plugin-dialog';
import { invoke } from '@tauri-apps/api/core';
import { listen, UnlistenFn } from '@tauri-apps/api/event';
import { getCurrentWebview } from '@tauri-apps/api/webview';
import { SrumFile } from '../types';
import { COLORS } from '../colors';

interface Props {
  onFile: (f: SrumFile) => void;
}

interface Progress {
  pct: number;
  label: string;
}

export function DropZone({ onFile }: Props) {
  const [progress, setProgress] = useState<Progress | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const unlistenProgress = useRef<UnlistenFn | null>(null);

  useEffect(() => {
    const webview = getCurrentWebview();
    let unlisten: UnlistenFn | undefined;

    webview.onDragDropEvent((event) => {
      if (event.payload.type === 'enter' || event.payload.type === 'over') {
        setDragOver(true);
      } else if (event.payload.type === 'leave') {
        setDragOver(false);
      } else if (event.payload.type === 'drop') {
        setDragOver(false);
        const paths: string[] = event.payload.paths;
        const dat = paths.find(p => /\.(dat|DAT)$/.test(p) || p.toLowerCase().endsWith('srudb.dat'));
        if (dat) parseFile(dat);
        else if (paths.length > 0) parseFile(paths[0]);
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
    setError(null);
    setProgress({ pct: 0, label: 'Opening…' });

    unlistenProgress.current = await listen<Progress>('parse-progress', (e) => {
      setProgress(e.payload);
    });

    try {
      const result = await invoke<SrumFile>('open_file', { path });
      setProgress({ pct: 100, label: 'Done' });
      setTimeout(() => {
        unlistenProgress.current?.();
        onFile(result);
      }, 300);
    } catch (e) {
      setError(String(e));
      setProgress(null);
    } finally {
      unlistenProgress.current?.();
      unlistenProgress.current = null;
    }
  }

  const loading = progress !== null;

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

      {loading ? (
        <div style={{ width: 340, display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span style={{ color: COLORS.textSecondary, fontSize: 13 }}>{progress.label}</span>
            <span style={{ color: COLORS.textSecondary, fontSize: 13 }}>{progress.pct}%</span>
          </div>
          <div style={{ height: 6, borderRadius: 3, background: 'rgba(255,255,255,0.1)', overflow: 'hidden' }}>
            <div
              style={{
                height: '100%',
                width: `${progress.pct}%`,
                borderRadius: 3,
                background: COLORS.informational,
                transition: 'width 300ms ease',
              }}
            />
          </div>
        </div>
      ) : (
        <button
          onClick={openFile}
          style={{
            padding: '12px 32px',
            background: COLORS.informational,
            color: '#fff',
            border: 'none',
            borderRadius: 6,
            cursor: 'pointer',
            fontSize: 14,
            fontWeight: 600,
          }}
        >
          Open SRUDB.dat
        </button>
      )}

      {error && (
        <p style={{ color: COLORS.critical, maxWidth: 480, textAlign: 'center' }}>{error}</p>
      )}
    </div>
  );
}
