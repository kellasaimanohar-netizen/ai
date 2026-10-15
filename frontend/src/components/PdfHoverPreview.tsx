import React, { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { X } from 'lucide-react';
import { getReportPdfUrl } from '../utils/reportPdf';
import { useFocusTrap } from './ui';

const WIDTH = 440;
const HEIGHT = 560;

/** Wraps a button. Hovering it shows the test's PDF report in a floating preview. Clicking still does whatever the button does. */
export const PdfHoverPreview: React.FC<{ testId: number; children: React.ReactNode }> = ({ testId, children }) => {
  const anchor = useRef<HTMLSpanElement>(null);
  const timer = useRef<number | undefined>(undefined);
  const [pos, setPos] = useState<{ left: number; top: number } | null>(null);
  const [url, setUrl] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => () => window.clearTimeout(timer.current), []);

  const open = () => {
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => {
      const r = anchor.current?.getBoundingClientRect();
      if (!r) return;
      const left = r.left - WIDTH - 12 >= 8 ? r.left - WIDTH - 12 : Math.min(r.right + 12, window.innerWidth - WIDTH - 8);
      const top = Math.max(8, Math.min(r.top + r.height / 2 - HEIGHT / 2, window.innerHeight - HEIGHT - 8));
      setPos({ left, top });
      if (!url) getReportPdfUrl(testId).then(setUrl).catch(() => setFailed(true));
    }, 350);
  };
  const close = () => {
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setPos(null), 150);
  };

  return (
    <span ref={anchor} style={{ display: 'inline-block' }} onMouseEnter={open} onMouseLeave={close}>
      {children}
      {pos && createPortal(
        <div
          className="doc-preview"
          role="dialog"
          aria-label="Report preview"
          onMouseEnter={() => window.clearTimeout(timer.current)}
          onMouseLeave={close}
          style={{ left: pos.left, top: pos.top, width: WIDTH, height: HEIGHT }}
        >
          {url ? (
            <iframe className="doc-frame" title="PDF report preview" src={`${url}#page=1&view=FitH&toolbar=0&navpanes=0`} />
          ) : (
            <div className="doc-status">{failed ? 'The report could not be loaded.' : <><span className="spinner" aria-hidden="true" />Loading report</>}</div>
          )}
        </div>,
        document.body
      )}
    </span>
  );
};

/** Full-size in-page viewer for a test's PDF report. Closes with the button, the backdrop or Escape. */
export const PdfViewerModal: React.FC<{ testId: number; title?: string; onClose: () => void }> = ({ testId, title, onClose }) => {
  const [url, setUrl] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useFocusTrap(ref, true);

  useEffect(() => {
    getReportPdfUrl(testId).then(setUrl).catch(() => setFailed(true));
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [testId, onClose]);

  return createPortal(
    <div className="modal-layer" style={{ paddingTop: '4vh' }} onPointerDown={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div
        ref={ref}
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-label={title || 'Audit report'}
        style={{ maxWidth: 960, width: '100%', height: 'min(92vh, 1100px)', maxHeight: 'none' }}
      >
        <div className="modal-head" style={{ alignItems: 'center', borderBottom: '1px solid var(--color-border)', paddingBottom: 12, paddingTop: 12 }}>
          <h2 style={{ fontSize: 16 }}>{title || 'Audit report'}</h2>
          <button className="icon-btn" onClick={onClose} aria-label="Close report" data-autofocus><X /></button>
        </div>
        {url ? (
          <iframe className="doc-frame" title="PDF report" src={`${url}#page=1&view=FitH`} />
        ) : (
          <div className="doc-status">{failed ? 'The report could not be loaded.' : <><span className="spinner" aria-hidden="true" />Loading report</>}</div>
        )}
      </div>
    </div>,
    document.body
  );
};
