import React, { useCallback, useRef, useState } from 'react';
import { Check, ChevronDown, ClipboardCopy, Download, FileText, FileType } from 'lucide-react';
import { Button, Tooltip, useDismiss } from './ui';
import { buildMarkdownReport, downloadMarkdownReport } from '../utils/markdownExport';

interface Props {
  /** Downloads the PDF. Each page keeps its own way of making it (stored server copy or built in the browser). */
  onPdf: () => void | Promise<void>;
  /** The full test result, for the Markdown version. May fetch it. */
  getReport: () => any | Promise<any>;
  /** Used in labels, for example the agent name. */
  name?: string;
  iconOnly?: boolean;
  size?: 'sm' | 'md';
  variant?: 'secondary' | 'ghost';
  onError?: (message: string) => void;
}

/** One "Download" button for a report that offers PDF (to share or print) and Markdown (to review with an AI assistant). */
export const ReportDownloadMenu: React.FC<Props> = ({ onPdf, getReport, name, iconOnly, size = 'md', variant = 'secondary', onError }) => {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState<'pdf' | 'md' | 'copy' | null>(null);
  const [copied, setCopied] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const close = useCallback(() => setOpen(false), []);
  useDismiss(ref, open, close);

  const run = async (kind: 'pdf' | 'md' | 'copy') => {
    setOpen(false);
    setBusy(kind);
    try {
      if (kind === 'pdf') {
        await onPdf();
      } else {
        const report = await getReport();
        if (!report) throw new Error('empty');
        if (kind === 'md') {
          downloadMarkdownReport(report);
        } else {
          await navigator.clipboard.writeText(buildMarkdownReport(report));
          setCopied(true);
          window.setTimeout(() => setCopied(false), 2000);
        }
      }
    } catch {
      onError?.(kind === 'pdf' ? 'The PDF could not be created. Try again.' : kind === 'md' ? 'The Markdown report could not be created. Try again.' : 'The report could not be copied. Try Download Markdown instead.');
    } finally {
      setBusy(null);
    }
  };

  const label = name ? `Download report for ${name}` : 'Download report';
  const trigger = (
    <Button
      size={size}
      variant={variant}
      iconOnly={iconOnly}
      icon={copied ? Check : Download}
      loading={busy !== null}
      aria-label={iconOnly ? label : undefined}
      aria-haspopup="menu"
      aria-expanded={open}
      onClick={() => setOpen(o => !o)}
    >
      {copied ? 'Copied' : <>Report <ChevronDown className="report-menu-caret" aria-hidden="true" /></>}
    </Button>
  );

  return (
    <div className="menu-anchor report-menu" ref={ref}>
      {iconOnly ? <Tooltip label={copied ? 'Markdown copied' : 'Download report'}>{trigger}</Tooltip> : trigger}
      {open && (
        <div className="menu report-menu-list" role="menu" aria-label={label}>
          <button type="button" role="menuitem" className="menu-item report-menu-item" onClick={() => run('pdf')}>
            <FileText aria-hidden="true" />
            <span><strong>PDF</strong><small>To share, print or file</small></span>
          </button>
          <button type="button" role="menuitem" className="menu-item report-menu-item" onClick={() => run('md')}>
            <FileType aria-hidden="true" />
            <span><strong>Markdown</strong><small>Full detail, easy for an AI to review</small></span>
          </button>
          <div className="menu-sep" role="separator" />
          <button type="button" role="menuitem" className="menu-item" onClick={() => run('copy')}>
            <ClipboardCopy aria-hidden="true" />
            Copy Markdown to clipboard
          </button>
        </div>
      )}
    </div>
  );
};
