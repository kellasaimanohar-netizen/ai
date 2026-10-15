import React, { useCallback, useEffect, useId, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import {
  AlertCircle, AlertTriangle, ArrowDown, ArrowUp, ArrowUpDown, CheckCircle2, ChevronDown, ChevronLeft, ChevronRight,
  Info, Minus, Search, TrendingDown, TrendingUp, X,
} from 'lucide-react';

/**
 * Shared presentation components. Styles live in src/styles/components.css and read only from tokens,
 * so every page picks up light and dark mode and the same spacing, type and radius scale.
 */

export type Tone = 'pass' | 'warning' | 'critical' | 'info' | 'neutral';

const TONE_ICON: Record<Tone, React.ElementType> = {
  pass: CheckCircle2,
  warning: AlertTriangle,
  critical: AlertCircle,
  info: Info,
  neutral: Info,
};

/* ------------------------------------------------------------------ */
/* Status                                                              */
/* ------------------------------------------------------------------ */

export const Badge: React.FC<{ tone?: Tone; children: React.ReactNode; title?: string; dot?: boolean }> = ({ tone = 'neutral', children, title, dot }) => (
  <span className={`badge ${tone === 'neutral' ? '' : tone}`} title={title}>
    {dot && <span className="badge-dot" aria-hidden="true" />}
    {children}
  </span>
);

const TIERS: Record<string, { label: string; tone: Tone }> = {
  CERTIFIED: { label: 'Certified', tone: 'pass' },
  CONDITIONAL: { label: 'Conditional', tone: 'warning' },
  NOT_CERTIFIED: { label: 'Not certified', tone: 'critical' },
  FRAMEWORK_VALIDATION_ONLY: { label: 'Validation only', tone: 'info' },
  INCONCLUSIVE: { label: 'Inconclusive', tone: 'neutral' },
  UNTESTED: { label: 'Not tested', tone: 'neutral' },
};

export const tierInfo = (tier?: string | null) =>
  TIERS[(tier || '').toUpperCase()] || { label: tier ? tier.replace(/_/g, ' ').toLowerCase().replace(/^./, c => c.toUpperCase()) : 'Not tested', tone: 'neutral' as Tone };

export const TierBadge: React.FC<{ tier?: string | null }> = ({ tier }) => {
  const t = tierInfo(tier);
  return <Badge tone={t.tone} dot>{t.label}</Badge>;
};

/** Validate mode runs against a built-in simulator, not the user's agent, so its results say so everywhere. */
export const isSimulated = (mode?: string | null) => (mode || '').toLowerCase() === 'validate';

export const modeLabel = (mode?: string | null) => {
  const m = (mode || '').toLowerCase();
  if (m === 'live_probe') return 'Live';
  if (m === 'validate') return 'Validate · simulated';
  if (m === 'certify') return 'Certify';
  if (m === 'target') return 'Target';
  return mode || '-';
};

export const SimulatedNotice: React.FC<{ mode?: string | null }> = ({ mode }) =>
  isSimulated(mode) ? (
    <Alert tone="warning" title="Simulated result">
      Validate mode checks the agent's configuration against a built-in simulator. Your agent was not contacted, so these
      scores do not show how it really behaves. Run the test in Certify mode for real results.
    </Alert>
  ) : null;

/** Tone for a 0-100 trust score: green at 90 and above, amber from 70, red below. */
export const scoreTone = (score: number | null | undefined, hasData = true): Tone =>
  !hasData || score === null || score === undefined ? 'neutral' : score >= 90 ? 'pass' : score >= 70 ? 'warning' : 'critical';

/** A score or change for display: at most 2 decimals, no trailing zeros (95.4000015 shows as 95.4). */
export const fmtScore = (v: unknown): string => String(Math.round((Number(v) || 0) * 100) / 100);

/** CSS color for a score, for numbers shown in tables. Neutral scores use body text. */
export const scoreColor = (score: number | null | undefined) => {
  const t = scoreTone(score);
  return t === 'pass' ? 'var(--color-success)' : t === 'warning' ? 'var(--color-warning)' : t === 'critical' ? 'var(--color-danger)' : 'var(--color-text)';
};

/* ------------------------------------------------------------------ */
/* Buttons                                                             */
/* ------------------------------------------------------------------ */

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger';
type ButtonSize = 'sm' | 'md' | 'lg';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  icon?: React.ElementType;
  loading?: boolean;
  /** Square button that shows only the icon. Requires an aria-label. */
  iconOnly?: boolean;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = 'secondary', size = 'md', icon: Icon, loading, iconOnly, className, children, disabled, type = 'button', ...rest }, ref) => {
    const classes = ['btn', `btn-${variant}`, size !== 'md' ? `btn-${size}` : '', iconOnly ? 'btn-icon' : '', className || '']
      .filter(Boolean)
      .join(' ');
    return (
      <button ref={ref} type={type} className={classes} disabled={disabled || loading} aria-busy={loading || undefined} {...rest}>
        {loading ? <span className="spinner" aria-hidden="true" /> : Icon ? <Icon aria-hidden="true" /> : null}
        {!iconOnly && children}
      </button>
    );
  },
);
Button.displayName = 'Button';

/* ------------------------------------------------------------------ */
/* Feedback                                                            */
/* ------------------------------------------------------------------ */

export const Alert: React.FC<{ tone?: Tone; title?: string; children?: React.ReactNode; action?: React.ReactNode }> = ({
  tone = 'info', title, children, action,
}) => {
  const Icon = TONE_ICON[tone];
  return (
    <div className={`alert ${tone}`} role={tone === 'critical' ? 'alert' : 'status'}>
      <Icon aria-hidden="true" />
      <div className="alert-body">
        {title && <div className="alert-title">{title}</div>}
        {children && <div className={title ? 'alert-text' : undefined}>{children}</div>}
      </div>
      {action && <div className="alert-actions">{action}</div>}
    </div>
  );
};

export const Skeleton: React.FC<{ width?: number | string; height?: number | string; style?: React.CSSProperties }> = ({ width = '100%', height = 12, style }) => (
  <span className="skeleton" aria-hidden="true" style={{ width, height, ...style }} />
);

export const EmptyState: React.FC<{ title: string; hint?: string; action?: React.ReactNode; icon?: React.ElementType }> = ({ title, hint, action, icon: Icon }) => (
  <div className="empty-state">
    {Icon && <div className="empty-icon"><Icon aria-hidden="true" /></div>}
    <div className="empty-title">{title}</div>
    {hint && <div className="empty-hint">{hint}</div>}
    {action && <div className="empty-action">{action}</div>}
  </div>
);

export interface ToastItem {
  id: string;
  message: string;
  type: 'success' | 'error' | 'warning' | 'info';
}

const TOAST_TONE: Record<ToastItem['type'], Tone> = { success: 'pass', error: 'critical', warning: 'warning', info: 'info' };

/** Toast stack. Announced politely to screen readers; errors interrupt. */
export const Toaster: React.FC<{ toasts: ToastItem[]; onDismiss: (id: string) => void }> = ({ toasts, onDismiss }) => (
  <div className="toast-region" aria-live="polite" aria-relevant="additions">
    {toasts.map(t => {
      const tone = TOAST_TONE[t.type];
      const Icon = TONE_ICON[tone];
      return (
        <div key={t.id} className={`toast ${tone}`} role={t.type === 'error' ? 'alert' : 'status'}>
          <Icon aria-hidden="true" />
          <div className="toast-message">{t.message}</div>
          <button className="icon-btn" onClick={() => onDismiss(t.id)} aria-label="Dismiss notification">
            <X />
          </button>
        </div>
      );
    })}
  </div>
);

/* ------------------------------------------------------------------ */
/* Overlays                                                            */
/* ------------------------------------------------------------------ */

export const Tooltip: React.FC<{ label: string; children: React.ReactElement; placement?: 'top' | 'bottom' | 'right' }> = ({ label, children, placement = 'top' }) => {
  const id = useId();
  const child = React.cloneElement(children as React.ReactElement<{ 'aria-describedby'?: string }>, { 'aria-describedby': id });
  return (
    <span className="tooltip-wrap">
      {child}
      <span role="tooltip" id={id} className={`tooltip ${placement === 'top' ? '' : placement}`}>{label}</span>
    </span>
  );
};

/** Closes a popup on Escape or on a pointer press outside `ref`. */
export function useDismiss(ref: React.RefObject<HTMLElement | null>, open: boolean, onClose: () => void) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    const onDown = (e: PointerEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) onClose(); };
    document.addEventListener('keydown', onKey);
    document.addEventListener('pointerdown', onDown);
    return () => {
      document.removeEventListener('keydown', onKey);
      document.removeEventListener('pointerdown', onDown);
    };
  }, [ref, open, onClose]);
}

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/** Keeps Tab inside `ref` while active, focuses the first control, and gives focus back on close. */
export function useFocusTrap(ref: React.RefObject<HTMLElement | null>, active: boolean) {
  useEffect(() => {
    if (!active || !ref.current) return;
    const root = ref.current;
    const previous = document.activeElement as HTMLElement | null;
    const first = root.querySelector<HTMLElement>('[data-autofocus]') || root.querySelector<HTMLElement>(FOCUSABLE);
    first?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Tab') return;
      const items = Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE));
      if (items.length === 0) return;
      const [head, tail] = [items[0], items[items.length - 1]];
      if (e.shiftKey && document.activeElement === head) { e.preventDefault(); tail.focus(); }
      else if (!e.shiftKey && document.activeElement === tail) { e.preventDefault(); head.focus(); }
    };
    root.addEventListener('keydown', onKey);
    return () => {
      root.removeEventListener('keydown', onKey);
      previous?.focus?.();
    };
  }, [ref, active]);
}

export const Modal: React.FC<{
  open: boolean;
  onClose: () => void;
  title: React.ReactNode;
  description?: React.ReactNode;
  children?: React.ReactNode;
  footer?: React.ReactNode;
  /** Buttons shown in the header, left of the close button. */
  actions?: React.ReactNode;
  size?: 'md' | 'lg';
  /** Overrides size with an exact max width in pixels. */
  width?: number;
}> = ({ open, onClose, title, description, children, footer, actions, size = 'md', width }) => {
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();
  useFocusTrap(ref, open);
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onClose]);
  if (!open) return null;
  return createPortal(
    <div className="modal-layer" style={width ? { paddingTop: '2vh', paddingBottom: '2vh' } : undefined} onPointerDown={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div
        ref={ref}
        className={`modal ${size === 'lg' ? 'modal-lg' : ''}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        style={width ? { maxWidth: width, maxHeight: '96vh' } : undefined}
      >
        <div className="modal-head" style={width ? { borderBottom: '1px solid var(--color-border)', paddingBottom: 16 } : undefined}>
          <div style={{ minWidth: 0 }}>
            <h2 id={titleId}>{title}</h2>
            {description && <p>{description}</p>}
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexShrink: 0 }}>
            {actions}
            <button className="icon-btn" onClick={onClose} aria-label="Close"><X /></button>
          </div>
        </div>
        {children && <div className="modal-body" style={width ? { paddingTop: 20 } : undefined}>{children}</div>}
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>,
    document.body,
  );
};

export const Drawer: React.FC<{ open: boolean; onClose: () => void; title: string; children?: React.ReactNode; footer?: React.ReactNode }> = ({
  open, onClose, title, children, footer,
}) => {
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();
  useFocusTrap(ref, open);
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <>
      <div className="scrim" onClick={onClose} />
      <aside ref={ref} className="drawer" role="dialog" aria-modal="true" aria-labelledby={titleId}>
        <div className="modal-head">
          <h2 id={titleId}>{title}</h2>
          <button className="icon-btn" onClick={onClose} aria-label="Close"><X /></button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </aside>
    </>
  );
};

/* ------------------------------------------------------------------ */
/* Forms                                                               */
/* ------------------------------------------------------------------ */

/** Label, control, hint and error wired together. The control receives id, aria-describedby and aria-invalid. */
export const Field: React.FC<{ label: string; hint?: React.ReactNode; error?: string | null; required?: boolean; children: React.ReactElement }> = ({
  label, hint, error, required, children,
}) => {
  const id = useId();
  const hintId = hint ? `${id}-hint` : undefined;
  const errorId = error ? `${id}-error` : undefined;
  const control = React.cloneElement(children as React.ReactElement<Record<string, unknown>>, {
    id,
    'aria-describedby': [hintId, errorId].filter(Boolean).join(' ') || undefined,
    'aria-invalid': error ? true : undefined,
    required,
  });
  return (
    <div className="field">
      <label className="field-label" htmlFor={id}>
        {label}
        {required && <span className="req" aria-hidden="true">*</span>}
      </label>
      {control}
      {error ? (
        <div className="field-error" id={errorId}><AlertCircle size={14} aria-hidden="true" />{error}</div>
      ) : hint ? (
        <div className="field-hint" id={hintId}>{hint}</div>
      ) : null}
    </div>
  );
};

export const Toggle: React.FC<{ checked: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean }> = ({ checked, onChange, label, disabled }) => (
  <button type="button" role="switch" className="toggle" aria-checked={checked} aria-label={label} disabled={disabled} onClick={() => onChange(!checked)} />
);

export const Checkbox: React.FC<{ checked: boolean; onChange: (v: boolean) => void; children: React.ReactNode; disabled?: boolean }> = ({ checked, onChange, children, disabled }) => (
  <label className="checkbox">
    <input type="checkbox" checked={checked} disabled={disabled} onChange={e => onChange(e.target.checked)} />
    <span>{children}</span>
  </label>
);

/* ------------------------------------------------------------------ */
/* Navigation                                                          */
/* ------------------------------------------------------------------ */

export function Tabs<T extends string>({ value, onChange, items, label }: { value: T; onChange: (v: T) => void; items: { value: T; label: string }[]; label: string }) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const onKey = (e: React.KeyboardEvent, i: number) => {
    const step = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
    if (!step) return;
    e.preventDefault();
    const next = (i + step + items.length) % items.length;
    onChange(items[next].value);
    refs.current[next]?.focus();
  };
  return (
    <div className="tabs" role="tablist" aria-label={label}>
      {items.map((it, i) => (
        <button
          key={it.value}
          ref={el => { refs.current[i] = el; }}
          role="tab"
          className="tab"
          aria-selected={value === it.value}
          tabIndex={value === it.value ? 0 : -1}
          onClick={() => onChange(it.value)}
          onKeyDown={e => onKey(e, i)}
        >
          {it.label}
        </button>
      ))}
    </div>
  );
}

/** Compact option switch for chart views and time ranges. */
export function Segmented<T extends string>({ value, onChange, items, label }: { value: T; onChange: (v: T) => void; items: { value: T; label: string }[]; label: string }) {
  return (
    <div className="segmented" role="group" aria-label={label}>
      {items.map(it => (
        <button key={it.value} type="button" aria-pressed={value === it.value} className={value === it.value ? 'active' : ''} onClick={() => onChange(it.value)}>
          {it.label}
        </button>
      ))}
    </div>
  );
}

export const Breadcrumbs: React.FC<{ items: { label: string; onClick?: () => void }[] }> = ({ items }) => (
  <nav className="breadcrumbs" aria-label="Breadcrumb">
    <ol>
      {items.map((it, i) => {
        const last = i === items.length - 1;
        return (
          <li key={`${it.label}-${i}`} className={last ? undefined : 'crumb-parent'}>
            {last ? <span aria-current="page">{it.label}</span> : it.onClick ? <button type="button" className="crumb-link" onClick={it.onClick}>{it.label}</button> : <span>{it.label}</span>}
          </li>
        );
      })}
    </ol>
  </nav>
);

export const initialsOf = (name?: string | null) =>
  (name || 'U').trim().split(/\s+/).map(p => p[0]).join('').slice(0, 2).toUpperCase() || 'U';

export const Avatar: React.FC<{ name?: string | null; size?: 'sm' | 'md' | 'lg' | 'xl' }> = ({ name, size = 'md' }) => (
  <span className={`avatar ${size === 'md' ? '' : `avatar-${size}`}`} aria-hidden="true">{initialsOf(name)}</span>
);

export const Kbd: React.FC<{ children: React.ReactNode }> = ({ children }) => <kbd className="kbd">{children}</kbd>;

/* ------------------------------------------------------------------ */
/* Layout                                                              */
/* ------------------------------------------------------------------ */

export const PageHeader: React.FC<{ title: string; subtitle?: string; actions?: React.ReactNode }> = ({ title, subtitle, actions }) => (
  <div className="page-head">
    <div>
      <h1>{title}</h1>
      {subtitle && <p>{subtitle}</p>}
    </div>
    {actions && <div className="page-head-actions">{actions}</div>}
  </div>
);

/** `accent` is accepted for older callers and ignored: panels no longer carry decorative color bars. */
export const Panel: React.FC<{
  title?: string; subtitle?: string; actions?: React.ReactNode; children: React.ReactNode; flush?: boolean; accent?: string; footer?: React.ReactNode;
}> = ({ title, subtitle, actions, children, flush, footer }) => (
  <section className="panel">
    {(title || actions) && (
      <div className="panel-head">
        <div>
          {title && <h3>{title}</h3>}
          {subtitle && <p>{subtitle}</p>}
        </div>
        {actions && <div className="panel-head-actions">{actions}</div>}
      </div>
    )}
    <div className={flush ? undefined : 'panel-body'}>{children}</div>
    {footer && <div className="panel-foot">{footer}</div>}
  </section>
);

export interface StatTrend {
  /** Signed change. Positive is drawn as up. */
  delta: number;
  /** Text after the number, for example "pts vs prior 7 days". */
  label: string;
  /** Set when a rise is bad news (for example more critical findings). */
  invert?: boolean;
}

/** KPI tile. Value color only carries meaning for pass, warning and critical; everything else stays neutral. */
export const Stat: React.FC<{
  label: string; value: React.ReactNode; note?: string; tone?: Tone; onClick?: () => void; icon?: React.ElementType; loading?: boolean; trend?: StatTrend | null;
}> = ({ label, value, note, tone = 'neutral', onClick, icon: Icon, loading, trend }) => {
  const toneClass = tone === 'pass' || tone === 'warning' || tone === 'critical' ? ` tone-${tone}` : '';
  const direction = !trend || trend.delta === 0 ? 'flat' : trend.delta > 0 ? 'up' : 'down';
  const good = trend ? (trend.invert ? trend.delta < 0 : trend.delta > 0) : false;
  const TrendIcon = direction === 'flat' ? Minus : direction === 'up' ? TrendingUp : TrendingDown;
  const body = (
    <>
      <div className="stat-top">
        <span className="stat-label">{label}</span>
        {Icon && <Icon className="stat-icon" aria-hidden="true" />}
      </div>
      {loading ? <Skeleton width="55%" height={32} /> : <div className={`stat-value${toneClass}`}>{value}</div>}
      <div className="stat-foot">
        {loading ? <Skeleton width="70%" height={12} /> : (
          <>
            {trend && (
              <span className={`stat-trend ${direction === 'flat' ? 'flat' : good ? 'up' : 'down'}`}>
                <TrendIcon aria-hidden="true" />
                {trend.delta > 0 ? `+${trend.delta}` : trend.delta}
                <span className="sr-only">{direction === 'up' ? 'up' : direction === 'down' ? 'down' : 'no change'}</span>
              </span>
            )}
            {trend && <span>{trend.label}</span>}
            {!trend && note && <span>{note}</span>}
          </>
        )}
      </div>
    </>
  );
  return onClick ? (
    <button type="button" className="stat" onClick={onClick}>{body}</button>
  ) : (
    <div className="stat">{body}</div>
  );
};

/* ------------------------------------------------------------------ */
/* Tables                                                              */
/* ------------------------------------------------------------------ */

export type SortDir = 'asc' | 'desc';

/** Client-side sorting for small tables. `accessors` maps a column key to the value to compare. */
export function useSort<T, K extends string>(rows: T[], accessors: Record<K, (row: T) => string | number | null | undefined>, initial: { key: K; dir: SortDir }) {
  const [sort, setSort] = useState(initial);
  const toggle = useCallback((key: K) => {
    setSort(s => (s.key === key ? { key, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'desc' }));
  }, []);
  const sorted = useMemo(() => {
    const get = accessors[sort.key];
    const factor = sort.dir === 'asc' ? 1 : -1;
    return [...rows].sort((a, b) => {
      const x = get(a);
      const y = get(b);
      if (x == null && y == null) return 0;
      if (x == null) return 1;
      if (y == null) return -1;
      if (typeof x === 'number' && typeof y === 'number') return (x - y) * factor;
      return String(x).localeCompare(String(y), undefined, { numeric: true, sensitivity: 'base' }) * factor;
    });
  }, [rows, sort]);
  return { sorted, sort, toggle };
}

export function SortHeader<K extends string>({ label, column, sort, onSort, numeric }: { label: string; column: K; sort: { key: K; dir: SortDir }; onSort: (k: K) => void; numeric?: boolean }) {
  const active = sort.key === column;
  const Icon = !active ? ArrowUpDown : sort.dir === 'asc' ? ArrowUp : ArrowDown;
  return (
    <th className={numeric ? 'num' : undefined} aria-sort={active ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'} scope="col">
      <button type="button" className="th-sort" onClick={() => onSort(column)}>
        {label}
        <Icon aria-hidden="true" />
      </button>
    </th>
  );
}

export const Pagination: React.FC<{ page: number; pageSize: number; total: number; onPage: (p: number) => void }> = ({ page, pageSize, total, onPage }) => {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(total, page * pageSize);
  return (
    <div className="pagination">
      <span>{from}-{to} of {total}</span>
      <div className="pagination-controls">
        <Button size="sm" variant="ghost" icon={ChevronLeft} iconOnly aria-label="Previous page" disabled={page <= 1} onClick={() => onPage(page - 1)} />
        <span style={{ padding: '0 8px' }}>Page {page} of {pages}</span>
        <Button size="sm" variant="ghost" icon={ChevronRight} iconOnly aria-label="Next page" disabled={page >= pages} onClick={() => onPage(page + 1)} />
      </div>
    </div>
  );
};

/** Placeholder rows shown while a table loads, so the layout does not jump when data arrives. */
export const TableSkeleton: React.FC<{ rows?: number; columns: number }> = ({ rows = 5, columns }) => (
  <>
    {Array.from({ length: rows }).map((_, r) => (
      <tr key={r} aria-hidden="true">
        {Array.from({ length: columns }).map((__, c) => (
          <td key={c}><Skeleton width={c === 0 ? '70%' : '50%'} /></td>
        ))}
      </tr>
    ))}
  </>
);

/** Search box with a leading icon, for page and panel toolbars. */
export const SearchInput: React.FC<{ value: string; onChange: (v: string) => void; placeholder: string; label?: string; width?: number | string }> = ({
  value, onChange, placeholder, label, width = 240,
}) => (
  <div className="input-icon search-input" style={{ width }}>
    <Search aria-hidden="true" />
    <input className="form-input" type="search" placeholder={placeholder} value={value} onChange={e => onChange(e.target.value)} aria-label={label || placeholder} />
  </div>
);

/** Colored dot plus a text label, for states such as Healthy, Paused, Down. */
export const StatusText: React.FC<{ color: string; children: React.ReactNode }> = ({ color, children }) => (
  <span className="status-text">
    <span className="status-dot" style={{ background: color }} aria-hidden="true" />
    {children}
  </span>
);

/** Live or certify test, colored with the same series colors the charts use. Identity, not status. */
export const KindBadge: React.FC<{ live: boolean }> = ({ live }) => (
  <span className="badge">
    <span className="badge-dot" style={{ background: live ? 'var(--chart-1)' : 'var(--chart-2)' }} aria-hidden="true" />
    {live ? 'Live' : 'Certify'}
  </span>
);

/** Checkbox with a title and a one-line explanation. */
export const OptionRow: React.FC<{ checked: boolean; onChange: (v: boolean) => void; title: React.ReactNode; hint?: React.ReactNode; disabled?: boolean }> = ({
  checked, onChange, title, hint, disabled,
}) => (
  <label className="option-row">
    <input type="checkbox" checked={checked} disabled={disabled} onChange={e => onChange(e.target.checked)} />
    <span>
      <span className="option-row-title">{title}</span>
      {hint && <span className="option-row-hint">{hint}</span>}
    </span>
  </label>
);

/** A section that opens and closes, with its state announced to screen readers. */
export const Disclosure: React.FC<{ title: React.ReactNode; icon?: React.ElementType; defaultOpen?: boolean; children: React.ReactNode }> = ({
  title, icon: Icon, defaultOpen = false, children,
}) => {
  const [open, setOpen] = useState(defaultOpen);
  const id = useId();
  return (
    <div className="disclosure">
      <button type="button" className="disclosure-trigger" aria-expanded={open} aria-controls={id} onClick={() => setOpen(o => !o)}>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>{Icon && <Icon size={16} aria-hidden="true" />}{title}</span>
        <ChevronDown size={16} aria-hidden="true" style={{ transform: open ? 'rotate(180deg)' : undefined, transition: 'transform 150ms' }} />
      </button>
      {open && <div className="disclosure-body" id={id}>{children}</div>}
    </div>
  );
};
