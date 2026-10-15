import React, { useEffect, useRef } from 'react';

/**
 * Shows about one week of a daily chart at a time. Scroll sideways for the other days; it opens on the newest.
 * Pass `axis` to pin a y-axis on the left that stays visible while the plot scrolls (the chart's own
 * YAxis should then be hidden and the chart given a matching left margin). The pin stops above the
 * 30px x-axis row so day labels stay readable.
 */
export const ScrollChart: React.FC<{ count: number; children: React.ReactNode; axis?: React.ReactNode; axisWidth?: number }> = ({
  count, children, axis, axisWidth = 52,
}) => {
  const box = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = box.current;
    if (el) el.scrollLeft = el.scrollWidth;
  }, [count]);

  return (
    <div style={{ position: 'relative', height: '100%' }}>
      <div ref={box} style={{ height: '100%', overflowX: 'auto', overflowY: 'hidden' }}>
        <div style={{ height: '100%', width: `${Math.max(100, (count / 7) * 100)}%`, minWidth: '100%' }}>{children}</div>
      </div>
      {axis && (
        <div aria-hidden="true" style={{ position: 'absolute', left: 0, top: 0, bottom: 30, width: axisWidth, background: 'var(--color-surface)', pointerEvents: 'none' }}>
          {axis}
        </div>
      )}
    </div>
  );
};
