import { apiFetch } from './apiClient';
import { generatePDFReport } from './pdfExport';

const cache = new Map<number, Promise<string>>();

/** Object URL of the PDF report for a test. Uses the stored server PDF, else builds it in the browser. Cached per test. */
export function getReportPdfUrl(testId: number): Promise<string> {
  let hit = cache.get(testId);
  if (!hit) {
    hit = (async () => {
      const res = await apiFetch(`/api/user/tests/${testId}/pdf`);
      if (res.ok) return URL.createObjectURL(new Blob([await res.blob()], { type: 'application/pdf' }));
      const detail = await apiFetch(`/api/user/tests/${testId}`);
      if (!detail.ok) throw new Error('not available');
      const data = await detail.json();
      return URL.createObjectURL(generatePDFReport(data.test.full_result || data.test, { save: false }).output('blob'));
    })();
    hit.catch(() => cache.delete(testId));
    cache.set(testId, hit);
  }
  return hit;
}

/** The full result of one of the signed-in user's tests, merged with who ran it, for reports. */
export async function fetchTestResult(testId: number): Promise<any> {
  const res = await apiFetch(`/api/user/tests/${testId}`);
  if (!res.ok) throw new Error('not available');
  const data = await res.json();
  const t = data.test || {};
  const full = t.full_result && Object.keys(t.full_result).length ? t.full_result : {};
  return { ...t, ...full, version: full.version || t.version, tested_by_name: full.tested_by_name || t.tested_by_name, tested_by_email: full.tested_by_email || t.tested_by_email };
}
