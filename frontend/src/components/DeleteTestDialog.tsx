import React, { useState } from 'react';
import { apiFetch } from '../utils/apiClient';
import { Alert, Button, Modal } from './ui';

export interface DeletableTest {
  id: number;
  agent_name?: string;
  version?: string | null;
  audit_id?: string;
}

/** Asks before deleting one test, then deletes it on the server. The test, its findings and its PDF are removed for good. */
export const DeleteTestDialog: React.FC<{
  test: DeletableTest | null;
  onClose: () => void;
  onDeleted: (test: DeletableTest) => void;
}> = ({ test, onClose, onDeleted }) => {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const close = () => { if (!busy) { setError(null); onClose(); } };

  const confirm = async () => {
    if (!test) return;
    setBusy(true);
    setError(null);
    try {
      const res = await apiFetch(`/api/user/tests/${test.id}`, { method: 'DELETE' });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || 'The test could not be deleted. Try again.');
      }
      onDeleted(test);
      onClose();
    } catch (e: any) {
      setError(e.message || 'The test could not be deleted. Try again.');
    } finally {
      setBusy(false);
    }
  };

  const label = test ? [test.agent_name, test.version].filter(Boolean).join(' ') : '';
  return (
    <Modal
      open={!!test}
      onClose={close}
      title={test ? `Delete this test of ${label || 'this agent'}?` : ''}
      description="The result, its findings and its report are deleted for good. Other tests of this agent stay."
      footer={
        <>
          <Button onClick={close} disabled={busy}>Cancel</Button>
          <Button variant="danger" loading={busy} onClick={confirm}>Delete test</Button>
        </>
      }
    >
      {test?.audit_id && <p className="cell-mono" style={{ margin: 0 }}>{test.audit_id}</p>}
      {error && <div style={{ marginTop: 12 }}><Alert tone="critical" title={error} /></div>}
    </Modal>
  );
};
