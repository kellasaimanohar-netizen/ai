import React from 'react';
import { Clock } from 'lucide-react';
import { Field, OptionRow } from '../ui';

export interface LiveTestConfig {
  agentType: string;
  endpointUrl: string;
  payloadTemplate: string;
  responsePath: string;
  goldenJsonl: string;
  repeats: number;
  useAiJudge: boolean;
  scheduleMinutes: number;
  monitor: boolean;
  healthMinutes: number;
  includeMultilingual: boolean;
  includeNumberChecks: boolean;
  requiresAuth: boolean;
  fairnessJson: string;
  accessJson: string;
}

export const DEFAULT_LIVE_CONFIG: LiveTestConfig = {
  agentType: '',
  endpointUrl: '',
  payloadTemplate: '',
  responsePath: '',
  goldenJsonl: '',
  repeats: 1,
  useAiJudge: false,
  scheduleMinutes: 0,
  monitor: true,
  healthMinutes: 5,
  includeMultilingual: true,
  includeNumberChecks: false,
  requiresAuth: false,
  fairnessJson: '',
  accessJson: '',
};

interface LiveTestSettingsProps {
  value: LiveTestConfig;
  onChange: (patch: Partial<LiveTestConfig>) => void;
}

export const LiveTestSettings: React.FC<LiveTestSettingsProps> = ({
  value,
  onChange,
}) => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div className="form-section">
        <OptionRow
          checked={value.monitor}
          onChange={v => onChange({ monitor: v })}
          title={<><Clock size={14} aria-hidden="true" />Monitor this agent around the clock</>}
          hint="The server checks the agent in the background, even when this page is closed. Problems show on the Live agents page and in Alerts: the agent down or slow, a wrong known answer, routes added or removed, an expiring certificate, or the repo code changing."
        />
        {value.monitor && (
          <div className="form-grid">
            <Field label="Health check every">
              <select className="form-input" value={value.healthMinutes} onChange={e => onChange({ healthMinutes: Number(e.target.value) })}>
                <option value={1}>1 minute</option>
                <option value={5}>5 minutes (recommended)</option>
                <option value={15}>15 minutes</option>
                <option value={60}>1 hour</option>
              </select>
            </Field>
            <Field label="Full test every">
              <select className="form-input" value={value.scheduleMinutes} onChange={e => onChange({ scheduleMinutes: Number(e.target.value) })}>
                <option value={0}>Off (health checks only)</option>
                <option value={360}>6 hours</option>
                <option value={1440}>Day (recommended)</option>
                <option value={10080}>Week</option>
              </select>
            </Field>
          </div>
        )}
      </div>

    </div>
  );
};
