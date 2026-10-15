import React from 'react';
import { Shield } from 'lucide-react';

type LegalKind = 'privacy' | 'terms';

interface Section { heading: string; body: string[] }

const UPDATED = 'October 1, 2026';

const PRIVACY: Section[] = [
  {
    heading: 'What this covers',
    body: [
      'CertifyAI tests, certifies and monitors autonomous AI agents. This policy explains what information the service collects, how it is used, and the choices you have.',
    ],
  },
  {
    heading: 'Information we collect',
    body: [
      'Account information: your name, email address and a hashed password, plus the role assigned to your account.',
      'Agent and test data: the agent definitions, endpoints and configuration you submit, the prompts and responses exchanged during a test, the findings and trust scores produced, and the reports and certificates generated from them.',
      'Usage information: sign-in times, pages used, and technical logs such as IP address and browser type, kept for security and troubleshooting.',
    ],
  },
  {
    heading: 'How we use it',
    body: [
      'To run the tests you request, produce reports and certificates, and show your history and trends.',
      'To secure the service, detect abuse, and diagnose faults.',
      'We do not sell personal information, and we do not use your agent data or test results to advertise to you.',
    ],
  },
  {
    heading: 'Credentials for live agents',
    body: [
      'If you connect a live agent, the API keys or tokens you provide are used only to call that agent during a test. Use credentials that are scoped for testing and rotate them when a test program ends.',
    ],
  },
  {
    heading: 'Sharing',
    body: [
      'Your data is visible to you and to administrators of your workspace. We share data with infrastructure providers that host and operate the service, and only as needed to provide it. We may disclose information when the law requires it.',
    ],
  },
  {
    heading: 'Retention and deletion',
    body: [
      'Data is kept while your account is active. You can ask for your account and associated test data to be deleted, and we will remove it except where we must keep records to meet a legal obligation.',
    ],
  },
  {
    heading: 'Security',
    body: [
      'Passwords are stored hashed, sessions use signed tokens, and access to data is restricted by role. No system is perfectly secure, so please report any suspected vulnerability to your workspace administrator.',
    ],
  },
  {
    heading: 'Your choices',
    body: [
      'You can view and update your profile in the app. You can request access to, correction of, or deletion of your personal information by contacting your workspace administrator.',
    ],
  },
  {
    heading: 'Changes to this policy',
    body: ['If we change this policy, the updated version will be posted on this page with a new date.'],
  },
];

const TERMS: Section[] = [
  {
    heading: 'Acceptance',
    body: ['By creating an account or using CertifyAI you agree to these terms. If you use the service for an organization, you confirm you are authorized to accept them on its behalf.'],
  },
  {
    heading: 'The service',
    body: [
      'CertifyAI runs structured test phases against AI agents and produces findings, trust scores, reports and certificates. Results describe how an agent behaved under the tests that were run. They are not a guarantee that an agent is safe, compliant or free of defects.',
    ],
  },
  {
    heading: 'Your account',
    body: [
      'Keep your credentials confidential and tell us promptly if you suspect unauthorized access. You are responsible for activity under your account.',
    ],
  },
  {
    heading: 'Acceptable use',
    body: [
      'Only test agents and endpoints that you own or have written permission to test.',
      'Do not use the service to attack, overload or gain unauthorized access to any system, to submit unlawful content, or to interfere with other users.',
      'Do not attempt to forge, alter or misrepresent a certificate or report issued by the service.',
    ],
  },
  {
    heading: 'Your data',
    body: [
      'You keep ownership of the agent definitions and data you submit. You grant us the limited right to process them to provide the service. See the Privacy Policy for how data is handled.',
    ],
  },
  {
    heading: 'Certificates and reports',
    body: [
      'A certificate reflects the state of an agent at the time and version tested. It may be shown to others only in full and without changes. A new version of an agent may need to be tested again.',
    ],
  },
  {
    heading: 'Availability and changes',
    body: [
      'We work to keep the service available but do not promise uninterrupted operation. We may change or discontinue features, and we will give reasonable notice of material changes.',
    ],
  },
  {
    heading: 'Disclaimer and liability',
    body: [
      'The service is provided as is, without warranties of any kind to the extent the law allows. To the extent the law allows, we are not liable for indirect or consequential loss, or for decisions you make based on test results.',
    ],
  },
  {
    heading: 'Suspension and termination',
    body: ['We may suspend or end access for breach of these terms or to protect the service. You may stop using the service at any time and ask for your data to be deleted.'],
  },
  {
    heading: 'Changes to these terms',
    body: ['We may update these terms. The current version is always on this page, and continued use after a change means you accept it.'],
  },
];

export const LegalPage: React.FC<{ kind: LegalKind }> = ({ kind }) => {
  const isPrivacy = kind === 'privacy';
  const sections = isPrivacy ? PRIVACY : TERMS;
  return (
    <div className="legal-shell">
      <header className="legal-head">
        <a className="login-brand" href="/login">
          <div className="nav-brand-mark"><Shield size={16} /></div>
          <span>CertifyAI</span>
        </a>
        <nav className="legal-nav" aria-label="Legal">
          <a href="/privacy" aria-current={isPrivacy ? 'page' : undefined}>Privacy Policy</a>
          <a href="/terms" aria-current={!isPrivacy ? 'page' : undefined}>Terms and Conditions</a>
          <a href="/login">Sign in</a>
        </nav>
      </header>
      <main className="legal-body">
        <h1>{isPrivacy ? 'Privacy Policy' : 'Terms and Conditions'}</h1>
        <p className="legal-updated">Last updated {UPDATED}</p>
        {sections.map(s => (
          <section key={s.heading}>
            <h2>{s.heading}</h2>
            {s.body.map(p => <p key={p}>{p}</p>)}
          </section>
        ))}
      </main>
    </div>
  );
};
