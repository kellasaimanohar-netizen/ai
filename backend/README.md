# CertifyAI / Agent Audit V10 - Backend Services

Pre-deployment certification, field operations telemetry, and live agent security auditing backend for CertifyAI.

## Features

- **Multi-Source Auditing**: Automated static & dynamic scanning for AI Agents (Repo, OpenAPI specs, Live Probes).
- **Standards Mapping**: OWASP LLM Top 10, NIST AI RMF compliance checks.
- **Database Engine**: Versioned schema migrations for PostgreSQL (Supports local & Supabase Cloud PostgreSQL).
- **PDF Report Generator**: Native ReportLab engine for audit certificates and detailed finding summaries.

## Getting Started

```bash
pip install -r requirements.txt
python -m database.migrate
uvicorn backend:app --reload
```

For detailed configuration options, see `.env.example`.
