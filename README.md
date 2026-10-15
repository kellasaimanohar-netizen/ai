# CertifyAI — AI Agent Field Operations, Telemetry & Security Certification Platform

CertifyAI (Agent Audit V10) is an enterprise pre-deployment certification and live telemetry platform for AI agents. It provides standards-mapped security auditing (OWASP Top 10 for LLMs, NIST AI RMF), live agent probing, automated PDF report generation, and real-time health monitoring.

---

## 🏗️ Architecture & Technology Stack

- **Backend**:
  - Python 3.10+ & FastAPI
  - PostgreSQL (Fully supports Supabase Cloud PostgreSQL and Local PostgreSQL)
  - `psycopg2-binary` connection pooling & versioned migrations
  - Pydantic v2 & PyJWT authentication
  - OpenAPI & HTTP probing client with ReportLab PDF engine

- **Frontend**:
  - React 19, TypeScript & Vite
  - Recharts telemetry & interactive dashboard components
  - Tailwind / Custom CSS design system
  - Lucide React iconography & jsPDF export client

- **Infrastructure**:
  - Docker & Docker Compose setup

---

## ⚡ Quick Start

### 1. Backend Setup

```bash
cd backend

# Create and activate virtual environment (optional)
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
copy .env.example .env   # On Linux/macOS: cp .env.example .env
```

Edit `backend/.env` with your database credentials:
```env
DB_HOST=db.dgfuvnregukdammfgtkn.supabase.co
DB_PORT=5432
DB_NAME=postgres
DB_USER=postgres
DB_PASSWORD=your_password_here
```

Apply database migrations:
```bash
python -m database.migrate
```

Start the FastAPI server:
```bash
uvicorn backend:app --reload --port 8000
```

Swagger UI documentation will be available at: [http://127.0.0.1:8000/api/docs](http://127.0.0.1:8000/api/docs)

---

### 2. Frontend Setup

```bash
cd frontend

# Install packages
npm install

# Start Vite development server
npm run dev
```

The frontend will run at [http://localhost:5173](http://localhost:5173).

---

### 3. Docker Compose Setup

Run backend, frontend, and PostgreSQL services simultaneously:

```bash
docker-compose up --build
```

---

## 🗄️ Database Management & Supabase

CertifyAI uses versioned schema migrations located in `backend/database/migrations/`.

- **Check migration status**:
  ```bash
  python -m database.migrate status
  ```

- **Apply pending migrations**:
  ```bash
  python -m database.migrate
  ```

Supported database configurations:
- **Supabase Cloud PostgreSQL** (`db.<project_ref>.supabase.co`)
- **Local PostgreSQL** (`localhost:5432`)

---

## 📄 License

Apache-2.0 License.
