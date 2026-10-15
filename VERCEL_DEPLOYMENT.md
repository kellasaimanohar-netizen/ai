# Deploying CertifyAI on Vercel as Two Services

This guide explains how to deploy **CertifyAI** on Vercel as two independent services:
1. **Backend Service** (FastAPI / Python Serverless)
2. **Frontend Service** (React 19 / Vite SPA)

Both services are deployed from the same GitHub repository (`https://github.com/Ayusystems/certifyai` on branch `Manohar`).

---

## 🚀 Service 1: Backend API (FastAPI)

### Step 1: Create Backend Project on Vercel
1. Go to [Vercel Dashboard](https://vercel.com/dashboard) and click **"Add New..."** > **"Project"**.
2. Select your repository `Ayusystems/certifyai`.
3. In the configuration screen:
   * **Project Name**: `certifyai-backend` (or your preferred name)
   * **Framework Preset**: Select **Other**
   * **Root Directory**: Click **Edit**, select `backend`, and click **Continue**.

### Step 2: Configure Environment Variables
Under the **Environment Variables** section, add the following:

| Key | Example Value | Description |
| :--- | :--- | :--- |
| `DATABASE_URL` | `postgresql://postgres:[PASSWORD]@db.[REF].supabase.co:5432/postgres` | Your Supabase or PostgreSQL connection string |
| `JWT_SECRET` | `your-secure-random-jwt-secret-key-32chars` | Secret key for JWT access tokens |
| `ADMIN_USERNAME` | `admin,syed` | Admin login username |
| `ADMIN_EMAIL` | `admin@certifyai.in,syed@certifyai.in` | Admin email |
| `ADMIN_PASSWORD` | `admin` (or strong password) | Admin login password |
| `USER_USERNAME` | `user,ismeet` | Standard user username |
| `USER_EMAIL` | `user@certifyai.in,ismeet@certifyai.in` | Standard user email |
| `USER_PASSWORD` | `user` (or strong password) | Standard user password |
| `AA_ALLOWED_ORIGINS` | `https://certifyai-frontend.vercel.app,http://localhost:5173` | Allowed frontend origins (Vercel domains are also permitted via regex) |

### Step 3: Deploy Backend
1. Click **Deploy**.
2. Once finished, note your deployed Backend URL (e.g., `https://certifyai-backend.vercel.app`).
3. Verify by opening `https://certifyai-backend.vercel.app/api/health` or `/health` in your browser.

---

## 🎨 Service 2: Frontend Dashboard (Vite + React)

### Step 1: Create Frontend Project on Vercel
1. In [Vercel Dashboard](https://vercel.com/dashboard), click **"Add New..."** > **"Project"**.
2. Select the same repository `Ayusystems/certifyai`.
3. In the configuration screen:
   * **Project Name**: `certifyai-frontend` (or your preferred name)
   * **Framework Preset**: **Vite** (detected automatically)
   * **Root Directory**: Click **Edit**, select `frontend`, and click **Continue**.
   * **Build Command**: `npm run build` (default)
   * **Output Directory**: `dist` (default)

### Step 2: Configure Environment Variables
Add the following variable:

| Key | Value | Description |
| :--- | :--- | :--- |
| `VITE_API_URL` | `https://certifyai-backend.vercel.app` | The URL of your deployed Backend Service from Service 1 |

*(Optional: You can also specify default demo login credentials like `VITE_DEV_ADMIN_EMAIL`, etc.)*

### Step 3: Deploy Frontend
1. Click **Deploy**.
2. Once completed, your frontend will be live at `https://certifyai-frontend.vercel.app`.
3. Open the URL and test signing in with your admin credentials.

---

## ⚙️ Configuration Files Summary

- [backend/vercel.json](file:///c:/Personal/V10/backend/vercel.json): Configures the Python runtime (`@vercel/python`) and routes all incoming requests to [backend/api/index.py](file:///c:/Personal/V10/backend/api/index.py).
- [frontend/vercel.json](file:///c:/Personal/V10/frontend/vercel.json): Configures Vite SPA client-side routing rewrites (`/(.*)` -> `/index.html`).
- [backend/backend.py](file:///c:/Personal/V10/backend/backend.py): CORS configured with regex matching `https://.*\.vercel\.app` for smooth multi-service communication.
