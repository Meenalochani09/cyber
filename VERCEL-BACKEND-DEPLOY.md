# TRACELYT — Vercel deployment

This archive contains the complete project and a Vercel catch-all serverless entry point for the backend.

## Deploy the backend

1. Push the complete `tracelyt/` folder contents to your GitHub repository.
2. In Vercel, import that repository as a **new backend project**.
3. In Project Settings → Build & Development Settings, set **Root Directory** to `tracelyt/backend` (or `backend` if you uploaded the contents of `tracelyt/` directly to the repository).
4. Framework Preset: **Other**.
5. Do not add a custom Build Command or Output Directory. Let Vercel detect the Node.js API function.
6. Set the Node.js runtime to Node 20 or newer if the setting is available.
7. Add Environment Variables:
   - `DATABASE_URL` — the PostgreSQL connection string used by `backend/config/database.js`.
   - `FRONTEND_ORIGIN` — the exact deployed frontend origin, for example `https://your-frontend.vercel.app`.
   - `DATABASE_CA` — optional CA certificate only if your database setup requires it.
8. Redeploy.

The catch-all function is `backend/api/[...path].js`. It forwards `/api/health`, `/api/investigations`, and the other `/api/*` endpoints to the existing Express app.

## Deploy the frontend

Deploy the `tracelyt/frontend` folder as a separate static frontend project, or keep using your existing working frontend deployment. In the frontend Settings, set the API URL to the deployed backend origin (for example `https://your-backend.vercel.app`), without a trailing slash.

## Verify

Open `https://your-backend.vercel.app/api/health`. A successful database connection returns JSON with `ok: true`. A database configuration or connectivity problem returns HTTP 503; check `DATABASE_URL` and the database network/SSL settings.

## Important

- Never commit `.env` or real database passwords to GitHub.
- Vercel serverless storage is ephemeral. Uploaded evidence files should not be treated as permanent storage; use object storage for durable uploads.
- Keep the frontend and backend origins in sync with `FRONTEND_ORIGIN`.
- The archive preserves the original application source and adds the Vercel backend entry point; it does not change the investigation logic.
