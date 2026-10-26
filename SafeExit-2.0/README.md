# SafeExit 2.0 — Complete College Project

Full-stack student/warden/officer/admin issue management and emergency exit demo.

## Before running
1. Install Node.js 20+ and have MongoDB running or MongoDB Atlas connection.
2. **Do not delete your old project.** Extract this ZIP to a NEW folder first.
3. Copy your EXISTING `backend/.env` from your original project into this new `backend` folder, or copy `.env.example` to `.env` and fill in `MONGO_URI`, `JWT_SECRET` (32+ random characters), `CLIENT_URL=http://localhost:5173`. Keep `.env` private.
4. In a terminal: `cd backend`, `npm install`, `npm start`.
5. In a second terminal: `cd frontend`, `npm install`, `npm run dev`.
6. Open **http://localhost:5173**. Close other Vite instances first; port 5173 is fixed deliberately.
7. Register a student through the UI. To create a real officer/warden/admin, in `backend` run `npm run staff` and answer the prompts. Then log in with that staff account.

## Implemented
- Student registration/login, HttpOnly cookie sessions, logout, refresh restoration. Staff roles created by CLI, not by public registration.
- College/hostel issue submission, public/private visibility, mandatory private safety categories, support without duplicate supporters.
- Role-scoped staff issue review and status notes, private student/staff messages, notifications, announcements, basic analytics.
- Private evidence photo upload, rule-based reporting helper, live Socket.IO refresh.
- Existing emergency exit monitoring, student hazard reports, officer review and add exits.

## Important security / deployment notes
- This is a **college prototype**, not an emergency dispatch or evacuation system.
- App server only accepts configured frontend origin; for deployment set `CLIENT_URL` to the HTTPS frontend origin, enable TLS and `NODE_ENV=production`, add production logging/monitoring, account recovery, stronger validation and comprehensive automated tests.
- Private photos require authentication and authorization; stored in `backend/private_uploads`. Back them up separately.
- For a production deployment, add file content signature verification, malware scanning, CSRF tokens, audit logs, rate limiting on all write endpoints, and Socket.IO event-level authorization.
- Do not share or commit `backend/.env` or private uploads.
- No existing MongoDB collections are dropped. Existing `Exit` and `Report` models are reused.

## Troubleshooting
- White screen: open Chrome DevTools Console; verify `frontend/src/App.jsx` exists and exports default App.
- Login not working: backend terminal should show server on port 5000; check `CLIENT_URL` matches `http://localhost:5173`.
- `EADDRINUSE`: stop the old server before starting this one.
- `npm` unknown command: type ONLY the command, not the PowerShell `PS C:\...>` prefix.
