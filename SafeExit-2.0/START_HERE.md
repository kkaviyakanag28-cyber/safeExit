# SafeExit 2.1 — College & Hostel Issue Management

## What changed
- Emergency exit monitoring removed from the interface and backend routes.
- Optional evidence photos; reports can be submitted without an image.
- College staff, hostel warden, and admin use the same login screen, with role-based access.
- Staff receive persistent real-time notifications on new reports and student messages. Students receive notifications when staff reply or change report status.
- Professional typography and cleaner interface.

## IMPORTANT: Keep your working credentials
This ZIP deliberately does **not** include `.env`, passwords, MongoDB connection strings, or `node_modules`. Your original SafeExit-2.0 folder is not modified.

1. Extract to a NEW folder. Do not delete your working old project.
2. Copy `backend/.env` from your **own working SafeExit-2.0/backend** into the new `backend` folder locally. Never share that file.
3. Open a VS Code terminal in new `backend`; run `npm install`, then `npm start`. `npm start` automatically loads `dns-fix.js`.
4. In another terminal, open new `frontend`; run `npm install`, then `npm run dev`.
5. Visit http://localhost:5173 and sign in with your existing account.
6. To create a staff account, from backend run `npm run staff`, choose `officer`, `warden` or `admin`, and provide a unique email and password. The same login screen is used by all roles.

### Verify real-time behavior
Open student and staff accounts in separate browser profiles (e.g. normal and incognito). Submit a college report: college staff/admin should receive a notification without refresh. Submit a hostel report: warden/admin should receive it. Open a report and send a private message; the other party should see a notification and new message.

### Security and limitations
This is a college prototype, not an emergency dispatch system. Keep MongoDB credentials and JWT secret private. A newly extracted copy still needs the existing local `.env` file and npm packages. Mobile hotspots may change public IP; update MongoDB Atlas Network Access when necessary.
