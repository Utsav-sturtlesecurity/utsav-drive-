# CloudDrive - Final (with working share links)
Features:
- Register / Login / Logout (Flask-Login)
- Upload (encrypted), preview, download, delete
- Shareable public links with expiry (preview + download)
- Attractive Bootstrap UI + dark toggle
- Per-user quota (default 500MB)

## Quick start
1. python -m venv venv
2. venv\Scripts\activate  # Windows
   source venv/bin/activate  # macOS / Linux
3. pip install -r requirements.txt
4. python app.py
5. Open http://127.0.0.1:5000 (demo/demo123)

## Notes
- This is a demo app. Do not use as-is in production.
- Keep SECRET_KEY and enc.key safe for production.
