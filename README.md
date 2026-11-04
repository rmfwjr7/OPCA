# OPCA local server

OPCA runs as a same-origin Python web app with a SQLite database. It uses only the Python standard library.

## Run

From this folder, run:

```powershell
C:/Users/오지영/AppData/Local/Python/pythoncore-3.14-64/python.exe server.py
```

Open <http://127.0.0.1:8000>. Keep the terminal running while using the app. Stop the server with `Ctrl+C`.

The first account created receives the nickname `데굴데굴 준킹볼 105`; later accounts receive another fixed anonymous nickname. Usernames are unique and may contain Hangul, English letters, numbers, `.`, `_`, and `-` (3–24 characters). Passwords must be at least 8 characters and are stored as PBKDF2-HMAC-SHA256 hashes, not plaintext. Login uses an HttpOnly, SameSite session cookie.

## Data and scope

The server stores accounts, listings, favorites, settings, sessions, and chat messages in `opca.sqlite3` in this folder. The database is intentionally excluded from static web serving. Existing browser-only demo records are not imported.

## Photo suggestions and moderator setup

Members sign in, then submit a card photo from **My Page → 포카 사진 제보**. New photos are stored outside the public web folder with `pending` status. Only an account whose username matches `OPCA_ADMIN_USERNAME` can view the review queue and approve or reject photos. Approval publishes the image and attaches it to matching card metadata. Rejected originals are deleted.

Choose your own moderator username before creating that account. In PowerShell, start the local server like this, replacing the example ID with the account ID you intend to use:

```powershell
$env:OPCA_ADMIN_USERNAME = "관리자아이디"
C:/Users/오지영/AppData/Local/Python/pythoncore-3.14-64/python.exe server.py
```

Then sign up with that exact username. On a hosting service, set `OPCA_ADMIN_USERNAME` in its environment-variable settings before signing up. The admin role is not self-selectable in the app.

For this local run, the moderator ID is configured as `opca관리자`. Create/log in with that exact ID to see **사진 승인 대기** on My Page. For a different moderator, stop the server, set `OPCA_ADMIN_USERNAME` to the chosen existing account ID, then restart it.

For deployment, mount the same persistent disk for the database and photo files, then set `OPCA_DB_PATH`, `OPCA_PRIVATE_UPLOAD_DIR`, and `OPCA_CARD_DIR` to paths on that disk (for example `/var/data/opca.sqlite3`, `/var/data/opca-pending`, and `/var/data/opca-cards`). Set `OPCA_ADMIN_USERNAME` to the moderator account ID and restart the service. Photo-submission files remain private until approval; only approved images are served publicly. The local `.gitignore` excludes both image directories.

The local server binds to `127.0.0.1`, so it is available only on this computer. This is not yet a public deployment.

## Deploy for other people

1. Put the project files in a private GitHub repository: `index.html`, `roster-data.js`, `server.py`, and `README.md`.
2. Create a Python web service with a host that supports a persistent disk. Set its start command to `python server.py`.
3. Mount persistent storage and set `OPCA_DB_PATH` to a file on that disk, for example `/var/data/opca.sqlite3`. Without persistent storage, accounts and messages may disappear when the service restarts.
4. The app reads the platform's `PORT` environment variable and binds to `0.0.0.0` when it is present. Enable the provider's HTTPS endpoint before sharing the public URL.
5. Before a wider launch, add request rate limits, account recovery, monitoring, automated database backups, and a production-grade server/database. The current notification preferences are stored, but web push is not configured.

Create the hosting account yourself. Never send hosting passwords, database credentials, or API keys in chat; enter them directly in the hosting dashboard's environment-variable settings. You do not need to choose a domain yet: the host can provide a temporary HTTPS URL first.

Run the backend tests with:

```powershell
C:/Users/오지영/AppData/Local/Python/pythoncore-3.14-64/python.exe -m unittest -v test_server.py
```
