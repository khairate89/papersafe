# PaperSafe

PaperSafe is a small Flask application for private PDF storage with explicit owner-managed sharing. It is a local coursework project for exploring web application security and vulnerability assessment.

## Features and technologies

- Python 3.10+, Flask, Flask-WTF, Werkzeug, and SQLite
- Registration and login with Werkzeug password hashing
- Session cookies and CSRF protection on state-changing forms
- PDF uploads capped at 10 MiB of file content, with a bounded 64 KiB allowance for multipart request overhead, an extension allowlist, and a basic `%PDF-` prefix check
- Private storage outside static assets, using generated filenames
- Parameterized title search
- Owner-only delete; documents can be shared with another registered user, who can then list and download them; owners can revoke access
- SQLite constraints for duplicate/self-share protection and foreign-key integrity

## Start with Docker Compose

Install Docker Desktop, then run from this directory:

```sh
docker compose up --build
```

Open <http://127.0.0.1:5000>. Compose binds the service to localhost only, persists the SQLite database, uploaded PDFs, and generated development secret in a named volume, and initializes synthetic demo data on first start. Stop with `Ctrl+C` or `docker compose down`; the named volume preserves data between starts.

### Local demo accounts

These fixed credentials are synthetic and intended only for this local coursework demo:

| Username | Password |
|---|---|
| `alice` | `PaperSafe-Alice-2026!` |
| `bob` | `PaperSafe-Bob-2026!` |

Alice owns a harmless sample PDF that is shared with Bob. The seed command is idempotent and does not reset existing account passwords. Never reuse these credentials elsewhere.

## Run without a container

```sh
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m flask --app app seed-demo
.venv\Scripts\python.exe app.py
```

On macOS/Linux, replace `.venv\Scripts\python.exe` with `.venv/bin/python`. Local development generates a random session secret in `instance/.flask_secret`, ignored by Git. Outside development mode, set `APP_ENV` appropriately and provide `PDF_APP_SECRET`; the app refuses to start if the secret is missing. Do not print or commit the secret.

## Tests

Install the pinned development test dependency and run the suite:

```sh
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```

The standard-library `unittest` suite uses temporary SQLite databases, synthetic accounts, and benign PDF fixtures; no test package needs to be installed. It covers registration/login, upload limits and type checks, title search/SQLi-style input, CSRF rejection, share/revoke behavior, SQLite share constraints, seeded demo data, secret handling, and cross-account authorization.

## Endpoint count

PaperSafe defines 9 route patterns and 12 explicit method–route operations (8 original route patterns plus the share-management pattern). Each explicit method is counted separately; share and revoke are actions handled by the same CSRF-protected `POST /documents/<id>/shares` operation. Flask's automatic `HEAD` and `OPTIONS` methods and its static-asset route are excluded from this application-operation count. Sharing adds one operation to the original 11, leaving the project two operations above the top of the approximate 8–10 range; the dedicated route keeps sharing authorization auditable.

## Security scope and limitations

- The application uses parameterized SQL queries to prevent user-supplied input from being interpreted as SQL code.
- A `.pdf` extension and `%PDF-` prefix are basic checks, not proof that a file is valid or safe, and they do not detect malware.
- PaperSafe does not parse, preview, or extract PDF contents. Adding that feature would add parser attack surface; use a maintained library, strict resource limits, and an isolated worker.
- Compose is configured for local coursework only. It uses the Flask development server and a generated development secret; it is not production-ready. Do not expose it publicly. A real deployment would require production WSGI hosting, HTTPS, managed secrets, rate limiting, logging, backups, and an operational security review.
- Use synthetic data only and assess systems only with authorization.

## Project files

- `app.py` — Flask routes, SQLite access, upload/download, sharing, and configuration
- `templates/`, `static/` — HTML templates and styling
- `tests/test_app.py` — isolated automated tests
- `Dockerfile`, `compose.yaml` — local-only container setup
- `requirements.txt`, `requirements-dev.txt` — pinned runtime dependencies (tests use the standard library)

