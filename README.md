# Secure Code Agent

Local-first source-code security review dashboard built with **Python FastAPI**, **PostgreSQL**, **Ollama**, HTML, CSS and JavaScript.

## Features
- Paste code or select a UTF-8 source file (Python, JavaScript, TypeScript, SQL, Shell, Java or Go).
- Conservative pattern-based checks for likely security mistakes.
- Optional Ollama-generated code review, remediation advice and suggested revised file.
- Scan history and findings saved in PostgreSQL.
- FastAPI REST endpoints and interactive browser dashboard.
- Pytest checks and GitHub Actions CI.

> **Limitations:** This is an educational local-only security review prototype, not a comprehensive vulnerability scanner or production gate. Regex checks have false positives and false negatives; the LLM can hallucinate bugs or unsafe fixes. Always review results and test suggested code. No code is executed during a scan. **Scanned source is stored in plaintext in your local PostgreSQL database.** Only scan authorized code, and do not upload credentials or confidential code. Authentication, authorization, encryption at rest, rate limiting, background jobs, migrations, automated dependency scanning, and sandboxing are not included. Do not expose this server or database publicly.

## Prerequisites
- Python 3.11+ (3.12 recommended)
- Docker Desktop (for PostgreSQL), or an existing PostgreSQL server
- Ollama installed locally (optional but recommended)
- VS Code or a terminal

## Quick start (macOS / Linux)

```bash
git clone https://github.com/YOUR_USERNAME/secure-code-agent.git
cd secure-code-agent
cp .env.example .env
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
docker compose up -d
ollama pull llama3.2
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000**. Ollama must be installed and running separately (open the Ollama app or run `ollama serve`). If you do not have Ollama installed, set `ENABLE_AI=false` in `.env` and run static checks only. To use existing PostgreSQL instead of Docker, update `DATABASE_URL` in `.env` and create the database manually.

**Windows (PowerShell):** use `Copy-Item .env.example .env`, `py -m venv .venv`, `.venv\Scripts\Activate.ps1`, then the same pip/Docker/Ollama/uvicorn commands.

To stop PostgreSQL: `docker compose down` (data persists in a volume). To remove the database volume as well: `docker compose down -v` (deletes all scans).

## Commands

```bash
python -m pytest -q
curl http://127.0.0.1:8000/api/health
curl -X POST http://127.0.0.1:8000/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{"filename":"test.py","code":"eval(input())"}'
curl -F 'file=@test.py' http://127.0.0.1:8000/api/upload
```

## API

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Dashboard |
| `/docs` | GET | FastAPI Swagger documentation |
| `/api/health` | GET | Health check |
| `/api/analyze` | POST | JSON body: `filename`, `code` |
| `/api/upload` | POST | Form-data `file` |
| `/api/scans` | GET | Most recent 100 scans |
| `/api/scans/{id}` | GET | Complete scan including original code |
| `/api/scans/{id}/fixed` | GET | Download AI-suggested fix as TXT |

## Repo layout

```
secure-code-agent/
├── app/
│   ├── __init__.py
│   ├── ai.py             # Local Ollama analysis
│   ├── db.py             # PostgreSQL models
│   ├── main.py           # FastAPI routes
│   └── scanner.py        # Static rule checks
├── static/
│   ├── index.html
│   ├── style.css
│   └── app.js
├── tests/test_scanner.py
├── .github/workflows/tests.yml
├── .env.example
├── .gitignore
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## Safety and deployment

The default credentials in `docker-compose.yml` are for **local development only**. Change them if adapting this project. The API has no authentication and scan details reveal stored source code; keep it bound to 127.0.0.1. Never commit `.env`, secrets, or actual scanned customer code to GitHub. AI suggestions are not applied automatically. Ollama is a local service and is not included in Docker Compose.

## Roadmap
- Semgrep and Bandit integration
- GitHub pull request review in CI with explicit permission scopes
- Authentication, multi-user data separation, encryption and migrations
- Background task queue and code diff viewer
- SARIF export and secure approval workflow for suggested fixes
