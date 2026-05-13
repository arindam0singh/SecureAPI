# SecureAPI Scanner

SecureAPI Scanner is a FastAPI-based API security testing tool that scans endpoints for common web/API vulnerabilities and stores scan history in SQLite.

It includes:
- A backend scanner API (FastAPI)
- A built-in static frontend dashboard (`index.html`)
- Single-endpoint scan, Swagger/OpenAPI scan, and endpoint discovery workflows

## Features

- Scan one endpoint (`/scan/single`)
- Scan all endpoints from Swagger/OpenAPI URL (`/scan/swagger`)
- Upload Swagger/OpenAPI file and scan (`/scan/swagger/upload`)
- Discover likely API endpoints from a website (`/discover`)
- Persist scans and findings in SQLite (`secureapi.db`)
- View all scans and scan details (`/scans`, `/scans/{id}`)

## Vulnerability Scanners Included

- `rate_limit` - Rate limiting weaknesses
- `auth` - Broken auth and JWT issues
- `sqli` - SQL injection checks
- `idor` - IDOR/BOLA patterns
- `mass_assignment` - Unsafe object/property binding
- `sensitive_data` - Sensitive data exposure
- `ssrf` - SSRF indicators
- `cmd_injection` - Command injection indicators
- `cors` - CORS misconfiguration checks

## Tech Stack

- Python 3.10+
- FastAPI + Uvicorn
- SQLAlchemy (async) + SQLite (`aiosqlite`)
- `httpx` for HTTP requests
- `beautifulsoup4` for endpoint discovery

## Project Structure

```text
SecureAPI-main/
  app/
    main.py                # FastAPI app and routes
    database.py            # DB engine/session setup
    models.py              # SQLAlchemy models
    schemas.py             # Request/response schemas
    parser.py              # OpenAPI/Swagger fetch + parse
    scanners/              # Security scanner modules
  index.html               # Dashboard UI (served separately as static file)
  secureapi.db             # Local SQLite database (auto-used by backend)
```

## Setup

1. Create and activate a virtual environment.

```bash
python -m venv .venv
.venv\Scripts\activate
```

2. Install dependencies.

```bash
pip install fastapi uvicorn sqlalchemy aiosqlite httpx pyyaml python-dotenv python-multipart beautifulsoup4 PyJWT
```

## Run the Backend

From the project root (`SecureAPI-main`):

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

API docs will be available at:
- [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

## Run the Frontend Dashboard

`index.html` is a static frontend that calls the backend at `http://127.0.0.1:8000`.

In a second terminal, from the same project root:

```bash
python -m http.server 5500
```

Then open:
- [http://127.0.0.1:5500/index.html](http://127.0.0.1:5500/index.html)

## API Usage Examples

### 1. Scan a Single Endpoint

```bash
curl -X POST "http://127.0.0.1:8000/scan/single" \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"https://api.example.com/users/1\",\"method\":\"GET\",\"headers\":{},\"body\":{},\"scanners\":[\"sqli\",\"auth\",\"cors\"]}"
```

### 2. Scan by Swagger/OpenAPI URL

```bash
curl -X POST "http://127.0.0.1:8000/scan/swagger" \
  -H "Content-Type: application/json" \
  -d "{\"spec_url\":\"https://petstore.swagger.io/v2/swagger.json\",\"scanners\":[\"sqli\",\"ssrf\",\"auth\"]}"
```

### 3. Discover Endpoints from a Website

```bash
curl -X POST "http://127.0.0.1:8000/discover" \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"https://example.com\"}"
```

### 4. Get Scan History

```bash
curl "http://127.0.0.1:8000/scans"
```

## Database Configuration

By default, the app uses:

```env
DATABASE_URL=sqlite+aiosqlite:///./secureapi.db
```

You can override it with a `.env` file in the project root.

## Notes and Limitations

- Requests are made with SSL verification disabled in scanner request helpers (`verify=False`) to allow testing non-production targets with self-signed certs.
- Swagger scanning depends on parsable OpenAPI/Swagger specs.
- Discovery is heuristic and may return false positives.
- Some scanners use timing/content heuristics and should be validated manually.

## Legal and Safe Usage

Use this tool only on systems and APIs you own or are explicitly authorized to test. Unauthorized scanning may be illegal and unethical.

## Future Improvements

- Add authentication and role-based access for the scanner dashboard
- Add export formats (JSON/PDF)
- Add background job queue and scan progress tracking
- Add unit/integration test coverage and pinned dependency file (`requirements.txt`)
