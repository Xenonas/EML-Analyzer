# EML Analyzer

EML Analyzer is a small Django and React application for uploading `.eml` email
files and extracting useful header information for review.

## Current Features

- Upload an EML file through `POST /api/upload/`.
- Store the uploaded sample with its original filename, SHA-256 hash, and status.
- Queue background analysis with Celery.
- Parse email headers with Python's standard `email` parser.
- Save analysis results including:
  - subject
  - from/to/date/message ID
  - reply-to and return-path
  - user agent or mail client
  - SPF, DKIM, and authentication results
  - received hop count and received path
  - attachment filename, MIME type, size, SHA-256, and risky-extension flags
  - URL extraction, DNS resolution, redirect expansion, and local reputation flags
  - explainable risk score based on authentication, attachments, URLs, sender
    alignment, and routing signals
- Check upload and analysis status through `GET /api/upload/<sample_id>/`.
- Preview sender, receiver, date, subject, and plain-text email content in a
  collapsible email-style panel.
- Click sender addresses, return paths, and hop domains to look up DNS and RDAP
  ownership/registration details.
- Review attachment metadata and risky extension flags without storing extracted
  attachment payloads.
- Review URLs found in email text/HTML with resolved IPs, redirect information,
  final URL, and local reputation flags.
- Review an explainable risk assessment with a 0-100 score, severity, and
  scored findings.

## Project Structure

```text
EML-Analyzer/
├── backend/         # Django API, Celery worker, parser, tests
└── frontend/        # React UI powered by Vite
```

## Backend Setup

Install the project dependencies:

```bash
cd backend
pip install -r requirements.txt
```

Start Redis for Celery:

```bash
redis-server
```

Run migrations:

```bash
python manage.py migrate
```

Start the Django development server:

```bash
EML_ANALYZER_SYNC_TASKS=1 python manage.py runserver 127.0.0.1:8001
```

For async analysis, leave `EML_ANALYZER_SYNC_TASKS` unset and start the Celery
worker in another terminal:

```bash
celery -A config worker -l info
```

## Frontend Setup

Start the React development server in another terminal:

```bash
cd frontend
npm install
npm run dev
```

The frontend runs at `http://127.0.0.1:5173` and proxies `/api` requests to the
Django server at `http://127.0.0.1:8001`.

## API Usage

Upload a file:

```bash
cd backend
curl -F "file=@samples/sample.eml" http://127.0.0.1:8001/api/upload/
```

Check status and analysis result:

```bash
curl http://127.0.0.1:8001/api/upload/1/
```

Look up an address, domain, or IP:

```bash
curl "http://127.0.0.1:8001/api/lookup/?q=example.com"
```

## Authentication Checks

The UI shows SPF, DKIM, and DMARC as `pass`, `fail`, or `unknown`.

The analyzer now independently verifies:

- SPF with DNS policy evaluation using the inferred SMTP client IP and
  Return-Path domain.
- DKIM by cryptographically validating `DKIM-Signature` against DNS public keys.
- DMARC by checking the From domain's DMARC record and SPF/DKIM alignment.

The original receiver-reported results from `Authentication-Results` and
`Received-SPF` are still returned as `reported_authentication`. Because an
uploaded `.eml` does not include the live SMTP session, SPF uses the best sender
IP inferred from `Received` headers.

## Risk Scoring

The analyzer calculates a local 0-100 risk score from extracted evidence. The
current rules score failed or missing authentication controls, risky attachment
extensions, suspicious URL flags, sender/Return-Path domain mismatch, and long
received paths. Each scored signal is returned as an explainable finding in the
API and displayed in the React UI.

## Current Stage

The EML Analyzer is at an early prototype / MVP stage.

What is working in the codebase:

- Basic Django project structure exists.
- Upload and status API endpoints are implemented.
- A simple React upload and results UI exists.
- The UI includes a collapsible email preview panel.
- Attachment metadata and risky extensions are extracted and displayed.
- URLs are extracted from text/HTML parts, checked for redirects and local
  reputation flags, and displayed in the UI.
- SPF, DKIM, and DMARC are independently verified and displayed separately from
  parsed receiver-reported authentication headers.
- Risk scoring produces a severity and explainable findings from local evidence.
- Uploaded files are hashed and stored.
- Celery analysis task is implemented.
- Header extraction and result persistence are implemented.
- Tests cover selected parser behavior, authentication, URL analysis, lookup,
  and risk scoring.

What is still incomplete or rough:

- The React UI is intentionally simple and still needs production polish.
- The risk score is rule-based and local-only. It does not query commercial
  threat intelligence feeds or sandbox attachments.
- There is no production configuration for secrets, allowed hosts, storage, or
  deployment.

In short: the analyzer can already accept an EML file and parse important
headers, but it is not production-ready and still needs broader tests,
deployment hardening, and external reputation/sandbox integrations.
