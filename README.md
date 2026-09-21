# 🛡️ Automated Security Log Analysis using Agentic AI

<p align="center">

  <strong>AI-Assisted Security Log Analysis & Threat Intelligence Platform</strong>

  <br><br>

  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/FastAPI-Backend-009688?style=for-the-badge&logo=fastapi&logoColor=white">
  <img src="https://img.shields.io/badge/JavaScript-Vanilla-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black">
  <img src="https://img.shields.io/badge/Groq-AI-orange?style=for-the-badge">
  <img src="https://img.shields.io/badge/Tavily-Threat%20Intel-4285F4?style=for-the-badge">
  <img src="https://img.shields.io/badge/JSON-Logs-000000?style=for-the-badge&logo=json&logoColor=white">

</p>

<p align="center">

  <a href="#-overview">Overview</a> •
  <a href="#-features">Features</a> •
  <a href="#-architecture">Architecture</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-api-documentation">API</a> •
  <a href="#-deployment">Deployment</a> •
  <a href="#-future-scope">Future Scope</a>

</p>

---

# 📌 Overview

**Automated Security Log Analysis using Agentic AI and Threat Intelligence** is a defensive cybersecurity application designed to simplify and automate the analysis of structured security logs.

Security systems generate a large amount of log data containing authentication events, network activity, suspicious requests, failed login attempts, attack patterns, and other security-related events.

Manually reviewing these logs can be time-consuming and difficult, especially when analysts need to correlate events with external threat intelligence.

This project provides an **AI-assisted security analysis pipeline** that processes logs through multiple stages:

```text
Security Logs
      │
      ▼
┌─────────────────────┐
│   Parse / Validate  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Normalize Logs     │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Extract Indicators  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Threat Intelligence │
│      - Tavily       │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│   AI Reasoning      │
│      - Groq         │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Threat Assessment   │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Recommendations     │
└─────────────────────┘
```

The application provides a web-based interface where users can:

- Paste security logs
- Upload JSON log files
- Start automated analysis
- View detected threats
- View severity levels
- Review evidence
- View threat-intelligence information
- View AI-generated explanations
- Review defensive recommendations
- Monitor the high-level analysis pipeline

---

# 🎯 Project Objectives

The main objectives of this project are:

1. Automate the initial analysis of structured security logs.
2. Reduce the amount of manual effort required for log inspection.
3. Extract security-relevant indicators from logs.
4. Enrich indicators using external threat intelligence.
5. Use AI-assisted reasoning to identify suspicious activity.
6. Generate structured security findings.
7. Provide severity and confidence information.
8. Provide evidence supporting detected threats.
9. Generate defensive recommendations.
10. Provide a simple and understandable web interface.
11. Demonstrate the practical use of Agentic AI in cybersecurity.

---

# ✨ Features

## 🔍 1. Security Log Analysis

The application accepts structured JSON security logs.

Supported input methods include:

- JSON paste
- JSON file upload
- Sample/mock logs

Example:

```json
{
  "logs": [
    {
      "timestamp": "2026-09-20T10:15:02Z",
      "source_ip": "203.0.113.42",
      "event": "failed login",
      "user": "admin",
      "status": "failure"
    }
  ]
}
```

---

## 🧹 2. Log Normalization

Incoming logs are normalized before analysis.

This helps the backend work with different structured log formats and prepares the information for subsequent processing.

The normalization stage may process information such as:

- Timestamp
- Source IP
- Event type
- User
- Status
- URL
- Request path
- Security event information

---

## 🔎 3. Indicator Extraction

The system extracts potentially security-relevant indicators from the submitted logs.

Examples include:

```text
IP Addresses
Domains
URLs
Suspicious Paths
Authentication Events
Failed Login Attempts
Attack Patterns
Security Events
```

These indicators are then used for further analysis and threat-intelligence enrichment.

---

# 🌐 4. Threat Intelligence Enrichment

The application integrates with **Tavily** to obtain additional information about extracted indicators.

The purpose of this stage is to provide additional context around suspicious indicators.

The enrichment pipeline can help answer questions such as:

```text
Is this indicator associated with suspicious activity?

Has this IP/domain been discussed in security-related sources?

What additional context is available?

What type of activity may be associated with the indicator?
```

---

# 🤖 5. Agentic AI-Assisted Reasoning

The project uses Groq-powered AI reasoning as part of the analysis pipeline.

The high-level processing flow is:

```text
Parse
  ↓
Extract
  ↓
Enrich
  ↓
Reason
  ↓
Recommend
```

The AI component can generate structured security findings including:

- Threat type
- Severity
- Confidence
- Description
- Evidence
- Threat intelligence context
- Recommendations

---

# 🚨 6. Threat Detection

The system can identify suspicious patterns such as:

- Repeated failed login attempts
- Suspicious authentication activity
- SQL injection attempts
- Suspicious requests
- Potential attack indicators
- Other abnormal security events present in the supplied logs

Detection depends on the quality and structure of the input logs.

---

# 📊 7. Risk Assessment

The application provides a high-level risk assessment.

Example:

```text
Overall Risk: HIGH

Threats Found: 2

Severity:
HIGH
MEDIUM
LOW
```

The exact assessment depends on the submitted logs and analysis results.

---

# 🧾 8. Evidence-Based Findings

Each detected threat can contain supporting evidence.

Example:

```text
Threat:
Brute Force Activity

Source IP:
203.0.113.42

Evidence:
- Multiple failed login attempts
- Multiple targeted accounts
- Repeated requests within a short period
```

This makes the result easier for a human analyst to review.

---

# 🛠️ 9. Defensive Recommendations

The system generates recommendations based on detected activity.

Examples:

```text
• Investigate the source IP
• Review authentication logs
• Apply rate limiting
• Monitor repeated failed login attempts
• Review affected accounts
• Investigate suspicious request patterns
```

AI-generated recommendations should be reviewed by a human before operational use.

---

# 🖥️ 10. Web Dashboard

The frontend provides a simple interface for:

- Log input
- File upload
- Analysis execution
- Risk display
- Threat display
- Severity indicators
- Evidence
- Recommendations
- Processing stages
- Analysis summary

The frontend is intentionally implemented using:

```text
HTML
CSS
Vanilla JavaScript
```

No frontend framework is required.

---

# 🏗️ Architecture

```text
                         ┌──────────────────────┐
                         │       User           │
                         │  Security Analyst    │
                         └──────────┬───────────┘
                                    │
                                    ▼
                    ┌──────────────────────────────┐
                    │          Frontend            │
                    │                              │
                    │       HTML / CSS / JS        │
                    │                              │
                    │  • Paste Logs                │
                    │  • Upload JSON               │
                    │  • View Results               │
                    │  • Risk Dashboard             │
                    └──────────────┬───────────────┘
                                   │
                              HTTP / JSON
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │        FastAPI Backend        │
                    │                              │
                    │  • Validation                 │
                    │  • Normalization              │
                    │  • Indicator Extraction      │
                    │  • Orchestration              │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────┴──────────────┐
                    │                             │
                    ▼                             ▼
          ┌──────────────────┐          ┌──────────────────┐
          │      Tavily      │          │      Groq AI     │
          │                  │          │                  │
          │ Threat Intel     │          │ AI Reasoning     │
          │ Enrichment       │          │ Analysis         │
          └────────┬─────────┘          └────────┬─────────┘
                   │                             │
                   └──────────────┬──────────────┘
                                  │
                                  ▼
                    ┌──────────────────────────────┐
                    │       Analysis Results       │
                    │                              │
                    │ • Threats                    │
                    │ • Severity                   │
                    │ • Confidence                 │
                    │ • Evidence                   │
                    │ • Threat Intelligence        │
                    │ • Recommendations            │
                    │ • Summary                    │
                    └──────────────┬───────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │       Frontend Dashboard      │
                    └──────────────────────────────┘
```

---

# 🔄 Agentic Processing Pipeline

The application exposes the following high-level processing stages:

```text
┌────────────┐
│   PARSE    │
│            │
│ Receive &  │
│ validate   │
│ logs       │
└─────┬──────┘
      │
      ▼
┌────────────┐
│  EXTRACT   │
│            │
│ Identify   │
│ indicators │
└─────┬──────┘
      │
      ▼
┌────────────┐
│   ENRICH   │
│            │
│ Threat     │
│ intelligence│
└─────┬──────┘
      │
      ▼
┌────────────┐
│   REASON   │
│            │
│ AI-assisted│
│ analysis   │
└─────┬──────┘
      │
      ▼
┌────────────┐
│ RECOMMEND  │
│            │
│ Defensive  │
│ actions    │
└────────────┘
```

---

# 🧩 Technology Stack

| Component | Technology |
|---|---|
| Programming Language | Python |
| Backend Framework | FastAPI |
| Frontend | HTML5, CSS3, JavaScript |
| AI Platform | Groq |
| AI Model | `openai/gpt-oss-120b` |
| Threat Intelligence | Tavily |
| Data Format | JSON |
| API Standard | REST |
| API Documentation | Swagger / OpenAPI |
| Version Control | Git |
| Repository | GitHub |
| Backend Deployment | Render |
| Frontend Deployment | Static Web Hosting |

The current Groq documentation lists `openai/gpt-oss-120b` as a production model with reasoning, tool-use and structured-output capabilities. :contentReference[oaicite:2]{index=2}

---

# 📁 Project Structure

```text
Security-Log-Analyzer/
│
├── backend/
│   │
│   ├── app.py
│   ├── requirements.txt
│   ├── .env.example
│   └── ...
│
├── frontend/
│   │
│   ├── index.html
│   ├── styles.css
│   ├── script.js
│   └── ...
│
├── mock-logs.json
│
├── SETUP.md
│
├── README.md
│
├── LICENSE.txt
│
└── .gitignore
```

---

# ⚙️ Requirements

Before running the project, install:

### Required Software

- Python 3.10 or newer
- Git
- Web browser
- Internet connection

### Required API Keys

The application requires:

```text
GROQ_API_KEY
TAVILY_API_KEY
```

Create the API keys from their respective platforms.

---

# 🚀 Installation

## Step 1 — Clone Repository

```bash
git clone https://github.com/Anubhavsethi13/Security-Log-Analyzer.git
```

Move into the project:

```bash
cd Security-Log-Analyzer
```

---

# 🐍 Backend Setup

## Step 2 — Open Backend

```bash
cd backend
```

---

## Step 3 — Create Virtual Environment

### Windows

```bash
python -m venv .venv
```

Activate:

```bash
.venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv .venv
```

Activate:

```bash
source .venv/bin/activate
```

---

# 📦 Step 4 — Install Dependencies

```bash
pip install -r requirements.txt
```

---

# 🔐 Step 5 — Configure Environment Variables

Create:

```text
backend/.env
```

Add:

```env
GROQ_API_KEY=your_groq_api_key
TAVILY_API_KEY=your_tavily_api_key
GROQ_MODEL=openai/gpt-oss-120b
```

### Example

```env
GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxx
TAVILY_API_KEY=tvly-xxxxxxxxxxxxxxxxx
GROQ_MODEL=openai/gpt-oss-120b
```

### ⚠️ NEVER commit `.env`

Your `.gitignore` should contain:

```gitignore
.env
.venv/
__pycache__/
*.pyc
```

---

# ▶️ Step 6 — Start Backend

From:

```text
Security-Log-Analyzer/backend
```

Run:

```bash
python -m uvicorn app:app --reload --host 127.0.0.1 --port 8000
```

You should see:

```text
Uvicorn running on http://127.0.0.1:8000
```

---

# ❤️ Step 7 — Test Backend Health

Open:

```text
http://127.0.0.1:8000/api/health
```

You should receive a successful response.

---

# 📚 API Documentation

FastAPI automatically provides Swagger documentation.

Open:

```text
http://127.0.0.1:8000/docs
```

You can test API endpoints directly from Swagger UI.

---

# 🔌 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/health` | Backend health check |
| POST | `/api/analyze` | Analyze JSON security logs |
| POST | `/api/analyze-file` | Analyze uploaded log file |

---

# 🧪 Analyze Logs using Swagger

Open:

```text
http://127.0.0.1:8000/docs
```

Find:

```text
POST /api/analyze
```

Click:

```text
Try it out
```

Use:

```json
{
  "logs": [
    {
      "timestamp": "2026-09-20T10:15:02Z",
      "source_ip": "203.0.113.42",
      "event": "failed login",
      "user": "admin",
      "status": "failure"
    },
    {
      "timestamp": "2026-09-20T10:15:05Z",
      "source_ip": "203.0.113.42",
      "event": "failed login",
      "user": "root",
      "status": "failure"
    },
    {
      "timestamp": "2026-09-20T10:16:11Z",
      "source_ip": "198.51.100.77",
      "event": "SQL injection attempt",
      "path": "/login?id=1 OR 1=1",
      "status": "blocked"
    }
  ]
}
```

Then click:

```text
Execute
```

---

# 🧪 Using the Mock Logs

The repository includes:

```text
mock-logs.json
```

This file can be used for:

- Testing
- Demonstration
- Presentation
- API testing
- Frontend testing

Example:

```bash
cat mock-logs.json
```

On Windows PowerShell:

```powershell
Get-Content mock-logs.json
```

---

# 🖥️ Frontend Setup

Open another terminal.

From the project root:

```bash
cd frontend
```

---

# ▶️ Run Frontend

Because the frontend is built using standard HTML, CSS and JavaScript, no Node.js framework is required.

## Option 1 — Python HTTP Server

Run:

```bash
python -m http.server 5500
```

Open:

```text
http://127.0.0.1:5500
```

---

# Option 2 — VS Code Live Server

1. Open the project in VS Code.
2. Open:

```text
frontend/index.html
```

3. Install the **Live Server** extension.
4. Right-click `index.html`.
5. Select:

```text
Open with Live Server
```

---

# 🔗 Frontend API Configuration

The frontend must communicate with the FastAPI backend.

For local development:

```javascript
const API = "http://127.0.0.1:8000";
```

For production:

```javascript
const API = "https://your-backend-url.onrender.com";
```

Make sure the backend CORS configuration allows the deployed frontend origin.

---

# 🧭 Complete Local Setup

You can run the complete application using two terminals.

### Terminal 1 — Backend

```bash
cd Security-Log-Analyzer/backend

python -m venv .venv

.venv\Scripts\activate

pip install -r requirements.txt

python -m uvicorn app:app --reload --host 127.0.0.1 --port 8000
```

### Terminal 2 — Frontend

```bash
cd Security-Log-Analyzer/frontend

python -m http.server 5500
```

Then open:

```text
Frontend:
http://127.0.0.1:5500

Backend:
http://127.0.0.1:8000

Swagger:
http://127.0.0.1:8000/docs

Health:
http://127.0.0.1:8000/api/health
```

---

# 📊 Example Analysis

Input:

```text
Multiple failed login attempts
+
SQL injection attempt
+
Suspicious source IP
```

Processing:

```text
             INPUT
               │
               ▼
       ┌──────────────┐
       │ Parse Logs   │
       └──────┬───────┘
              │
              ▼
       ┌──────────────┐
       │ Extract IOCs │
       └──────┬───────┘
              │
              ▼
       ┌──────────────┐
       │ Tavily Search│
       └──────┬───────┘
              │
              ▼
       ┌──────────────┐
       │   Groq AI    │
       │   Reasoning  │
       └──────┬───────┘
              │
              ▼
       ┌──────────────┐
       │ Threat       │
       │ Assessment   │
       └──────┬───────┘
              │
              ▼
       ┌──────────────┐
       │ Recommend    │
       │ Actions      │
       └──────────────┘
```

---

# 📋 Example Result Structure

The backend can return structured information similar to:

```json
{
  "analysis": {
    "overall_risk": "HIGH",
    "summary": "Suspicious activity detected in the submitted logs.",
    "threats": [
      {
        "type": "Brute Force",
        "severity": "HIGH",
        "source_ip": "203.0.113.42",
        "confidence": 0.91,
        "description": "Repeated failed authentication attempts were detected.",
        "evidence": [
          "Multiple failed login attempts",
          "Multiple targeted accounts"
        ],
        "recommendations": [
          "Review authentication logs",
          "Apply rate limiting",
          "Investigate the source IP"
        ]
      }
    ]
  }
}
```

The exact output varies according to the supplied logs and external API results.

---

# ☁️ Deployment

The application can be deployed as separate frontend and backend services.

```text
                    INTERNET
                       │
          ┌────────────┴────────────┐
          │                         │
          ▼                         ▼
   ┌───────────────┐        ┌────────────────┐
   │   Frontend    │        │    Backend     │
   │               │        │                │
   │ HTML/CSS/JS   │───────►│    FastAPI     │
   │ Static Host   │  API   │    Render      │
   └───────────────┘        └───────┬────────┘
                                    │
                         ┌──────────┴──────────┐
                         │                     │
                         ▼                     ▼
                   ┌──────────┐          ┌──────────┐
                   │   Groq   │          │  Tavily  │
                   │   AI     │          │ Threat   │
                   │          │          │ Intel    │
                   └──────────┘          └──────────┘
```

---

# 🚀 Backend Deployment on Render

## Build Command

```text
pip install -r requirements.txt
```

## Start Command

```text
uvicorn app:app --host 0.0.0.0 --port $PORT
```

## Environment Variables

Configure these in Render:

```text
GROQ_API_KEY=your_groq_api_key
TAVILY_API_KEY=your_tavily_api_key
GROQ_MODEL=openai/gpt-oss-120b
```

Do not put API keys directly into the source code.

---

# 🌐 Frontend Deployment

The frontend is a static website and can be deployed using a static hosting provider.

After deployment, change:

```javascript
const API = "http://127.0.0.1:8000";
```

to:

```javascript
const API = "https://your-backend-url.onrender.com";
```

Then redeploy the frontend.

---

# ❤️ Uptime Monitoring

The backend health endpoint can be monitored using an uptime-monitoring service.

Recommended endpoint:

```text
https://your-backend-url.onrender.com/api/health
```

Use the health endpoint instead of:

```text
/api/analyze
```

because the analysis endpoint requires log data and invokes the AI analysis pipeline.

---

# 🧪 Testing

Testing should be performed before deployment.

## Backend Tests

If tests are included in the backend:

```bash
pytest
```

Verbose:

```bash
pytest -v
```

---

# 🔬 Manual Testing Checklist

### Backend

- [ ] Backend starts successfully
- [ ] `/api/health` responds successfully
- [ ] Swagger UI loads
- [ ] `/api/analyze` accepts valid JSON
- [ ] `/api/analyze-file` accepts valid files
- [ ] Invalid JSON is rejected
- [ ] Missing fields are handled
- [ ] Missing API keys are handled
- [ ] AI API failures are handled
- [ ] Threat-intelligence failures are handled

### Frontend

- [ ] Frontend loads
- [ ] JSON can be pasted
- [ ] JSON file can be uploaded
- [ ] Analyze button works
- [ ] Loading state appears
- [ ] Results are displayed
- [ ] Severity is visible
- [ ] Evidence is displayed
- [ ] Recommendations are displayed
- [ ] Agent stages are visible
- [ ] Backend errors are displayed properly

---

# 🔐 Security Considerations

Security is an important part of this project.

## API Key Protection

API keys must remain in the backend environment.

```text
             ❌ WRONG

Frontend
   │
   ├── GROQ_API_KEY
   └── TAVILY_API_KEY


             ✅ CORRECT

Frontend
   │
   │ HTTP Request
   ▼
Backend
   │
   ├── GROQ_API_KEY
   └── TAVILY_API_KEY
```

---

# 🔒 Environment Variables

Never commit:

```text
.env
```

Never expose:

```text
GROQ_API_KEY
TAVILY_API_KEY
```

Never hard-code API keys into:

```text
app.py
script.js
index.html
styles.css
```

---

# 🧹 Recommended `.gitignore`

```gitignore
# Environment
.env
.env.*
!.env.example

# Python
__pycache__/
*.py[cod]
*.pyo
*.pyd

# Virtual environments
.venv/
venv/
env/

# Testing
.pytest_cache/
.coverage
htmlcov/

# IDE
.vscode/
.idea/

# OS
.DS_Store
Thumbs.db

# Logs
*.log
```

---

# ⚠️ Security & Privacy

Security logs can contain sensitive information.

Examples:

```text
IP addresses
Usernames
URLs
Internal hostnames
Authentication information
System information
```

Therefore:

- Do not upload confidential production logs to a public repository.
- Use synthetic logs for demonstrations.
- Sanitize sensitive information before analysis.
- Do not commit private logs to GitHub.
- Review AI-generated results before using them operationally.

---

# 🧠 Why Agentic AI?

Traditional log analysis usually follows a relatively static process:

```text
Log
 ↓
Rule
 ↓
Alert
```

This project demonstrates a multi-stage AI-assisted workflow:

```text
Log
 ↓
Parse
 ↓
Extract
 ↓
Enrich
 ↓
Reason
 ↓
Recommend
```

Each stage contributes to the overall security-analysis workflow.

The goal is not to replace security analysts, but to assist them by reducing repetitive analysis and providing structured context.

---

# 📈 Advantages

### ⚡ Faster Initial Analysis

Large amounts of structured logs can be processed automatically.

### 🤖 AI-Assisted Reasoning

The AI model can provide contextual analysis instead of relying only on fixed rules.

### 🌐 External Threat Intelligence

Indicators can be enriched using external search-based threat intelligence.

### 📊 Structured Results

Security findings are presented using structured fields such as:

```text
Threat
Severity
Confidence
Evidence
Description
Recommendations
```

### 🖥️ Simple User Interface

The frontend does not require knowledge of complex SIEM tools.

### 🔐 Secure API Key Architecture

External API credentials remain on the backend.

---

# ⚠️ Limitations

The project currently has several limitations.

### 1. AI Dependency

Analysis quality depends on the AI model and API availability.

### 2. Threat Intelligence Dependency

External enrichment depends on Tavily availability and the information returned by external sources.

### 3. Input Dependency

Poorly structured or incomplete logs may reduce detection quality.

### 4. Human Verification

AI-generated findings should not automatically be treated as confirmed security incidents.

### 5. No Complete SIEM Replacement

The project is an AI-assisted log-analysis application and is not intended to replace enterprise SIEM/SOC platforms.

### 6. External API Limits

API providers may enforce request and usage limits.

---

# 🔮 Future Scope

The project can be expanded with:

## 📡 Real-Time Log Monitoring

Integrate:

- Syslog
- Windows Event Logs
- Linux authentication logs
- Application logs
- Network logs

---

## 🧩 SIEM Integration

Possible integrations:

```text
Splunk
Elastic / ELK
Wazuh
Microsoft Sentinel
Security Onion
```

---

## 🧠 MITRE ATT&CK Mapping

Detected activity could be mapped to:

```text
Tactics
Techniques
Sub-techniques
Attack Patterns
```

---

## 🚨 Automated Alerts

Future versions could support:

```text
Email Alerts
Slack Alerts
Webhook Alerts
SMS Alerts
SOC Notifications
```

---

## 📊 Advanced Dashboard

Future dashboards could include:

```text
Threat Trends
Risk Trends
Top Source IPs
Attack Categories
Severity Distribution
Timeline Analysis
IOC Statistics
```

---

## 🗄️ Persistent Storage

A future version could store:

```text
Analysis History
Threat Findings
Indicators
Reports
User Activity
Investigation Records
```

using a database.

---

## 👥 Authentication & RBAC

Future versions could introduce:

```text
Administrator
Security Analyst
Viewer
Auditor
```

with role-based access control.

---

## 🔄 Automated Incident Response

Future versions could integrate controlled response actions such as:

```text
Block IP
Disable Account
Create Incident
Isolate Host
Generate SOC Ticket
```

These actions should require appropriate authorization and safeguards.

---

# 🎓 Academic Relevance

This project combines multiple areas of computer science and cybersecurity.

### Cybersecurity

- Security logs
- Threat detection
- Indicators of compromise
- Threat intelligence
- Security recommendations

### Artificial Intelligence

- Large Language Models
- AI-assisted reasoning
- Structured AI output
- Agentic workflow

### Web Development

- Frontend
- REST APIs
- Backend services
- JSON communication

### Cloud / Deployment

- API deployment
- Static frontend deployment
- Environment configuration

---

# 🧑‍💻 Project Workflow

```text
                    START
                      │
                      ▼
             User submits logs
                      │
                      ▼
               Validate input
                      │
                      ▼
              Normalize logs
                      │
                      ▼
            Extract indicators
                      │
                      ▼
       ┌──────────────┴──────────────┐
       │                             │
       ▼                             ▼
Threat Intelligence             Log Context
       │                             │
       └──────────────┬──────────────┘
                      │
                      ▼
                 Groq AI
                      │
                      ▼
             Analyze activity
                      │
                      ▼
              Classify threats
                      │
                      ▼
            Generate evidence
                      │
                      ▼
           Generate recommendations
                      │
                      ▼
              Display results
                      │
                      ▼
                     END
```

---

# 📋 Example Security Scenarios

The application can be demonstrated using scenarios such as:

## Scenario 1 — Brute Force

```text
Multiple failed login attempts
        ↓
Same source IP
        ↓
Multiple accounts targeted
        ↓
Potential brute-force activity
```

---

## Scenario 2 — SQL Injection

```text
Suspicious request
        ↓
SQL injection pattern
        ↓
Request blocked
        ↓
Potential SQL injection attempt
```

---

## Scenario 3 — Suspicious IP

```text
Security event
        ↓
Extract source IP
        ↓
Threat intelligence lookup
        ↓
Additional context
        ↓
AI-assisted assessment
```

---

# 📸 Screenshots

Add your actual application screenshots here.

Recommended screenshots:

### 1. Main Dashboard

```text
docs/screenshots/dashboard.png
```

### 2. Log Input

```text
docs/screenshots/log-input.png
```

### 3. Analysis Result

```text
docs/screenshots/analysis-result.png
```

### 4. Swagger API

```text
docs/screenshots/swagger.png
```

Example Markdown:

```markdown
## Dashboard

![Dashboard](docs/screenshots/dashboard.png)

## Analysis Results

![Analysis Results](docs/screenshots/analysis-result.png)

## API Documentation

![Swagger](docs/screenshots/swagger.png)
```

---

# 📚 API Documentation

When running locally:

```text
Swagger UI
http://127.0.0.1:8000/docs
```

Alternative OpenAPI documentation:

```text
http://127.0.0.1:8000/redoc
```

---

# 🛠️ Troubleshooting

## Backend does not start

Check Python:

```bash
python --version
```

Check virtual environment:

```bash
.venv\Scripts\activate
```

Install dependencies again:

```bash
pip install -r requirements.txt
```

---

## Port 8000 already in use

Windows:

```powershell
netstat -ano | findstr :8000
```

Then stop the conflicting process if necessary.

Alternatively run:

```bash
python -m uvicorn app:app --reload --port 8001
```

---

## Frontend cannot connect to backend

Check that the backend is running:

```text
http://127.0.0.1:8000/api/health
```

Then verify the frontend API URL:

```javascript
const API = "http://127.0.0.1:8000";
```

---

## Groq API Error

Check:

```text
GROQ_API_KEY
GROQ_MODEL
```

Example:

```env
GROQ_MODEL=openai/gpt-oss-120b
```

Also verify that the selected model is currently supported by Groq.

---

## Tavily API Error

Check:

```text
TAVILY_API_KEY
```

Make sure the API key is configured in the backend environment.

---

## CORS Error

If the frontend is deployed separately from the backend, configure FastAPI CORS to allow the frontend origin.

For local development, verify the backend is accessible from:

```text
http://127.0.0.1:5500
```

---

# 📝 Development Guidelines

When contributing to the project:

1. Keep API keys out of source code.
2. Use environment variables for secrets.
3. Validate user input.
4. Keep frontend and backend responsibilities separated.
5. Add tests for important backend changes.
6. Avoid committing generated files.
7. Use meaningful commit messages.
8. Test locally before deployment.
9. Do not upload confidential security logs.
10. Document major architectural changes.

---

# 🤝 Contribution

Contributions are welcome.

## Clone

```bash
git clone https://github.com/Anubhavsethi13/Security-Log-Analyzer.git
```

## Create a Branch

```bash
git checkout -b feature/your-feature
```

## Make Changes

Implement and test your changes.

## Commit

```bash
git add .
git commit -m "Add your feature"
```

## Push

```bash
git push origin feature/your-feature
```

Then create a Pull Request.

---

# 📜 License

This project is distributed under the license specified in:

```text
LICENSE.txt
```

Please review the license before redistributing or modifying the project.

---

# ⚠️ Disclaimer

This project is intended for:

- Educational purposes
- Academic demonstrations
- Cybersecurity research
- Defensive security analysis
- Authorized testing

Do not use this application to analyze systems, networks, accounts, or data without proper authorization.

AI-generated security findings are not guaranteed to be correct and should be reviewed by a qualified human analyst before operational use.

---

# 👨‍💻 Project Information

**Project Name**

> Automated Security Log Analysis using Agentic AI and Threat Intelligence

**Domain**

> Cybersecurity + Artificial Intelligence

**Application Type**

> Defensive Security Analysis Platform

**Backend**

> Python + FastAPI

**Frontend**

> HTML + CSS + Vanilla JavaScript

**AI**

> Groq

**Threat Intelligence**

> Tavily

**Data Format**

> JSON

**Repository**

> https://github.com/Anubhavsethi13/Security-Log-Analyzer

---

# 🔗 Important Links

### GitHub Repository

https://github.com/Anubhavsethi13/Security-Log-Analyzer

### Local Backend

```text
http://127.0.0.1:8000
```

### Swagger

```text
http://127.0.0.1:8000/docs
```

### ReDoc

```text
http://127.0.0.1:8000/redoc
```

### Health Check

```text
http://127.0.0.1:8000/api/health
```

---

# ⭐ Support the Project

If you found this project useful for learning about:

- Cybersecurity
- Artificial Intelligence
- Threat Intelligence
- FastAPI
- Agentic AI
- Security Log Analysis

consider giving the repository a ⭐.

---

# 🛡️ Final Summary

```text
┌─────────────────────────────────────────────────────┐
│                                                     │
│       AUTOMATED SECURITY LOG ANALYSIS               │
│                                                     │
│                  Agentic AI                         │
│                      +                              │
│              Threat Intelligence                   │
│                      +                              │
│                Security Logs                        │
│                                                     │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Parse → Extract → Enrich → Reason → Recommend     │
│                                                     │
├─────────────────────────────────────────────────────┤
│                                                     │
│  FastAPI  •  Groq  •  Tavily  •  JavaScript        │
│                                                     │
└─────────────────────────────────────────────────────┘
```

> **Built for defensive cybersecurity, academic learning, experimentation, and AI-assisted security analysis.**
