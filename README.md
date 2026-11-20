# COGNISEC-AI: Agentic Cognitive Zero Trust Identity Protection System

**Institution:** Sai Vidya Institute of Technology (SVIT), Bengaluru
**Department:** Department of Computer Science and Engineering
**Project Type:** Major Project Evaluation
**Live Production URL:** [https://cognisec-ai.cognisecai-agentic-x.workers.dev](https://cognisec-ai.cognisecai-agentic-x.workers.dev)
**Backend API Documentation:** [https://103.102.46.56.sslip.io/docs](https://103.102.46.56.sslip.io/docs)

---

## Table of Contents

- [1. Project Title](#1-project-title)
- [2. Institution](#2-institution)
- [3. Project Overview](#3-project-overview)
- [4. Problem Statement](#4-problem-statement)
- [5. Project Objectives](#5-project-objectives)
- [6. Key Features](#6-key-features)
- [7. System Architecture](#7-system-architecture)
- [8. Zero Trust Security Architecture](#8-zero-trust-security-architecture)
- [9. Behavioral Authentication Mechanism](#9-behavioral-authentication-mechanism)
- [10. Risk-Based Authentication and Step-Up Verification](#10-risk-based-authentication-and-step-up-verification)
- [11. Machine Learning and Anomaly Detection](#11-machine-learning-and-anomaly-detection)
- [12. AI-Powered Security Analysis (Agentic Layer)](#12-ai-powered-security-analysis-agentic-layer)
- [13. OTP and Email Verification](#13-otp-and-email-verification)
- [14. Application Portals](#14-application-portals)
  - [14.1 E-Commerce Portal (Nyraa Luxe Retail)](#141-e-commerce-portal-nyraa-luxe-retail)
  - [14.2 College Examination Portal (BITS Pilani)](#142-college-examination-portal-bits-pilani)
  - [14.3 Healthcare Portal (AyuSync MedCare Network)](#143-healthcare-portal-ayusync-medcare-network)
  - [14.4 SOC Command Center & Admin Portal](#144-soc-command-center--admin-portal)
- [15. Technology Stack](#15-technology-stack)
- [16. Frontend Architecture](#16-frontend-architecture)
- [17. Backend Architecture](#17-backend-architecture)
- [18. Database Design and Integration](#18-database-design-and-integration)
- [19. API Structure](#19-api-structure)
- [20. Project Directory Structure](#20-project-directory-structure)
- [21. Installation and Setup Instructions](#21-installation-and-setup-instructions)
- [22. Environment Variable Configuration](#22-environment-variable-configuration)
- [23. Running the Application Locally](#23-running-the-application-locally)
- [24. Production Deployment Architecture](#24-production-deployment-architecture)
- [25. Security Considerations](#25-security-considerations)
- [26. Testing and Verification](#26-testing-and-verification)
- [27. Research Publication and Conference Details](#27-research-publication-and-conference-details)
- [28. Future Enhancements](#28-future-enhancements)
- [29. Contributors and Project Team](#29-contributors-and-project-team)
- [30. Acknowledgements](#30-acknowledgements)

---

## 1. Project Title

**COGNISEC-AI: Agentic Cognitive Zero Trust Identity Protection System**

---

## 2. Institution

**Sai Vidya Institute of Technology (SVIT)**
Rajanukunte, Doddaballapur Main Road, Bengaluru, Karnataka 560064
Affiliated to Visvesvaraya Technological University (VTU), Belagavi
Approved by AICTE, New Delhi | Accredited by NBA & NAAC

---

## 3. Project Overview

COGNISEC-AI is an end-to-end continuous identity protection and risk mitigation platform engineered to enforce Zero Trust principles across web-based institutional and enterprise applications. Rather than relying solely on static perimeter authentication (such as username, password, or initial MFA at login), COGNISEC-AI passively monitors continuous user interaction dynamics—including keystroke rhythms, cursor acceleration vectors, and navigational entropy.

The platform processes this telemetry through online statistical algorithms (Welford's algorithm) and unsupervised machine learning models (Isolation Forest) to detect session hijacking, credential stuffing, and bot impersonation in real time. Elevated risks trigger adaptive, friction-appropriate challenges—including out-of-band email OTP, NeuralTrace gesture verification, and multi-factor re-authentication—or execute automated session revocation. An integrated Agentic AI layer powered by Google Gemini coordinates security context aggregation, risk advisory reasoning, and Security Operations Center (SOC) incident generation under a deterministic security arbiter.

---

## 4. Problem Statement

Traditional perimeter-based authentication architectures suffer from critical structural weaknesses:

1. **The Static Login Fallacy:** Conventional authentication validates identity exclusively at the initial perimeter gate. Once authenticated, the session cookie or token is trusted unconditionally until expiration, leaving the session vulnerable to cookie theft, session hijacking, or unauthorized physical handover.
2. **Credential Vulnerability & Exploitation:** Stolen credentials, automated credential stuffing, and phishing remain primary entry vectors. Multi-Factor Authentication (MFA) prompts at login disrupt user workflows yet fail to detect an adversary operating post-authentication.
3. **Privacy Invasiveness in Monitoring:** Conventional behavioral monitoring often captures keylogged strings or desktop activity, creating compliance and privacy risks under modern data protection regulations (such as GDPR and the DPDP Act).
4. **Disjointed Multi-Application Security:** Academic institutions, healthcare networks, and enterprise portals maintain fragmented authentication silos with no unified risk propagation across sensitive resource tiers.

---

## 5. Project Objectives

- **Implement Continuous Authentication:** Maintain continuous verification of identity throughout active user sessions without requiring repetitive manual credentials.
- **Privacy-Preserving Telemetry Collection:** Capture mathematical interaction characteristics (flight times, dwell times, cursor velocity) without ever capturing keystroke content, input characters, or sensitive user entries.
- **Online Profile Adaptation:** Standardize user behavior against personal statistical baselines using Welford's algorithm with anti-poisoning guards.
- **Unsupervised Anomaly Detection:** Deploy per-user Scikit-Learn Isolation Forest models that score deviations in real time without requiring labeled malicious datasets.
- **Dynamic Risk-Driven Policy Enforcement:** Formulate multi-tiered risk scores ($[0.0, 1.0]$) that map directly to automated policy responses (`ALLOW`, `STEP_UP_REQUIRED`, `TERMINATE`).
- **Autonomous SOC Orchestration:** Coordinate specialized AI agents via Google Gemini to summarize security context, evaluate threat patterns, and draft incident containment plans while keeping final decision authority with deterministic policy engines.
- **Real-World Domain Protection:** Protect three sensitive simulated portals:
  - Higher Education: Anti-proxy college examination vaults.
  - E-Commerce: High-value checkout fraud mitigation.
  - Healthcare: Electronic Health Record (EHR) privacy and doctor consultation gating.

---

## 6. Key Features

- **10-Dimensional Behavioral Biometric Pipeline:** Passive capture of typing dynamics, mouse physics, scroll velocities, and navigational entropy.
- **Zero-Storage of Raw Credentials:** Passwords hashed with salted Bcrypt; telemetry strictly isolated from input content.
- **Per-User Isolation Forest:** Tailored machine learning estimators with feature standardization and sigma floors to prevent false alarms.
- **Continuous Observation Phase:** Configurable 20-second active observation window upon login to assess behavioral baseline before granting elevated vault clearances.
- **Out-of-Band Multi-Factor Step-Up:** Cryptographic OTP delivery via Gmail SMTP over TLS (Port 587) with rate limiting and attempt-bounding.
- **NeuralTrace Gesture Verification:** Visual kinetic pattern challenge for step-up verification under intermediate risk conditions.
- **Deterministic Security Arbiter:** Guarantees that AI-generated advisory recommendations cannot override deterministic mathematical risk ceilings or security locks.
- **Real-Time SOC Command Center:** Interactive dashboard featuring live radar graphs, active session inventories, audit logs, and an on-demand attack simulation engine.
- **Automated Session Kill-Switch:** Rapid session invalidation, cookie clearing, and audit event logging upon critical risk detection ($R \ge 0.85$).

---

## 7. System Architecture

```mermaid
flowchart TD
    subgraph ClientLayer ["Client Layer (Web Portals)"]
        UI["Protected Web Client<br/>(College / Retail / Healthcare / SOC)"]
        TELEMETRY["CogniSec Behavioral Engine<br/>(Passive Biometric Listeners)"]
    end

    subgraph CDNLayer ["Edge Infrastructure"]
        CF["Cloudflare Edge CDN<br/>(Global Static Distribution)"]
    end

    subgraph BackendLayer ["Application Layer (Kamatera VPS)"]
        NGINX["Nginx Reverse Proxy<br/>(SSL Termination & Rate Limiting)"]
        API["FastAPI Application Server<br/>(Uvicorn Single-Worker Process)"]

        subgraph CoreEngines ["Core Processing Engines"]
            AUTH["Auth & Session Service<br/>(JWT & Bcrypt)"]
            RISK["Dynamic Risk Engine<br/>(Welford Baselines)"]
            ML["Model Manager<br/>(Isolation Forest Estimators)"]
            STEPUP["Step-Up Verification<br/>(OTP & NeuralTrace)"]
            AGENTS["Agentic AI Orchestrator<br/>(5 Specialized Agents)"]
        end
    end

    subgraph DataExternal ["Persistence & External Services"]
        NEON[("Neon PostgreSQL<br/>(Serverless Production Database)")]
        GEMINI["Google Gemini API<br/>(Advisory Threat Reasoning)"]
        SMTP["Gmail SMTP Server<br/>(Port 587 STARTTLS)"]
    end

    UI -->|"HTTPS Static Assets"| CF
    UI -->|"Telemetry Events & API Calls"| NGINX
    TELEMETRY -->|"Interaction Feature Vectors"| NGINX
    NGINX -->|"HTTP Proxy"| API
    API --> AUTH
    API --> RISK
    API --> ML
    API --> STEPUP
    API --> AGENTS
    AUTH --> NEON
    RISK --> NEON
    STEPUP --> SMTP
    AGENTS --> GEMINI
    API --> NEON
```

---

## 8. Zero Trust Security Architecture

COGNISEC-AI adheres strictly to the core Zero Trust tenet: **"Never Trust, Always Verify."**

```mermaid
flowchart LR
    A["Continuous User Interaction"] --> B{"Risk Evaluation Engine"}
    B -->|"Risk < 0.30 (LOW)"| C["ALLOW<br/>(Full Access Maintained)"]
    B -->|"0.30 <= Risk < 0.65 (MEDIUM)"| D["EVALUATE CONTEXT<br/>(Vault Access Gated)"]
    B -->|"0.65 <= Risk < 0.85 (HIGH)"| E["STEP_UP_REQUIRED<br/>(Mandatory OTP / NeuralTrace)"]
    B -->|"Risk >= 0.85 (CRITICAL)"| F["TERMINATE<br/>(Session Revocation & Kill Switch)"]
    E -->|"Successful Verification"| G["Risk Dampened to 0.05"]
    E -->|"Failed Challenge"| F
```

### Zero Trust Principles Enforced:
1. **Explicit Identity Verification:** Every API call validates JWT session validity, account state, and client IP/User-Agent consistency.
2. **Least Privilege Resource Access:** Sensitive resource vaults (College Exam Paper, High-Value Payment Gateway, Doctor Consultation Notes) require explicit application grants (`application_grants` table).
3. **Continuous Re-Assessment:** Telemetry is submitted in rolling batches; anomaly scores dynamically modulate session risk between requests.
4. **Assume Breach:** Compromised credentials trigger immediate elevation as behavioral vectors deviate from established legitimate owner baselines.

---

## 9. Behavioral Authentication Mechanism

The client-side telemetry engine ([`cognisec-client.js`](cognisec-client.js)) passively measures interaction physics without intercepting keystroke character values:

| # | Telemetry Feature Key | Description | Measurement Unit |
| :---: | :--- | :--- | :--- |
| **1** | `typing_speed_wpm` | Normalized typing velocity calculated across timing intervals | Words Per Minute (WPM) |
| **2** | `avg_flight_time_ms` | Mean duration between releasing key $N$ and pressing key $N+1$ | Milliseconds (ms) |
| **3** | `avg_dwell_time_ms` | Mean duration a single key is held in depressed state | Milliseconds (ms) |
| **4** | `mouse_velocity_avg` | Mean euclidean cursor displacement per unit time | Pixels / Second (px/s) |
| **5** | `mouse_acceleration_avg` | Second derivative of cursor position across sampling intervals | $\text{px/s}^2$ |
| **6** | `mouse_curvature_entropy`| Angular deviation and trajectory smoothness of cursor arcs | Mathematical Entropy ($[0, 5]$) |
| **7** | `click_frequency` | Aggregate pointer down/up events relative to active session time | Clicks / Second |
| **8** | `scroll_speed_avg` | Wheel and touch-scroll delta movement over active scrolling windows | Pixels / Second (px/s) |
| **9** | `idle_duration_sec` | Continuous period of user inactivity within an active session | Seconds |
| **10**| `navigation_entropy` | Variety and pattern complexity across DOM element focus transitions | Entropy metric ($[0, 5]$) |

---

## 10. Risk-Based Authentication and Step-Up Verification

### Continuous Scoring Formula
Session risk $R_{\text{total}} \in [0.0, 1.0]$ is computed as a weighted composition:

$$R_{\text{total}} = w_{\text{ml}} \cdot S_{\text{anomaly}} + w_{\text{dev}} \cdot S_{\text{device}} + w_{\text{geo}} \cdot S_{\text{context}} + w_{\text{fails}} \cdot S_{\text{penalties}}$$

- $S_{\text{anomaly}}$: Calibrated Isolation Forest deviation score.
- $S_{\text{device}}$: Device trust deficit ($0.0$ if trusted, $0.5$ if unrecognized).
- $S_{\text{context}}$: Temporal and geographic anomalies.
- $S_{\text{penalties}}$: Failed challenge and rate-limiting penalties.

### Action Thresholds (Configured in Backend Settings)
- **$R_{\text{total}} < 0.30$ (`LOW`):** Action `ALLOW`. Continuous access permitted without interruption.
- **$0.30 \le R_{\text{total}} < 0.65$ (`MEDIUM`):** Context evaluation active; sensitive vault operations restricted until observation is completed.
- **$0.65 \le R_{\text{total}} < 0.85$ (`HIGH`):** Action `STEP_UP_REQUIRED`. Mandatory secondary challenge (Email OTP or NeuralTrace) required to continue.
- **$R_{\text{total}} \ge 0.85$ (`CRITICAL`):** Action `TERMINATE`. Immediate session invalidation, account ejection, and audit alert dispatched.

```mermaid
sequenceDiagram
    autonumber
    actor User as User Browser
    participant API as FastAPI Backend
    participant Risk as Risk Service
    participant Mail as Gmail SMTP
    participant DB as Neon PostgreSQL

    User->>API: User interaction (typing, moving cursor)
    User->>API: POST /api/behavior/events (10D Vector)
    API->>Risk: Evaluate Vector against Baseline
    Risk-->>API: Risk = 0.68 (HIGH - Step-Up Required)
    User->>API: POST /api/security/vault/college_exam
    API-->>User: 403 Forbidden (STEP_UP_REQUIRED, Challenge Issued)
    User->>API: POST /api/security/exam-otp/request
    API->>Mail: Dispatch 6-digit OTP (Port 587 STARTTLS)
    Mail-->>User: Delivery to user's registered inbox
    User->>API: POST /api/security/exam-otp/verify { "otp": "..." }
    API->>DB: Record Application Grant (10 min expiry)
    API-->>User: 200 OK (Grant Token Generated)
    User->>API: POST /api/security/vault/college_exam (With Grant)
    API-->>User: 200 OK (Exam Paper Vault Decrypted)
```

---

## 11. Machine Learning and Anomaly Detection

### Unsupervised Isolation Forest
- **Framework:** `scikit-learn` (`sklearn.ensemble.IsolationForest`).
- **Architecture:** Per-user model instances managed by [`ModelManager`](backend/app/ml/model_manager.py).
- **Hyperparameters:** `n_estimators=100`, `contamination=0.05`, `random_state=42`, `n_jobs=1` (configured for single-worker execution).
- **Computational Profile:** Single-vector scoring operates with lightweight CPU overhead; model fitting is bounded to per-user historical vectors without requiring large-scale distributed training.

### Welford Incremental Profiling
To accommodate evolving user styles without massive historical storage, COGNISEC-AI implements Welford's algorithm to compute rolling running means ($\mu_k$) and sample variances ($s_k^2$) in $\mathcal{O}(1)$ space and time:

$$M_{k} = M_{k-1} + (x_k - \mu_{k-1}) \cdot (x_k - \mu_k)$$

### Anti-Poisoning & Cold-Start Guards
- **Cold-Start Phase ($N < 5$ samples):** Anomaly scores are dampened to prevent false positives while initial baseline forms.
- **Training Eligibility ($N \ge 25$ samples):** Model training executes only when sufficient legitimate baseline observations exist.
- **Baseline Quarantine:** Samples recorded during anomalous or failed states are quarantined to prevent adversarial baseline poisoning.

---

## 12. AI-Powered Security Analysis (Agentic Layer)

COGNISEC-AI incorporates a multi-agent analytical pipeline coordinated by [`SecurityOrchestrator`](backend/app/agents/execution/orchestrator.py):

```mermaid
flowchart TD
    EVENT["Security Event / High-Risk Signal"] --> ORCH["Security Orchestrator"]
    ORCH --> AG1["1. Security Context Agent<br/>(Aggregates Historical Telemetry & IP Intel)"]
    AG1 --> AG2["2. Risk Analysis Agent<br/>(Evaluates Anomaly Vectors via Gemini LLM)"]
    AG2 --> AG3["3. Adaptive Auth Agent<br/>(Recommends Challenge Type & Challenge Strictness)"]
    AG3 --> AG4["4. Security Response Agent<br/>(Formulates Quarantine & Session Actions)"]
    AG4 --> AG5["5. SOC Monitoring Agent<br/>(Generates Human-Readable SOC Alerts)"]
    AG5 --> ARBITER{"Deterministic Security Arbiter"}
    ARBITER -->|"Validates against Policy Rules"| FINAL["Final Action Executed"]
```

### Specialized Agents:
1. **Security Context Agent:** Gathers historical device fingerprints, location shifts, and prior incidents.
2. **Risk Analysis Agent:** Evaluates raw behavioral vector deviations and outputs structured threat reasoning.
3. **Adaptive Auth Agent:** Selects the most appropriate step-up challenge (Email OTP, NeuralTrace, Biometric Re-entry).
4. **Security Response Agent:** Outlines graduated containment recommendations.
5. **SOC Monitoring Agent:** Synthesizes technical incident narratives for security analysts.

> **Deterministic Security Boundary:**
> The `DeterministicSecurityArbiter` enforces strict fail-secure constraints. AI agent recommendations are strictly advisory and can **never** lower a mathematical risk score, dismiss an active lock, or bypass deterministic policy rules.

---

## 13. OTP and Email Verification

- **Delivery Protocol:** Google SMTP (`smtp.gmail.com`) using port **587** with `STARTTLS`.
- **Security Design:**
  - 6-digit cryptographically generated numeric tokens (`secrets.randbelow`).
  - Strict 5-minute time-to-live (`expires_at`).
  - Rate limiting with cooldown periods on retry requests.
  - One-time consumption: Invalidated immediately upon verification.
  - Attempt-bounding: Session locked if 3 consecutive invalid attempts are entered.
  - Privacy masking: Recipient email masked in all system logs (`u***e@domain.com`).

---

## 14. Application Portals

COGNISEC-AI provides three protected enterprise/institutional portals and one administrative command portal:

### 14.1 E-Commerce Portal (Nyraa Luxe Retail)
- **Path:** `/shopping.html`
- **Security Features:**
  - Passive behavioral monitoring on item selection and cart operations.
  - Step-up OTP payment verification for transactions exceeding ₹5,000.
  - Frictionless background checkout for consistent behavioral scores.

### 14.2 College Examination Portal (BITS Pilani)
- **Path:** `/college.html`
- **Security Features:**
  - DigiLocker Aadhaar gating and student ID matching.
  - Continuous behavioral observation window (20 seconds) prior to question paper decryption.
  - Out-of-band exam access OTP.
  - Automatic portal ejection and exam paper lock if proxy typing or impersonation is detected.

### 14.3 Healthcare Portal (AyuSync MedCare Network)
- **Path:** `/healthcare.html`
- **Security Features:**
  - Clinical role-based access control (Doctor, Medical Staff, Patient).
  - Protected Electronic Health Records (EHR) consultation vault.
  - Verification challenge before booking confirmations and patient history access.

### 14.4 SOC Command Center & Admin Portal
- **Path:** `/index.html` (Accessible via Admin credentials)
- **Security Features:**
  - Real-time Threat Radar charting aggregate organizational risk.
  - Active session monitoring with administrative session termination.
  - Attack Simulator: Evaluates system defenses against simulated impossible travel, erratic mouse curves, and robotic key speeds.
  - Audit timeline with full event logging.

---

## 15. Technology Stack

### Backend
- **Language:** Python 3.12.3
- **Web Framework:** FastAPI 0.110+
- **ASGI Server:** Uvicorn (Standard)
- **ORM:** SQLAlchemy 2.0+
- **Database Driver:** `psycopg-binary` / `psycopg3`

### Machine Learning & Data Processing
- **Anomaly Detection:** Scikit-Learn 1.4+ (`IsolationForest`)
- **Scientific Computing:** NumPy 1.26+, Pandas 2.2+, SciPy 1.18+
- **Online Statistics:** Custom Welford formulation with sigma floors

### Security & Authentication
- **Hashing:** Bcrypt 4.0+ / Passlib
- **Token Infrastructure:** Python-Jose (Cryptographic JWT HS256)
- **Email Delivery:** Python `smtplib` over TLS (Port 587)
- **AI Reasoning:** Google Gemini API (`gemini-2.5-flash` / `gemini-3.5-flash-lite`) via `httpx`

### Frontend
- **Interface:** HTML5, CSS3 (Cybersecurity Dark Theme), Vanilla JavaScript (ES6 Modules)
- **Graphics:** HTML5 Canvas & Three.js 3D Visual HUD
- **Telemetry Client:** Privacy-preserving asynchronous event capture ([`cognisec-client.js`](cognisec-client.js))

### Production Infrastructure
- **Server:** Kamatera Cloud VPS (1 vCPU, 1 GB RAM, 20 GB NVMe, Singapore Region)
- **Web Server & Proxy:** Nginx 1.24+ (Reverse Proxy & HTTP/2 termination)
- **SSL / TLS:** Let's Encrypt (Automated renewal via Certbot)
- **Static Hosting:** Cloudflare Workers Static Assets (Global Edge CDN)
- **Database:** Neon PostgreSQL (Singapore AWS Region)

---

## 16. Frontend Architecture

The frontend is constructed using pure vanilla web technologies to eliminate heavy framework overhead and ensure fast load times:

```mermaid
flowchart TD
    subgraph Browser ["User Browser"]
        HTML["Portal DOM Pages<br/>(index, shopping, college, healthcare)"]
        CONFIG["config.js<br/>(Dynamic API Base Resolution)"]
        CLIENT["cognisec-client.js<br/>(Telemetry & Auth State)"]
        APP["app.js<br/>(UI Controller & Modals)"]
    end

    HTML --> CONFIG
    CONFIG --> CLIENT
    CLIENT --> APP
    CLIENT -->|"Captures keyup/keydown/mousemove"| BUFFER["Internal Telemetry Buffer"]
    BUFFER -->|"Flushes every 2-5s"| BACKEND["FastAPI Backend (/api/behavior/events)"]
```

- **Dynamic Base URL Resolution:** [`config.js`](config.js) dynamically sets `window.COGNISEC_API_BASE`, routing traffic to the production VPS HTTPS endpoint with automatic protocol upgrade to prevent Mixed Content errors.
- **Asynchronous Telemetry Buffering:** Interaction events are collected in memory and transmitted in batched intervals without blocking UI operations.

---

## 17. Backend Architecture

The backend follows clean layered architecture patterns:

```
backend/app/
├── core/         # Settings, security encryption, user-agent parser
├── database/     # SQLAlchemy connection pool, base model, schema synchronization
├── models/       # ORM entity schemas (User, Device, Session, Event, Alert, OTP, etc.)
├── schemas/      # Pydantic schemas for request/response validation
├── routes/       # FastAPI route controllers grouped by functional domain
├── services/     # Business logic (Auth, Risk, Email, Device, Session, Step-Up)
├── ml/           # Feature engineering, Welford profiler, Isolation Forest engine
└── agents/       # Multi-agent orchestrator, Gemini client, deterministic arbiter
```

---

## 18. Database Design and Integration

The database layer utilizes **Neon PostgreSQL** (AWS Asia Pacific 1 - Singapore) with connection pooling and relational integrity:

```mermaid
erDiagram
    USERS ||--o{ SESSIONS : "owns"
    USERS ||--o{ DEVICES : "registers"
    USERS ||--o{ SECURITY_EVENTS : "generates"
    USERS ||--o{ OTP_CHALLENGES : "receives"
    USERS ||--o{ APPLICATION_GRANTS : "holds"
    SESSIONS ||--o{ APPLICATION_GRANTS : "scopes"
    SECURITY_EVENTS ||--o{ ALERTS : "triggers"

    USERS {
        int id PK
        string email UK
        string name
        string password_hash
        string role
        string account_status
        timestamp created_at
    }

    SESSIONS {
        string id PK
        int user_id FK
        string state
        float risk_score
        string ip_address
        timestamp expires_at
        timestamp created_at
    }

    DEVICES {
        int id PK
        int user_id FK
        string device_id
        string browser_name
        string os_name
        string trust_state
        boolean is_trusted
    }

    OTP_CHALLENGES {
        int id PK
        string challenge_id UK
        int user_id FK
        string session_id
        string challenge_type
        string status
        timestamp expires_at
    }

    APPLICATION_GRANTS {
        int id PK
        string session_id FK
        int user_id FK
        string application
        string resource
        timestamp expires_at
        boolean revoked
    }
```

---

## 19. API Structure

All API endpoints are prefixed with `/api` and documented via OpenAPI:

| Route Path | Method | Description | Access Level |
| :--- | :---: | :--- | :--- |
| `/health` | `GET` | Health verification, DB connection test & engine state | Public |
| `/api/auth/register` | `POST` | User registration with input validation | Public |
| `/api/auth/login` | `POST` | Primary authentication, password check & JWT issue | Public |
| `/api/auth/me` | `GET` | Retrieve authenticated profile and active session context | Authenticated |
| `/api/auth/login-otp/request` | `POST` | Request out-of-band email OTP for login verification | Public / Authenticated |
| `/api/auth/login-otp/verify` | `POST` | Verify 6-digit login OTP code | Public / Authenticated |
| `/api/behavior/events` | `POST` | Ingest 10-dimensional passive behavioral telemetry vector | Authenticated |
| `/api/security/status/{session_id}` | `GET` | Retrieve real-time dynamic risk score & session policy | Authenticated |
| `/api/security/step-up/challenge` | `POST` | Initiate adaptive step-up challenge | Authenticated |
| `/api/security/step-up/verify` | `POST` | Complete step-up challenge and dampen session risk | Authenticated |
| `/api/security/vault/{resource}` | `GET` | Decrypt and access protected resource vault | Granted Session |
| `/api/admin/dashboard` | `GET` | Aggregated SOC statistics, threat radar & system metrics | Admin Only |
| `/api/admin/sessions` | `GET` | Active session inventory across all portals | Admin Only |
| `/api/admin/sessions/{id}/terminate`| `POST` | Administrative kill-switch session revocation | Admin Only |
| `/api/admin/simulator/attack` | `POST` | Execute controlled security attack simulation | Admin Only |
| `/api/healthcare/departments` | `GET` | Retrieve clinical departments catalog | Public / User |
| `/api/healthcare/doctors` | `GET` | Retrieve available doctors and schedule slots | Public / User |

---

## 20. Project Directory Structure

```
cognisec-ai/
├── README.md                           # Main Institutional & Technical Documentation
├── index.html                          # SOC Command Center & Main Platform Landing
├── college.html                        # BITS Pilani Examination Portal
├── shopping.html                       # Nyraa Luxe Retail E-Commerce Portal
├── healthcare.html                     # AyuSync MedCare Network Healthcare Portal
├── app.js                              # Frontend UI Event Handlers & View Controllers
├── cognisec-client.js                  # Client Behavioral Telemetry Collection Engine
├── config.js                           # Dynamic Backend API Base URL Resolver
├── styles.css                          # Cybersecurity Dark Theme Stylesheet
├── frames/                             # NeuralTrace Visual Kinetic Challenge Frames
│   ├── robot/
│   ├── seq1/
│   └── seq3/
├── backend/
│   ├── requirements.txt                # Python Production Dependencies
│   ├── .env.example                    # Sample Environment Configuration Template
│   ├── app/
│   │   ├── main.py                     # FastAPI Application Initialization & Routers
│   │   ├── core/                       # Security, Configuration, User Agent Parsers
│   │   ├── database/                   # Engine, Base, Non-Destructive Schema Sync
│   │   ├── models/                     # SQLAlchemy Database Entity Models
│   │   ├── schemas/                    # Pydantic Schemas for Request/Response
│   │   ├── routes/                     # Domain-Specific API Route Controllers
│   │   ├── services/                   # Business Services (Auth, Risk, Email, Session)
│   │   ├── ml/                         # Welford Profiling, Isolation Forest Engine
│   │   └── agents/                     # Multi-Agent Orchestrator, Gemini LLM Client
│   └── tests/                          # Automated Unit & Integration Tests
└── .gitignore                          # Excludes secrets, virtual environments & logs
```

---

## 21. Installation and Setup Instructions

### Prerequisites
- Python 3.12+ (with `venv` and `pip`)
- Node.js 18+ (optional, for static file linting)
- PostgreSQL database (or local SQLite fallback)

### Step 1: Clone the Repository
```bash
git clone https://github.com/Boomika181/COGNISEC-AI.git
cd COGNISEC-AI
```

### Step 2: Set Up Backend Virtual Environment
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 22. Environment Variable Configuration

Create a `.env` file in the `backend/` directory based on the example:

```bash
cp .env.example .env
```

Configure your `.env` with appropriate values:

```ini
PROJECT_NAME="COGNISEC-AI"
ENVIRONMENT="development"
API_V1_STR="/api"

# Cryptographic Keys (Use: openssl rand -hex 32)
SECRET_KEY="your-strong-random-secret-key-here"
BOOTSTRAP_ADMIN_KEY="your-strong-bootstrap-key-here"
ALGORITHM="HS256"
ACCESS_TOKEN_EXPIRE_MINUTES=1440

# Database Connection (Neon PostgreSQL or SQLite)
DATABASE_URL="postgresql://user:password@host/neondb?sslmode=require"
# SQLite alternative for offline testing:
# DATABASE_URL="sqlite:///./cognisec.db"

# CORS Configuration (Explicit origins, NO wildcards with credentials)
CORS_ORIGINS=["http://localhost:5500","http://127.0.0.1:5500","http://localhost:8000"]

# Real Email Delivery via Gmail SMTP (STARTTLS on port 587)
SMTP_HOST="smtp.gmail.com"
SMTP_PORT=587
SMTP_USER="your-email@gmail.com"
SMTP_PASSWORD="your-16-character-google-app-password"
SMTP_FROM="your-email@gmail.com"
SMTP_FROM_NAME="COGNISEC-AI Security"
SMTP_TLS=true
SMTP_TIMEOUT_SECONDS=15
SMTP_ENABLED=true

# AI / Gemini Configuration
LLM_PROVIDER="mock"                  # "gemini" for cloud API, "mock" for offline deterministic
GEMINI_MODEL="gemini-2.5-flash"
GEMINI_API_KEY=""                    # Your Google Gemini API Key
AGENTIC_AI_ENABLED=true
AGENT_EXECUTION_TIMEOUT_SECONDS=0.8
```

> [!WARNING]
> Never commit `.env` containing real database passwords, Google App Passwords, or Gemini API keys to GitHub.

---

## 23. Running the Application Locally

### 1. Start the Backend API Server
```bash
cd backend
source venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
The API documentation will be available at:
- Swagger UI: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- Health Endpoint: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

### 2. Start the Frontend Web Server
In a separate terminal window from the project root:
```bash
python3 -m http.server 5500
```

### 3. Open Portals in Your Browser
- **Main / SOC Portal:** [http://localhost:5500/index.html](http://localhost:5500/index.html)
- **College Exam Portal:** [http://localhost:5500/college.html](http://localhost:5500/college.html)
- **E-Commerce Portal:** [http://localhost:5500/shopping.html](http://localhost:5500/shopping.html)
- **Healthcare Portal:** [http://localhost:5500/healthcare.html](http://localhost:5500/healthcare.html)

---

## 24. Production Deployment Architecture

COGNISEC-AI is deployed in a dedicated cloud architecture combining a Singapore-based virtual server with global edge static distribution:

| Layer | Host / Provider | Specification | Role |
| :--- | :--- | :--- | :--- |
| **Edge CDN (Frontend)** | Cloudflare Workers | Global Edge V8 Isolates | Distributes static HTML/JS/CSS assets with HTTP/2 and edge caching. |
| **Backend VPS** | Kamatera Cloud (Singapore) | 1 vCPU, 1 GB RAM, 20 GB NVMe | Executes FastAPI, scikit-learn models, and background security orchestrators. |
| **Reverse Proxy** | Nginx 1.24 (Ubuntu 24.04 LTS) | SSL Termination via Let's Encrypt | Proxies `/api/` to local Uvicorn; enforces UFW firewall isolation. |
| **Application Server** | Uvicorn (managed by `systemd`) | Single asynchronous worker (`--workers 1`)| Maintains in-memory OTP dictionaries and per-user Isolation Forest instances. |
| **Database** | Neon Serverless PostgreSQL | AWS Singapore Region | Stores users, devices, sessions, grants, audit logs, and appointments. |
| **SMTP Delivery** | Google Mail MTA | Port 587 (TLS Handshake) | Transmits cryptographic 6-digit OTP verification codes. |

---

## 25. Security Considerations

- **Single-Worker Concurrency:** Uvicorn runs with `--workers 1` to ensure process-local memory consistency for active OTP challenges ([`StepUpService`](backend/app/services/step_up_service.py)) and cached Isolation Forest models without race conditions.
- **Fail-Secure Architecture:** If external network calls to Gemini or SMTP time out, the system defaults to strict deterministic security policies.
- **Memory Optimization & Virtual Memory:** Baseline application import consumes approximately 253 MB RSS on a 1 GB RAM VPS. A 2.0 GB NVMe swap file (`swappiness=10`) provides supplementary virtual memory to handle transient memory bursts during operations such as model fitting. However, swap does not eliminate the risk of out-of-memory errors under sustained high concurrency, which is managed by bounding worker concurrency (`--workers 1`).
- **Strict CORS Origin Isolation:** Production rejects wildcard (`*`) origins and permits only the explicit Cloudflare frontend origin and local testing hosts.

---

## 26. Testing and Verification

**867 tests collected across 38 test suites** (measured via test collection inventory). These test suites cover authentication, session lifecycle, machine learning baselines, risk scoring policies, and multi-agent coordination:

```bash
# Verify test collection inventory
pytest --collect-only -q

# Run automated tests
pytest -v
```

### Verified Test Scope:
- **`test_behavioral_pipeline_audit.py`:** Tests feature vector bounds and sigma floors.
- **`test_mandatory_enrollment_flow.py`:** Tests factor enrollment and access gating.
- **`test_healthcare_lockout_and_dev_reset.py`:** Tests lockout triggers upon three consecutive failures.
- **`test_step5_8_1_live_orchestration.py`:** Tests end-to-end multi-agent execution pipeline.
- **`test_deployment_readiness.py`:** Tests CORS, dynamic API base resolution, and health probes.

---

## 27. Research Publication and Conference Details

- **Conference:** International Conference on Sustainable Engineering and Management (ICSEM 2026)
- **Conference Dates:** 2nd and 3rd December 2026
- **Conference Venue:** Visvesvaraya Technological University (VTU), Centre for Postgraduate Studies (CPGS), Bengaluru, Karnataka, India
- **Paper Status:** Accepted

---

## 28. Future Enhancements

- **Federated Behavioral Learning:** Implement federated model aggregation across distributed enterprise nodes without centralizing raw behavioral telemetry.
- **FIDO2 / WebAuthn Integration:** Add hardware security key support (YubiKey) as a complementary biometric step-up factor.
- **eBPF Kernel-Level Telemetry:** Extend telemetry from user-space browser interactions to kernel-level socket and process execution tracking.
- **Mobile Sensor Telemetry:** Expand client listeners to capture touchscreen gyroscope, accelerometer, and swipe pressure metrics on mobile operating systems.

---

## 29. Contributors and Project Team

**Project Lead & Developer:**
- **Boomika Ram**
  Department of Computer Science and Engineering
  Sai Vidya Institute of Technology, Bengaluru
  GitHub: [@Boomika181](https://github.com/Boomika181)

**Major Project Batch:** 2022 – 2026
**Degree:** Bachelor of Engineering (B.E.) in Computer Science and Engineering

---

## 30. Acknowledgements

We express our sincere gratitude to:
- **The Management and Leadership of Sai Vidya Institute of Technology (SVIT)** for providing research facilities and cloud computing infrastructure.
- **Department of Computer Science and Engineering** faculty members and project coordinators for their technical guidance, architectural review, and continuous support.
- **Visvesvaraya Technological University (VTU)** for academic curriculum frameworks fostering practical research in cybersecurity and artificial intelligence.
- **Open-source communities** behind FastAPI, Scikit-Learn, SQLAlchemy, Cloudflare, and Neon for empowering modern zero-trust security research.
