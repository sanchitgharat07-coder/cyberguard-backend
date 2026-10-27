# CyberGuard AI — Backend

A research-oriented backend for **CyberGuard AI**, a multi-layer system for detecting potentially malicious URLs and supporting phishing analysis. The backend combines machine-learning-based URL assessment, threat-intelligence lookups, deeper forensic checks, and real-time communication for connected clients.

> **Research / safety notice:** CyberGuard AI is a decision-support tool, not a guarantee that a URL is safe or malicious. Detection results can be wrong or incomplete. Do not use this project as the sole security control for sensitive systems.

## Contents

- [Overview](#overview)
- [Detection architecture](#detection-architecture)
- [Technology stack](#technology-stack)
- [Repository structure](#repository-structure)
- [Getting started](#getting-started)
- [Configuration](#configuration)
- [HTTP endpoints](#http-endpoints)
- [Real-time communication](#real-time-communication)
- [Model evaluation](#model-evaluation)
- [Security and operational notes](#security-and-operational-notes)
- [Contributing](#contributing)
- [License](#license)

## Overview

CyberGuard AI uses a **cascaded detection approach**: lightweight checks can handle straightforward cases, while uncertain or suspicious cases can be escalated for additional analysis. The repository includes model-loading and training utilities, threat-intelligence modules, forensic-analysis code, Firebase integration, background synchronization, task-queue support, and Socket.IO event handling.

### Goals

- Assess URLs for phishing-related signals.
- Combine model predictions with threat-intelligence evidence.
- Support deeper investigation when a URL needs additional scrutiny.
- Keep threat-intelligence lists synchronized in the background.
- Communicate with client applications through real-time events.
- Expose basic HTTP endpoints, including service health and curated cybersecurity news.

## Detection architecture

```text
Client application
       |
       v
Flask + Socket.IO backend
       |
       +--> Tier 1: Machine-learning URL assessment
       |       - Loads the configured phishing model
       |       - Uses configured decision thresholds
       |
       +--> Tier 2: Threat intelligence
       |       - Local blacklist / threat-list checks
       |       - Background list synchronization
       |
       +--> Tier 3: Deeper forensic checks
       |       - Additional URL/domain investigation
       |
       +--> Supporting services
               - Firebase integration
               - Background task queue
               - Real-time socket events
               - Cybersecurity news feed
```

The exact execution path and escalation behavior are implemented in the application modules. Review the current code and model configuration before changing thresholds or describing results as production guarantees.

## Technology stack

- **Python**
- **Flask** for HTTP routes
- **Flask-CORS** for cross-origin request handling
- **Flask-SocketIO** for real-time client communication
- **scikit-learn / model dependencies** as specified in `requirements.txt`
- **Firebase** integration for persistence or threat-list support
- **Requests** and **feedparser** for external HTTP/RSS data
- **Pickle (`.pkl`)** files for serialized model artifacts

See [`requirements.txt`](requirements.txt) for the repository's dependency list.

## Repository structure

```text
cyberguard-backend/
├── app.py                    # Flask application and service initialization
├── config.py                 # Detection thresholds and runtime configuration
├── graph.py                  # Graph-related utilities
├── model_trainer.py           # Model training utilities
├── offline_evaluation.py      # Offline evaluation workflow
├── phistank.py                # PhishTank-related utility/module
├── requirements.txt           # Python dependencies
├── test_client.py             # Client/testing utility
├── tier3_live_eval.py         # Tier 3 live evaluation utility
├── phishing_model.pkl         # Serialized model artifact
├── phishing_model_v2.pkl      # Serialized model artifact
├── phishing_model_v3.pkl      # Serialized model artifact
├── roc_curve.png              # ROC visualization
├── roc_curve.pdf              # ROC visualization (PDF)
├── database/
│   └── ...                    # Firebase/database integration
├── sockets/
│   └── ...                    # Socket.IO setup and event handlers
├── tier1_ml/
│   └── ...                    # Model loading and Tier 1 assessment
├── tier2_intel/
│   └── ...                    # Threat-intelligence lists and sync
├── tier3_forensics/
│   └── ...                    # Deeper forensic checks
├── utils/
│   └── ...                    # Shared helpers
└── workers/
    └── ...                    # Background task queue
```

## Getting started

### 1. Prerequisites

- Python version compatible with the dependencies in `requirements.txt`
- Git
- Firebase credentials/configuration if required by your deployment
- Network access for external threat-intelligence or RSS sources used by enabled modules

### 2. Clone the repository

```bash
git clone https://github.com/sanchitgharat07-coder/cyberguard-backend.git
cd cyberguard-backend
```

### 3. Create and activate a virtual environment

**Windows PowerShell**

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Linux / macOS**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 4. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 5. Configure credentials and environment

Review `config.py` and the Firebase initialization code under `database/`. Supply the Firebase credentials and any external-service keys using the mechanism expected by the current implementation.

**Never commit credentials, service-account JSON files, API keys, access tokens, or private environment files.** Keep local secrets out of Git and rotate any credential that has been exposed.

### 6. Start the backend

```bash
python app.py
```

The current application entry point initializes Firebase, loads the configured Tier 1 model, loads local threat-intelligence lists, starts background synchronization, initializes Socket.IO and the task queue, and then starts the service on port `5000`.

For local development, the default URL is:

```text
http://127.0.0.1:5000
```

If startup fails, check that dependencies are installed, the model path configured in `app.py` exists, Firebase configuration is valid, and required external services are reachable.

## Configuration

Detection and timeout settings are defined in `config.py`. The current configuration includes:

- `T_SAFE`: lower decision threshold
- `T_MALICIOUS`: high-risk decision threshold
- `SUSPICIOUS_TLDS`: a list of TLDs treated as suspicious signals
- `PROTECTED_BRANDS`: brand names used by relevant detection logic
- `TIER3_FETCH_TIMEOUT`: timeout for a Tier 3 fetch
- `RDAP_TIMEOUT`: timeout for RDAP-related checks

Treat these as model/application settings, not universal indicators of maliciousness. Validate changes against a representative evaluation dataset and document the resulting trade-offs.

The news cache duration can be configured through `NEWS_CACHE_TTL_SECONDS`; the application defaults it to 600 seconds when the variable is not set.

## HTTP endpoints

The following routes are defined in the current `app.py` entry point:

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/health` | Returns a basic service-health response and lists the configured detection tiers. |
| `GET` | `/news` | Returns a cached list of recent cybersecurity news items collected from configured RSS feeds. |

### Health check

```bash
curl http://127.0.0.1:5000/health
```

The response includes a service status, service name, and tier list. This is a basic process-level health check; it does not by itself prove that every dependency or detection path is functioning correctly.

### Cybersecurity news

```bash
curl http://127.0.0.1:5000/news
```

The route aggregates entries from configured cybersecurity RSS feeds and caches the result. Feed availability, content formats, and external network conditions may affect the response.

### Socket.IO events

Real-time communication is initialized through the `sockets/` package. Event names and payload schemas are defined in the socket event modules; consult those files and the matching client implementation before integrating or changing events. This README intentionally does not guess event names or payload formats.

## Model evaluation

The repository includes scripts and artifacts for model training and evaluation:

- `model_trainer.py` — model training utilities
- `offline_evaluation.py` — offline evaluation
- `tier3_live_eval.py` — Tier 3 live-evaluation utility
- `roc_curve.png` and `roc_curve.pdf` — ROC curve visualizations

Run evaluation scripts with the arguments and dataset paths expected by their source code. Before publishing metrics, document the dataset source, sample counts, class balance, train/test split, feature set, threshold selection, and evaluation date. Avoid comparing metrics from different datasets or evaluation procedures as if they were directly equivalent.

Serialized pickle models should only be loaded from trusted sources. Loading an untrusted `.pkl` file can execute arbitrary code.

## Security and operational notes

Before deploying beyond local development:

- Restrict CORS to the trusted client origins instead of allowing every origin.
- Disable Flask debug mode in production.
- Keep credentials and API keys in environment variables or a managed secrets store.
- Add authentication, authorization, request validation, and rate limiting where appropriate.
- Use explicit timeouts and controlled error responses for external requests.
- Review logging to ensure secrets and sensitive URL data are not exposed.
- Validate and sanitize any URL or domain submitted for analysis.
- Monitor third-party feed availability and Firebase connectivity.
- Pin and regularly review dependencies.
- Add automated tests for API routes, model loading, threat-list updates, and socket events.
- Do not treat a “safe” prediction as proof that a URL is harmless.

## Contributing

Contributions and issue reports are welcome. For changes to detection logic or model thresholds, include:

1. A clear description of the change.
2. The dataset and evaluation method used to validate it.
3. Relevant precision, recall, F1, ROC-AUC, and false-positive/false-negative analysis where applicable.
4. Tests or reproducible steps.
5. Any new configuration variables or setup requirements.

## License

No license information is specified in this README. Add a `LICENSE` file before explicitly granting reuse, modification, or redistribution rights.
