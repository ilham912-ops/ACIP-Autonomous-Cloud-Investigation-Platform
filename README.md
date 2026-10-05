# 🔐 Autonomous Cloud Investigation Platform (ACIP)

> **Automated Cloud Incident Investigation Platform with Machine Learning-based Anomaly Detection**

ACIP (Autonomous Cloud Investigation Platform) is a cloud security investigation platform designed to **automate the detection, analysis, and investigation of security incidents in cloud environments**.

The platform combines **cloud event collection, rule-based detection, Machine Learning, evidence management, investigation cases, and an interactive dashboard** to help security analysts reduce investigation time and improve incident analysis.

---

## 🎯 Project Objectives

The main objective of ACIP is to automate the cloud incident investigation lifecycle and reduce the workload of SOC analysts.

The platform aims to:

* 🔎 Detect suspicious cloud activities automatically
* ☁️ Analyze AWS CloudTrail and IAM events
* 🤖 Detect behavioral anomalies using Machine Learning
* 🚨 Generate standardized security findings
* 📂 Collect and preserve investigation evidence
* 🧩 Correlate security events and findings
* 📊 Provide an investigation dashboard
* 📝 Generate investigation summaries and recommendations
* ⏱️ Reduce the Mean Time To Investigate (MTTI)
* 🔐 Improve cloud security monitoring and incident response

---

## 🏗️ Architecture

The ACIP architecture is organized into several main components:

```text
                    ┌─────────────────────┐
                    │   Cloud Environment │
                    │      AWS Events     │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │      CloudTrail     │
                    │   Event Collection  │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Detection Engine   │
                    │                     │
                    │ • Rule-based        │
                    │ • ML Detection      │
                    └──────────┬──────────┘
                               │
                 ┌─────────────┴─────────────┐
                 ▼                           ▼
        ┌─────────────────┐        ┌──────────────────┐
        │ Security Rules  │        │ Isolation Forest │
        │                 │        │  ML Detection    │
        └────────┬────────┘        └────────┬─────────┘
                 │                          │
                 └────────────┬─────────────┘
                              ▼
                    ┌─────────────────────┐
                    │      Findings       │
                    │                     │
                    │ • Severity          │
                    │ • Confidence        │
                    │ • Finding Type      │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Investigation Case  │
                    │                     │
                    │ Evidence + Findings │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │     Dashboard       │
                    │                     │
                    │ MTTI / Findings /   │
                    │ Metrics / Analysis  │
                    └─────────────────────┘
```

---

## 🧠 Machine Learning — IAM Anomaly Detection

One of the main Machine Learning components of ACIP is the detection of **anomalous IAM login behavior**.

The platform uses the **Isolation Forest** algorithm to identify unusual authentication patterns.

### Detection Pipeline

```text
CloudTrail IAM Events
        │
        ▼
Feature Extraction
        │
        ▼
Feature Normalization
        │
        ▼
Isolation Forest
        │
        ▼
Anomaly Score
        │
        ▼
Confidence Score
        │
        ▼
ANOMALOUS_LOGIN Finding
```

### Features

The ML model analyzes behavioral characteristics extracted from IAM login events, such as:

* Login frequency
* Source IP behavior
* Geographic / contextual characteristics
* Authentication patterns
* User activity
* Event characteristics

The trained model is stored as:

```text
backend/app/ml/models/iam_isolation_forest.joblib
```

The detection threshold is calibrated to transform the model output into an interpretable confidence score.

---

## 🚨 Rule-Based Detection

ACIP also includes deterministic security rules for detecting known suspicious behaviors.

Examples include:

### Brute Force

Detects repeated authentication attempts from suspicious sources.

```text
Multiple failed login attempts
             ↓
        Rule Engine
             ↓
      BRUTE_FORCE
             ↓
        HIGH severity
```

### Privilege Escalation

Detects suspicious IAM privilege changes, such as attaching highly privileged policies.

Example:

```text
AttachUserPolicy
        +
AdministratorAccess
        ↓
PRIVILEGE_ESCALATION
```

### ML Anomalous Login

```text
Unusual IAM login behavior
            ↓
     Isolation Forest
            ↓
    ANOMALOUS_LOGIN
```

---

## 📊 Findings

All detection mechanisms generate standardized **Finding** objects.

A finding contains information such as:

* Finding type
* Severity
* Confidence score
* Data source
* Investigation case
* Detection method
* Analyst verdict

Example:

```text
Finding
├── Type: ANOMALOUS_LOGIN
├── Severity: HIGH
├── Confidence: 0.74
├── Source: IAM
└── Method: Isolation Forest
```

Supported analyst verdicts include:

```text
PENDING
CONFIRMED
FALSE_POSITIVE
```

---

## ☁️ Evidence Management

Investigation evidence is stored using an S3-compatible storage architecture.

The project uses **LocalStack** during development to emulate AWS services locally.

Evidence follows a structured organization:

```text
s3://acip-evidence/
└── evidence/
    └── <case-id>/
        └── iam/
            └── sample_cloudtrail_events.json
```

This allows evidence to remain associated with its corresponding investigation case.

---

## 🗄️ Database

ACIP uses **PostgreSQL** for persistent storage.

The database manages entities such as:

```text
Incidents
    │
    ▼
Investigation Cases
    │
    ├── Evidence
    │
    └── Findings
```

Database migrations are managed with **Alembic**.

---

## 🔧 Technology Stack

### Backend

* Python
* FastAPI
* SQLAlchemy
* PostgreSQL
* Alembic
* Pydantic

### Machine Learning

* Scikit-learn
* Isolation Forest
* NumPy
* Pandas
* Joblib

### Cloud / Storage

* AWS CloudTrail
* AWS IAM
* Amazon S3 architecture
* LocalStack

### Frontend

* React
* JavaScript / JSX
* Dashboard components

### Infrastructure

* Docker
* Docker Compose

### Testing

* Pytest

---

## 🐳 Docker Architecture

The development environment is containerized with Docker.

Main services include:

```text
┌─────────────────────┐
│   ACIP Frontend     │
│      Port 3000      │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│    ACIP Backend     │
│      Port 8000      │
│      FastAPI        │
└──────┬───────┬──────┘
       │       │
       ▼       ▼
┌──────────┐ ┌──────────────┐
│PostgreSQL│ │  LocalStack  │
│   5432   │ │     4566     │
└──────────┘ └──────────────┘
```

---

## 📁 Project Structure

```text
Autonomous-Cloud-Investigation-Platform/
│
├── backend/
│   ├── app/
│   │   ├── detection/
│   │   ├── dashboard/
│   │   ├── ml/
│   │   ├── models/
│   │   ├── routers/
│   │   └── ...
│   │
│   ├── tests/
│   ├── train_iam_anomaly_model.py
│   └── ...
│
├── frontend/
│   ├── src/
│   ├── MLAnomalyCard.jsx
│   └── ...
│
├── docs/
│   └── architecture/
│
├── docker-compose.yml
├── README.md
└── .gitignore
```

---

## 🚀 Installation

### Prerequisites

Make sure the following tools are installed:

* Git
* Docker
* Docker Compose
* Python 3.10+
* Node.js / npm

### Clone the repository

```bash
git clone https://github.com/ilham912-ops/ACIP-Autonomous-Cloud-Investigation-Platform.git
cd ACIP-Autonomous-Cloud-Investigation-Platform
```

### Start the infrastructure

```bash
docker compose up -d
```

Check running containers:

```bash
docker ps
```

---

## 🧪 Testing

Run the backend test suite:

```bash
docker exec -it acip-backend pytest -v
```

For IAM detection tests:

```bash
docker exec -it acip-backend pytest /app/tests/test_iam_rules.py -v
```

For ML dashboard metrics:

```bash
docker exec -it acip-backend pytest /app/tests/test_ml_dashboard_metrics.py -v
```

---

## 🤖 Run IAM ML Detection

The IAM anomaly detection pipeline can be executed using:

```bash
docker exec acip-backend python -m app.run_iam_detection \
  --case-id <CASE_ID> \
  --events-file /app/sample_cloudtrail_events.json
```

The pipeline:

```text
CloudTrail Events
       ↓
Evidence Storage
       ↓
Rule-Based Detection
       ↓
ML Anomaly Detection
       ↓
Findings
       ↓
Database Persistence
       ↓
Dashboard
```

---

## 📈 Dashboard

The ACIP dashboard provides security investigation metrics such as:

* Number of findings
* Findings by severity
* Findings by data source
* MTTI (Mean Time To Investigate)
* False-positive rate
* Pending findings
* ML anomaly findings
* Analyst verdicts

Dashboard API:

```text
GET /api/dashboard/summary
```

---

## 🔐 Security Considerations

This repository is intended for development, demonstration, and academic purposes.

Do not commit:

```text
.env
AWS credentials
API keys
Passwords
Private tokens
Production secrets
```

Use environment variables for sensitive configuration.

---

## 📚 Documentation

Additional architecture documentation is available in:

```text
docs/architecture/
```

Including:

```text
S3_CONVENTION.md
```

---

## 🎓 Project Context

ACIP was developed as a project focused on **Cloud Security, Data Engineering, Machine Learning, and Automated Incident Investigation**.

The project combines:

```text
Cloud Security
      +
Data Engineering
      +
Machine Learning
      +
Incident Response
      +
Web Development
```

The Machine Learning component focuses specifically on **behavioral anomaly detection for IAM authentication events using Isolation Forest**.

---

## 👩‍💻 Author

**Ilham Boudali**

Big Data & Cloud Computing

Interested in:

* Data Engineering
* Big Data
* Cloud Computing
* Machine Learning
* Data Science
* Cybersecurity
* Python

---

## 📌 Project Status

**Completed academic / internship project**

The current version includes:

* ✅ Cloud incident management
* ✅ Investigation cases
* ✅ Evidence management
* ✅ Rule-based detection
* ✅ IAM security detection
* ✅ Brute-force detection
* ✅ Privilege escalation detection
* ✅ Isolation Forest anomaly detection
* ✅ ML-based IAM findings
* ✅ PostgreSQL persistence
* ✅ S3-compatible evidence storage
* ✅ Dashboard metrics
* ✅ Dockerized environment
* ✅ Automated tests
