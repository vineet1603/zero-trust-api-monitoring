# 🛡️ Zero-Trust API Traffic & Threat Monitor

A full-stack cybersecurity monitoring project that stores API security policies and traffic logs, applies database-level validation, and presents threat analytics through a Flask-powered web dashboard.

Built with **Python, Flask, PyMongo, MongoDB, HTML, CSS, and Chart.js**, the project demonstrates how a Zero-Trust-inspired monitoring workflow can record request activity, enforce data rules, and summarize traffic patterns. The included live-traffic feature generates randomized sample logs for demonstration and testing.

## ✨ Features

- **Policy management:** Store API endpoint rules, including allowed HTTP methods, payload limits, and authentication requirements.
- **Database-level validation:** Use MongoDB `$jsonSchema` validators to reject malformed documents and enforce required fields, types, enumerated values, and numeric ranges.
- **Traffic logging:** Record request metadata such as source IP, threat score, action taken, timestamp, and associated security policy.
- **CRUD operations:** Demonstrate Create, Read, Update, and Delete operations using PyMongo.
- **Threat analytics:** Use MongoDB aggregation pipelines to calculate average threat scores per endpoint, count traffic by action, and identify the most targeted endpoint over the last 30 days.
- **Interactive dashboard:** Visualize traffic decisions and endpoint risk profiles in a dark-themed web interface using Chart.js.
- **Live traffic simulation:** Generate randomized traffic log entries through a Flask route and refresh dashboard visualizations without a full page reload.

> **Note:** This is an educational project using a mock dataset and simulated traffic. It demonstrates monitoring and database validation concepts; it is not, by itself, a production API gateway, identity provider, or complete threat-prevention system.

## 🧰 Tech Stack

| Area | Technologies |
|---|---|
| Backend | Python, Flask |
| Database | MongoDB |
| Database driver | PyMongo |
| Data validation | MongoDB `$jsonSchema` |
| Frontend | HTML5, CSS3, JavaScript |
| Charts | Chart.js |
| Analytics | MongoDB aggregation pipelines |

## 🏗️ Architecture Overview

1. **Security policies** define rules for API endpoints.
2. **Traffic logs** store request-related details and reference the relevant policy through `policy_id`.
3. **MongoDB validators** enforce data requirements when documents are written.
4. **PyMongo** performs CRUD operations and executes aggregation pipelines.
5. **Flask** exposes routes for dashboard data and simulated traffic.
6. **Chart.js** displays traffic decisions and endpoint threat profiles in the browser.

## 📂 Project Structure

```text
zero-trust-api-monitor/
├── app.py                     # Flask application and dashboard/API routes
├── zero_trust_engine.py       # Database setup, validation, sample data, CRUD, aggregations
├── requirements.txt           # Python dependencies
├── README.md                  # Project documentation
└── templates/
    └── dashboard.html         # Dashboard interface and Chart.js visualizations
```

The structure above follows the project files described in this README. If your repository uses different filenames or folders, update this tree to match the files actually committed.

## 🗄️ Database Design

Database: `zero_trust_engine_db`

| Collection | Purpose |
|---|---|
| `security_policies` | Stores endpoint rules, permitted methods, payload-size limits, and authentication requirements. |
| `traffic_logs` | Stores request source IPs, threat scores, actions, timestamps, and references to security policies. |

Traffic logs use a `policy_id` reference to connect each log to a security policy, avoiding repeated copies of policy data in every log.

### Validation rules documented in the project

- `endpoint_name`: required string in `security_policies`
- `method`: required string; one of `GET`, `POST`, `PUT`, or `DELETE`
- `max_payload_size`: required integer between `500` and `8000`
- `policy_id`: required ObjectId reference in `traffic_logs`
- `source_ip`: required string
- `action_taken`: required value such as `ALLOWED`, `BLOCKED`, or `FLAGGED`
- `threat_score`: required integer greater than or equal to `0`

MongoDB schema validation protects the database from invalid document shapes and values. Authentication and request authorization still need to be implemented and enforced by the application or an API gateway where required.

## 📊 Aggregation Analytics

The project demonstrates three main analytics pipelines:

1. **Average threat score per endpoint** — groups logs by policy, calculates average threat scores and request counts, and joins policy details to display endpoint names.
2. **Request frequency by action** — counts traffic logs by action, such as `ALLOWED`, `BLOCKED`, and `FLAGGED`, for the dashboard doughnut chart.
3. **Most targeted endpoint in the last 30 days** — filters recent logs, counts requests per policy, and identifies the most frequently targeted endpoint.

## ⚙️ Getting Started

### Prerequisites

- Python 3.x
- MongoDB Community Server running locally, or a MongoDB connection URI
- Git

### 1. Clone the repository

Replace `YOUR_USERNAME` with your GitHub username:

```bash
git clone https://github.com/YOUR_USERNAME/zero-trust-api-monitor.git
cd zero-trust-api-monitor
```

### 2. Create and activate a virtual environment

**Windows (PowerShell):**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**macOS / Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Make sure `requirements.txt` contains the dependencies actually imported by your project, including Flask and PyMongo.

### 4. Configure MongoDB

Start your local MongoDB service. The default local connection URI is commonly:

```text
mongodb://localhost:27017/
```

If your code supports configuration through environment variables, place your connection URI in a local `.env` file or environment variable and ensure secrets are excluded from Git. Use the exact variable name expected by your code. **Never commit database credentials or API secrets.**

### 5. Initialize the database and sample data

Run the database setup script:

```bash
python zero_trust_engine.py
```

According to the project report, initialization creates the validated collections and seeds sample security policies and traffic logs. **Warning:** the initialization process described in the report drops and recreates collections. Review the script before running it against any database containing data you need to keep.

### 6. Start the Flask dashboard

```bash
python app.py
```

Open the local address shown in the terminal. If the application uses Flask's default local port, visit:

```text
http://127.0.0.1:5000
```



Create the `screenshots/` directory and commit the images before using these paths. The image links above are placeholders until those files exist.

## 🧪 Example Workflow

1. Initialize MongoDB collections and seed sample data.
2. Review endpoint policies and their validation constraints.
3. Run the CRUD demonstrations in the database script.
4. Start the Flask dashboard.
5. Inspect traffic-action counts and endpoint threat-score summaries.
6. Trigger the live-traffic simulation to add sample log entries and refresh the charts.

## 🔐 Security Considerations

- Use mock data for demonstrations and testing.
- Keep credentials and `.env` files out of version control.
- Do not expose the development Flask server directly to the public internet.
- Validate and authenticate incoming requests in the application/API gateway; database schema validation alone does not authenticate users.
- Review the database initialization script before running it, because it may reset collections.
- Before production use, add appropriate authentication, authorization, rate limiting, audit controls, secure configuration, monitoring, and deployment hardening.

## 🚧 Possible Future Improvements

- Add authenticated administrator access and role-based permissions.
- Implement configurable threat thresholds and alerting.
- Add pagination and filters for traffic logs.
- Add automated tests for validation rules, API routes, and aggregation results.
- Use environment-based configuration for database connections.
- Add Docker support and a deployment guide.

## 🤝 Contributing

Contributions, bug reports, and feature requests are welcome. Open an issue to discuss a proposed change, or submit a pull request with a clear description of the improvement.


---

**Built as a learning project exploring MongoDB, PyMongo, Flask, schema validation, CRUD operations, aggregation pipelines, and cybersecurity observability.**
