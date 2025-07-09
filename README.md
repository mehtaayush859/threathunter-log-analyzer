# ThreatHunter – Lightweight SIEM-like Log Analyzer with Alerting

## 1. Project Overview
ThreatHunter is a lightweight, modular SIEM-inspired tool that helps users:
- Ingest and parse security logs (auth logs, web logs, syslogs)
- Detect anomalies or signs of attack (failed logins, lateral movement, brute force, privilege escalation, etc.)
- Alert based on rule-based detection
- Visualize suspicious activity and generate security reports

## 2. Project Objectives
- Enable security analysis without a full-blown SIEM
- Provide actionable intelligence from logs (local or uploaded)
- Usable for students, sysadmins, and small teams
- Fully open-source, Dockerized, and cloud-hostable

## 3. Real-World Use Cases
| Role                | How It's Useful                                 |
|---------------------|------------------------------------------------|
| Security Analyst    | Analyze Linux auth logs, detect brute-force & sudo abuse |
| SOC Trainee         | Practice writing detection rules and parsing logs |
| Pentester/Blue Team | Analyze post-exploitation logs                  |
| Instructor          | Simulate alert pipelines in a lab               |

## 4. Security Concepts Covered
- Log collection & normalization
- Detection engineering (rules/alerts)
- Indicators of compromise (IP, time anomalies, account usage)
- Security alerting pipeline
- Alert severity classification
- Correlation between log events

## 5. Tech Stack
| Layer         | Technology                                  |
|-------------- |---------------------------------------------|
| Language      | Python 3.10+                                |
| Backend       | FastAPI or Streamlit (optional UI)          |
| Storage       | SQLite or JSON flat files                   |
| Log Types     | Linux auth.log, syslog, Apache access logs, AWS CloudTrail logs |
| Visualization | Matplotlib, Seaborn, Streamlit dashboard    |
| Alerting      | Rule-based logic, optional Slack/Email alert|
| Container     | Docker (optional)                           |
| CI/CD         | GitHub Actions (tests, formatting)          |

## 6. Project Structure
```
threathunter/
├── core/
│   ├── log_parser.py
│   ├── rule_engine.py
│   └── utils.py
├── alerts/
│   ├── alert_manager.py
│   └── alert_rules.yaml
├── dashboard/ (optional)
│   ├── streamlit_app.py
│   └── visualizer.py
├── data/
│   ├── sample_logs/
│   └── processed/
├── reports/
│   ├── alerts.json
│   └── summary.pdf
├── tests/
│   └── test_log_parser.py
├── main.py
├── config.yaml
├── requirements.txt
├── Dockerfile
└── README.md
```

## 7. Features
### MVP Features
- Upload logs (or provide path if local)
- Parse Linux auth logs & Apache access logs
- Rule-based detection (e.g., 5 failed logins in 2 mins)
- Output alerts with severity tags (Low, Med, High)
- Generate alert report (JSON + PDF)
- Optional visualization (failed logins over time, top IPs)

### Advanced Features
- Streamlit dashboard to filter alerts, graphs
- Add AWS CloudTrail parser (via JSON)
- Slack/email alert for critical severity
- Rule testing mode (simulate rules)
- Simple correlation engine (e.g., failed logins + sudo = HIGH)
- Anomaly detection (time-based patterns)
- Logging pipeline to append live alerts

## 8. Testing Plan
| Type              | Tools                                 |
|-------------------|---------------------------------------|
| Unit Testing      | PyTest (log_parser, rule_engine)      |
| Functional Testing| Use known vulnerable log datasets      |
| CI                | GitHub Actions: flake8 + pytest       |
| Security Linting  | Bandit                                |
| Visualization QA  | Ensure graphs render with Streamlit    |

## 9. Sample Alert Rules (YAML)
```yaml
- name: Brute Force Login
  log_type: auth
  match:
    - pattern: "Failed password for"
      count: 5
      timeframe: 120  # seconds
  severity: High

- name: Sudo Abuse
  log_type: auth
  match:
    - pattern: "sudo"
      user: "not root"
  severity: Medium
```

## 10. Hosting Plan
- Web UI (Streamlit or FastAPI) → Host on Streamlit Cloud or Render
- Data → SQLite or JSON (no cloud DB needed)
- No Nmap or root tools — all local parsing
- Docker-ready: simple docker-compose up deployment

## Getting Started
1. **Clone the repository**
   ```bash
   git clone <repo-url>
   cd Threat_Hunter
   ```
2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```
3. **Run the main application**
   ```bash
   python main.py
   ```
4. **(Optional) Run the dashboard**
   ```bash
   streamlit run dashboard/streamlit_app.py
   ```
5. **Run tests**
   ```bash
   pytest
   ```
6. **Build Docker image**
   ```bash
   docker build -t threathunter .
   ```

---

For more details, see the documentation in each module and the sample alert rules in `alerts/alert_rules.yaml`. 