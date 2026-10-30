# DDoS Attack Detection and Prevention System
> College Project — Safe Demo & Simulation Mode

---

## 📌 Project Objectives

| # | Objective |
|---|-----------|
| 1 | Detect known DDoS patterns using **supervised machine learning** |
| 2 | Detect unknown/novel anomalies using **anomaly-based adaptive detection** |
| 3 | Monitor network traffic statistics in **real time** |
| 4 | Demonstrate **fast, automated mitigation** (simulated — no real firewall changes) |

> ⚠️ **Safety Notice**: This project runs entirely in simulation/demo mode. It does NOT modify your firewall, does NOT send packets to external systems, and does NOT affect your real network. All traffic data is synthetic and generated locally.

---

## 📁 Project Structure

```
ddos-detection-project/
│
├── backend/
│   ├── app.py                  # Flask web server & API endpoints
│   ├── simulator.py            # Synthetic traffic generator (safe demo)
│   ├── ml_detector.py          # Supervised ML detection (Random Forest)
│   ├── anomaly_detector.py     # Anomaly detection (Isolation Forest)
│   ├── mitigation.py           # Simulated mitigation engine
│   ├── logger.py               # Event & log persistence
│   └── models/                 # Saved trained ML models
│
├── frontend/
│   ├── index.html              # Main dashboard page
│   ├── style.css               # Modern dark-theme CSS
│   └── dashboard.js            # Real-time chart & API polling
│
├── data/
│   ├── logs/                   # Saved event logs (JSON)
│   └── training/               # Synthetic training data (CSV)
│
├── requirements.txt            # Python dependencies
├── setup.py                    # One-step setup script
└── README.md                   # This file
```

---

## 🖥️ Windows Setup (Step by Step)

### Step 1 — Check Python
Open **PowerShell** or **Command Prompt** and run:
```powershell
python --version
```
You need Python 3.9 or later. Download from https://www.python.org/downloads/ if needed.

### Step 2 — Install dependencies
In your project folder, run:
```powershell
pip install -r requirements.txt
```

### Step 3 — Train the ML models (first time only)
```powershell
python setup.py
```
This generates synthetic training data and trains both ML models. Takes about 30–60 seconds.

### Step 4 — Start the application
```powershell
python backend/app.py
```

### Step 5 — Open the dashboard
Open your browser and go to:
```
http://localhost:5000
```

---

## 🧪 How the Demo Works

The system runs in **Safe Simulation Mode** by default:
- A background thread generates synthetic network traffic packets (normal + attack types)
- The ML pipeline classifies each packet in real time
- Detections trigger simulated mitigation (IP blocking list, rate limiting log)
- All events are saved to `data/logs/`
- The dashboard updates every 2 seconds

### Traffic Types Simulated
| Type | Description |
|------|-------------|
| Normal | Legitimate web/DNS/HTTPS traffic |
| SYN Flood | High-volume TCP SYN packets from spoofed IPs |
| UDP Flood | Large volume of UDP packets |
| HTTP Flood | Rapid HTTP GET requests |
| ICMP Flood | Ping flood attack pattern |
| Slowloris | Slow HTTP connection exhaustion |

---

## 🧠 ML Models Used

| Model | Type | Purpose |
|-------|------|---------|
| Random Forest | Supervised | Classify known attack types |
| Isolation Forest | Unsupervised/Anomaly | Detect novel/unknown attack patterns |

> Note: Models are trained on **synthetic data** for demonstration. Accuracy values shown in the dashboard reflect performance on the synthetic test set, not real-world traffic.

---

## 📊 Dashboard Features

- **Live Traffic Chart** — packets/sec over time
- **Detection Results** — real-time classification feed
- **Alert Panel** — triggered when attack confidence > threshold
- **Mitigation Log** — simulated IP blocks and rate limits
- **Model Stats** — confusion matrix summary on synthetic test data

---

## 🌐 Mininet SDN Network Integration (Real Network Mode)

This project now includes complete ready-to-run scripts to deploy inside a **Mininet virtual network with Open vSwitch**:

- **`mininet/topology.py`**: Boots an OpenFlow network containing 1 Victim Web Server (`10.0.0.1`), 1 Normal Client (`10.0.0.2`), and 2 Attacker Bots (`10.0.0.3`, `10.0.0.4`) connected via an Open vSwitch (`s1`).
- **`mininet/collector.py`**: Sniffs live packets on the switch interface, extracts the 10 flow features, classifies traffic using the Random Forest and Isolation Forest models, and dynamically installs real OpenFlow `actions=drop` rules using `ovs-ofctl`.
- **`mininet/README.md`**: Complete step-by-step setup and attack commands (`hping3`, `curl`).

---

## 👩‍💻 Tech Stack

- **Backend**: Python 3.x, Flask, scikit-learn, pandas, numpy
- **Frontend**: HTML5, CSS3, Vanilla JavaScript, Chart.js
- **Network & SDN**: Mininet, Open vSwitch, Scapy, OpenFlow 1.3
- **Storage**: JSON log files (local)
- **ML Models**: Random Forest (Supervised), Isolation Forest (Unsupervised)
