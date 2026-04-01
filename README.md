# 🚀 AI-Driven Security & Performance Intelligence Platform

This platform integrates **Apache JMeter**, **OWASP ZAP**, and **Scikit-learn AI** to provide next-level testing insights.

## 🏗️ Architecture
1. **GitHub Actions**: Triggers JMeter/ZAP scans and runs the **AI Engine** (Anomaly Detection, Prediction, Risk Prioritization).
2. **AI Engine**: A Python-based intelligence layer using `IsolationForest` and `LinearRegression`.
3. **AWS EC2**: Hosts the **Streamlit Dashboard** and **FastAPI Backend**, receiving real-time JSON findings from GitHub.

---

## 🛠️ Setup Instructions

### 1. Prepare your AWS EC2 Instance
- Launch an Ubuntu 22.04 LTS (`t2.micro` is Free Tier eligible).
- **Security Group**: Open ports `22` (SSH), `80` (HTTP), `8501` (Dashboard), and `8000` (API).
- Download your `.pem` key.

### 2. Configure GitHub Secrets
Go to your GitHub Repository -> **Settings** -> **Secrets and variables** -> **Actions**. 
Add the following secrets:
- `EC2_HOST`: The Public IP or DNS of your EC2 instance.
- `EC2_SSH_KEY`: The **entire content** of your `.pem` private key file.

### 3. Initialize your EC2 Server
Connect to your EC2 via SSH and run:
```bash
git clone https://github.com/[your-username]/[your-repo-name].git
cd [your-repo-name]
chmod +x scripts/ec2_setup.sh
./scripts/ec2_setup.sh
```

### 4. Start the Dashboard (on EC2)
Launch the services inside `tmux` sessions so they stay running:
```bash
# Start Backend
tmux new-session -d -s backend 'uvicorn backend.main:app --host 0.0.0.0 --port 8000'

# Start Dashboard
tmux new-session -d -s dashboard 'streamlit run dashboard/app.py --server.port 8501 --server.address 0.0.0.0'
```

---

## 📊 How it Works
1. **Push Code**: Every push to `main` triggers the GitHub Action.
2. **AI Analysis**: GitHub runs the tests and the AI scripts.
3. **Dashboard Sync**: GitHub pushes the latest `findings.json` to your EC2.
4. **View Results**: Visit `http://your-ec2-ip` to see the AI insights!

---

## 🤖 AI Engine Details
- **Anomaly Detection**: `IsolationForest` identifies latency spikes that stay within "success" bounds but indicate a silent bottleneck.
- **Predictive Failure**: `LinearRegression` projects mean response times to predict when the system will crash under load.
- **Risk Scoring**: High-confidence vulnerabilities are prioritized using a weighted scoring algorithm.