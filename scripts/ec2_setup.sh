#!/bin/bash
# AI-Driven Testing Platform: EC2 Setup Script
# This runs on a clean Ubuntu 22.04 instance.

echo "🚀 Starting AI Platform Environment Setup..."

# 1. Update and install basic dependencies
sudo apt-get update -y
sudo apt-get upgrade -y
sudo apt-get install python3-pip git tmux nginx -y

# 2. Clone the repository (Use your own repo URL if different)
# git clone https://github.com/[your-user]/ai-testing-platform.git
# cd ai-testing-platform

# 3. Create a Virtual Environment (Crucial for modern Ubuntu)
echo "📦 Creating Python Virtual Environment..."
sudo apt-get install python3-venv -y
python3 -m venv venv
source venv/bin/activate

# 4. Install Python requirements inside venv
echo "📥 Installing Python requirements..."
pip3 install --upgrade pip
pip3 install -r requirements.txt

# 5. Create necessary data directories
mkdir -p data reports
touch data/results.jtl reports/zap_report.json

# 6. Set up Nginx Reverse Proxy
# This points Port 80 to Streamlit (8501)
echo "🌐 Configuring Nginx..."
sudo rm -f /etc/nginx/sites-enabled/default
cat <<EOF | sudo tee /etc/nginx/sites-available/ai-platform
server {
    listen 80;
    location / {
        proxy_pass http://127.0.0.1:8501;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
    location /api {
        proxy_pass http://127.0.0.1:8000;
    }
}
EOF
sudo ln -s /etc/nginx/sites-available/ai-platform /etc/nginx/sites-enabled/
sudo systemctl restart nginx

echo "✅ Environment Ready!"
echo "---"
echo "To start the Dashboard and Backend, run THESE exactly:"
echo "---"
echo "1. Start Backend:"
echo "tmux new-session -d -s backend './venv/bin/uvicorn backend.main:app --host 0.0.0.0 --port 8000'"
echo ""
echo "2. Start Dashboard:"
echo "tmux new-session -d -s dashboard './venv/bin/streamlit run dashboard/app.py --server.port 8501 --server.address 0.0.0.0'"
echo "---"
echo "Public Dashboard: http://your-ec2-ip"
