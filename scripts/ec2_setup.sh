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

# 3. Install Python requirements
pip3 install -r requirements.txt

# 4. Create necessary data directories
mkdir -p data reports

# 5. Set up Nginx Reverse Proxy (Optional but recommended)
# This points Port 80 to Streamlit (8501)
sudo rm /etc/nginx/sites-enabled/default
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
echo "To start the Dashboard and Backend, use these commands:"
echo "tmux new-session -d -s backend 'uvicorn backend.main:app --host 0.0.0.0 --port 8000'"
echo "tmux new-session -d -s dashboard 'streamlit run dashboard/app.py --server.port 8501 --server.address 0.0.0.0'"
echo "---"
echo "Public Dashboard: http://your-ec2-ip"
echo "API Docs: http://your-ec2-ip/api/docs"
