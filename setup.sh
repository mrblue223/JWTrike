#!/bin/bash
# setup.sh

echo "JWT Tool Setup Script"
echo "====================="

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is not installed. Installing..."
    sudo apt update
    sudo apt install -y python3 python3-pip python3-venv
fi

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv jwt-env

# Activate virtual environment
echo "Activating virtual environment..."
source jwt-env/bin/activate

# Install requirements
echo "Installing requirements..."
pip install --upgrade pip
pip install -r requirements.txt

# Make main.py executable
chmod +x main.py

echo ""
echo "Setup complete!"
echo "To use the tool:"
echo "1. Activate virtual environment: source jwt-env/bin/activate"
echo "2. Run the tool: python main.py --help"
echo ""
echo "Example: python main.py encode --payload '{\"sub\":\"test\"}' --secret mysecret"