# Network Intrusion Detection System (SecureNet)

An advanced Network Intrusion Detection System (NIDS) powered by a Deep Residual Neural Network (ResNet) trained on the NSL-KDD dataset. The system features a real-time React/TypeScript frontend dashboard and a Python/Flask backend capable of both live packet capture (via Scapy) and simulated dataset traffic.

## Features

- **Deep Learning Classifier**: ResNet model trained on NSL-KDD for detecting DoS, Probe, R2L, and U2R attacks.
- **Live Traffic Capture**: Uses Scapy for real-time packet sniffing and flow aggregation.
- **Application-layer Threat Detection**: Basic regex-based heuristics for identifying SQLi, XSS, and Malware callbacks in payloads.
- **Adversarial Security**: Built-in monitoring for model drift, low-confidence predictions, and adversarial input patterns.
- **Real-time Dashboard**: Modern React UI with live feeds, geographic origin mapping, and interactive charts.

## Prerequisites

- Node.js (v16+)
- Python 3.9+
- (Optional) `libpcap` for Scapy live capture capabilities

## Setup Instructions

### 1. Backend Setup

Navigate to the `backend` directory:
```bash
cd backend
```

Create and activate a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

Install the required Python packages:
```bash
pip install -r requirements.txt
```

**Train the Model:**
Before running the backend, you must train the ResNet model. This will generate `resnet_nslkdd.pth`, `norm_mean.npy`, and `norm_std.npy`.
```bash
python train_resnet.py
```

### 2. Environment Configuration

Copy the `.env.example` file to `.env` in the root directory:
```bash
cp .env.example .env
```
Update `.env` with your desired secure credentials.

### 3. Frontend Setup

In the root directory, install the Node dependencies:
```bash
npm install
```

## Running the Application

**Start the Backend Server:**
In the `backend` directory (with your virtual environment activated):
```bash
python app.py
```
The Flask server will start on `http://localhost:5000`.

**Start the Frontend Server:**
In the root directory:
```bash
npm run dev
```
The React development server will start (typically on `http://localhost:8080`). Open this URL in your browser to access the dashboard.

## Login

By default, use the credentials specified in your `.env` file. If not set, it defaults to:
- **Username:** admin
- **Password:** 1234
