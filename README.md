# TrustWatch Backend – AI/ML Phishing Detection API

TrustWatch Backend is the server-side component of the TrustWatch phishing detection system.  
It provides REST APIs for detecting phishing threats in URLs, emails, and SMS messages using machine learning and rule-based analysis.

This repository contains **backend code only**.  
The frontend user interface is maintained in a separate repository.

---

## 🎯 Purpose of the Backend

The backend is responsible for:
- Processing phishing scan requests
- Analyzing URLs, email text, and SMS content
- Applying ML and rule-based detection logic
- Generating threat scores and risk levels
- Managing database operations
- Providing secure REST APIs for clients

---

## 🌟 Key Features

- AI/ML-based phishing detection engine  
- Real-time URL, Email, and SMS analysis  
- Multilingual text analysis support  
- Threat scoring with risk classification  
- RESTful API architecture  
- Secure environment variable handling  
- Lightweight and fast response times  

---

## 🏗️ Backend Project Structure

trustwatch-backend/
├── app.py # Main Flask application (entry point)
├── database/ # Database schemas and access logic
│ ├── db.py
│ └── schema.sql
├── models/ # Detection and ML modules
│ ├── url_analyzer.py
│ ├── text_analyzer.py
│ ├── ml_detector.py
│ └── threat_intel.py
├── utils/ # Utility and helper functions
│ ├── email_service.py
│ ├── validators.py
│ └── logger.py
├── requirements.txt # Python dependencies
├── .env.example # Environment variable template
├── .gitignore # Git ignore rules


---

## 🧰 Technologies Used

- Python 3.8+
- Flask
- Machine Learning (rule-based + ML models)
- SQLite (local database)
- SendGrid (email services)

---

## ⚙️ Setup Instructions

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Install Dependencies

```bash
pip install -r requirements.txt

Environment Configuration
Copy .env.example and rename it to .env

Fill in the required values (API keys, email config, etc.)

⚠️ Do not commit .env to GitHub

▶️ Run the Backend Server
python app.py

The backend server will start at:
http://localhost:5000

🔌 API Endpoints


Scan URL
POST /api/scan/url


Scan Email / Text
POST /api/scan/text

Scan SMS
POST /api/scan/sms


Get Statistics
GET /api/stats


Get Recent Scans

GET /api/scans/recent

🔁 Backend Flow Overview
Client sends scan request

Input is validated

Detection models analyze the content

Threat score and risk level are calculated

Response is returned to the client

Scan data is stored for analytics

🔒 Security Notes
Sensitive configuration is stored in .env

.env is ignored using .gitignore

.env.example is provided for reference only

No secrets are committed to the repository

📈 Performance
Average response time under 100 ms

Efficient handling of concurrent requests

Low false-positive detection rate

⚠️ Limitations
Designed for educational and demonstration purposes

Uses lightweight ML and rule-based models

Not hardened for production environments

📌 Usage Notes
Can be consumed by web or mobile clients

Frontend must call backend APIs for detection

Easily extensible for new detection models

📝 License
This project is intended for educational and academic use only.







