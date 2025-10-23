# Employee Monitoring System (Public Demo)

This project is a **demo version** of an employee monitoring system.  
It includes:

- Webcam-based behavior monitoring.
- Gmail activity analysis for suspicious keywords.
- Sensitive file access tracking and warning system.
- Trust score calculation and alert notifications.

> ⚠ **Important:** This is a demo for educational purposes.  
> Do **NOT** use it to monitor real employees without proper consent.

## Folder Structure

```
.
├── master_monitor.py       # Main launcher script
├── employeemonitor1.py    # Webcam + Gmail monitoring module
├── sensitivefile.py       # Sensitive file access + warnings module
├── README.md              # Project documentation
├── .gitignore             # Ignore sensitive and unnecessary files
```

## Setup Instructions

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/EmployeeMonitoringDemo.git
cd EmployeeMonitoringDemo
```

2. **Install required packages**
```bash
pip install opencv-python google-api-python-client google-auth-httplib2 google-auth-oauthlib
```

3. **Add credentials (local only)**
- Place your `credentials.json` from Google Cloud API in the folder.  
- **Do NOT commit this file** to GitHub.  
- The script will generate `token.json` automatically after first run.

4. **Run the monitoring system**
```bash
python master_monitor.py
```

5. **Controls**
- Press **`q`** in the webcam window to quit.  
- Placeholder employee name is `"Employee1"` for public demo.  

## Notes

- All emails, usernames, and file paths are **placeholders**.  
- To test locally:
  - Replace `"Employee1"` with your system username if desired.  
  - Replace dummy files in `SENSITIVE_FILES` with your own test files.  
- Gmail alerts will only work if valid credentials are provided.  

## Disclaimer

This project is intended **only for educational purposes**.  
Do not use it on real employees or sensitive data without permission.
