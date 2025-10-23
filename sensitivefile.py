import os
import cv2
import base64
import re
import csv
import getpass
from datetime import datetime, time
from email.mime.text import MIMEText

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# ------------ CONFIG ----------------
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.send"
]
CREDENTIALS_FILE = "credentials.json"
TOKEN_FILE = "token.json"
ADMIN_EMAIL = "xyz@gmail.com"   # Replace with your real admin email
TRUST_THRESHOLD = 50
SUSPICIOUS_KEYWORDS = ["password", "hack", "leak", "resign", "confidential", "cheat", "login", "otp"]
LOG_FILE = "employee_log.csv"
WARNINGS_FILE = "warnings.csv"

# Office timings
OFFICE_START = time(9, 0, 0)   # 9:00 AM
OFFICE_END = time(18, 0, 0)    # 6:00 PM

# Sensitive files (change paths as per your system)
SENSITIVE_FILES = [
    r"\\Replace with the your real file path",
    r"\\Replace with the your real file path",
    r"\\Replace with the your real file path"
]
# ------------------------------------


def init_log():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, mode="w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["Timestamp", "Employee", "Behavior Score", "Email Score", "Final Trust Score", "Suspicious Keywords"])
    if not os.path.exists(WARNINGS_FILE):
        with open(WARNINGS_FILE, mode="w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["Employee", "Warnings"])


def log_activity(employee_name, behavior_score, email_score, trust_score, suspicious_words):
    with open(LOG_FILE, mode="a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                         employee_name, behavior_score, email_score, trust_score, "; ".join(suspicious_words)])


def get_warnings(employee_name):
    if not os.path.exists(WARNINGS_FILE):
        return 0
    with open(WARNINGS_FILE, mode="r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row["Employee"].lower() == employee_name.lower():
                return int(row["Warnings"])
    return 0


def update_warnings(employee_name, warnings):
    rows = []
    found = False
    if os.path.exists(WARNINGS_FILE):
        with open(WARNINGS_FILE, mode="r") as file:
            reader = csv.DictReader(file)
            rows = list(reader)

    for row in rows:
        if row["Employee"].lower() == employee_name.lower():
            row["Warnings"] = str(warnings)
            found = True

    if not found:
        rows.append({"Employee": employee_name, "Warnings": str(warnings)})

    with open(WARNINGS_FILE, mode="w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=["Employee", "Warnings"])
        writer.writeheader()
        writer.writerows(rows)


def get_gmail_service():
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(TOKEN_FILE, "w") as token:
            token.write(creds.to_json())
    return build("gmail", "v1", credentials=creds)


def send_gmail_alert(service, employee_name, score, alert_type, suspicious_words=None, unusual_time=False, warnings=0):
    subject = ""
    body = ""
    if alert_type == "warning":
        subject = f"⚠ Warning: {employee_name}"
        body = f"Employee {employee_name} triggered a WARNING (1st violation).\n"
    elif alert_type == "block":
        subject = f"⛔ Block Alert: {employee_name}"
        body = f"Employee {employee_name} is BLOCKED after repeated violations (2nd violation).\n"
    else:
        subject = f"ℹ Info: {employee_name}"
        body = f"Employee {employee_name} activity notice.\n"

    body += f"Trust score: {score}\n"
    body += f"Total warnings so far: {warnings}\n"

    if suspicious_words:
        body += f"Suspicious activity detected: {', '.join(suspicious_words)}\n"
    if unusual_time:
        body += "Employee activity detected outside office hours.\n"

    body += "\nPlease review their webcam behavior, file access, and email activity."

    message = MIMEText(body)
    message["to"] = ADMIN_EMAIL
    message["subject"] = subject

    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    try:
        service.users().messages().send(userId="me", body={"raw": raw}).execute()
        print(f"✅ {alert_type.upper()} email sent to admin")
    except Exception as e:
        print(f"❌ Failed to send email alert: {e}")


def extract_message_text(payload):
    text = ""
    if "body" in payload and "data" in payload["body"]:
        try:
            text += base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8", errors="ignore")
        except Exception:
            pass
    if "parts" in payload:
        for part in payload["parts"]:
            text += extract_message_text(part)
    return text


def analyze_behavior(frame):
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
    faces = face_cascade.detectMultiScale(gray, 1.3, 5)

    if len(faces) == 1:
        return 80
    elif len(faces) > 1:
        return 40
    else:
        return 30


def analyze_gmail_messages(service, max_results=5):
    results = service.users().messages().list(userId="me", maxResults=max_results, labelIds=["INBOX"]).execute()
    messages = results.get("messages", [])
    risk_score = 0
    suspicious_words_found = []

    for msg in messages:
        txt = service.users().messages().get(userId="me", id=msg["id"], format="full").execute()
        body_text = extract_message_text(txt["payload"])
        for word in SUSPICIOUS_KEYWORDS:
            if re.search(rf"\b{word}\b", body_text, re.IGNORECASE):
                risk_score += 10
                if word not in suspicious_words_found:
                    suspicious_words_found.append(word)

    return max(0, 100 - risk_score), suspicious_words_found


def check_login_credentials(expected_employee):
    current_user = getpass.getuser()
    if current_user.lower() != expected_employee.lower():
        return current_user
    return None


def block_employee(employee_name):
    """Simulated block (no real logout)."""
    print(f"⛔ Employee {employee_name} is BLOCKED from access!")


# ------------------- Main Monitoring Function -------------------
def monitor_employee(employee_name):
    service = get_gmail_service()
    cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
    trust_score = 100
    init_log()

    # Store last access times of sensitive files
    file_last_access = {f: os.path.getatime(f) if os.path.exists(f) else 0 for f in SENSITIVE_FILES}

    try:
        while True:
            ret, frame = cap.read()
            if not ret:
                print("⚠️ Webcam not detected.")
                break

            # Webcam behavior analysis
            behavior_score = analyze_behavior(frame)

            # Gmail suspicious email analysis
            email_score, suspicious_words = analyze_gmail_messages(service, max_results=5)

            # Trust score
            trust_score = int((behavior_score + email_score) / 2)

            # Unusual login time
            now = datetime.now().time()
            unusual_time_flag = False
            if now < OFFICE_START or now > OFFICE_END:
                unusual_time_flag = True
                trust_score -= 20
                suspicious_words.append("Unusual login time")

            # Check login credentials
            wrong_user = check_login_credentials(employee_name)
            if wrong_user:
                trust_score -= 30
                suspicious_words.append(f"Using other employee's login ({wrong_user})")

            # Check sensitive file access
            for f in SENSITIVE_FILES:
                if os.path.exists(f):
                    last_access = os.path.getatime(f)
                    if last_access > file_last_access[f]:
                        filename = os.path.basename(f)
                        print(f"⚠️ Sensitive file accessed: {filename}")
                        suspicious_words.append(f"Accessed file: {filename}")
                        send_gmail_alert(service, employee_name, score=0, alert_type="warning",
                                         suspicious_words=[f"Accessed file: {filename}"], unusual_time=False,
                                         warnings=get_warnings(employee_name)+1)
                        update_warnings(employee_name, get_warnings(employee_name)+1)
                    file_last_access[f] = last_access

            # Display trust score on webcam
            cv2.putText(frame, f"Trust Score: {trust_score}", (30, 50),
                        cv2.FONT_HERSHEY_SIMPLEX, 1,
                        (0, 255, 0) if trust_score >= TRUST_THRESHOLD else (0, 0, 255), 2)
            cv2.imshow("Employee Monitor", frame)

            # Log activity
            log_activity(employee_name, behavior_score, email_score, trust_score, suspicious_words)

            # Warnings and block handling
            if trust_score < TRUST_THRESHOLD or suspicious_words:
                warnings = get_warnings(employee_name)
                if warnings == 0:
                    send_gmail_alert(service, employee_name, trust_score, "warning",
                                     suspicious_words=[w for w in suspicious_words if w != "Unusual login time"],
                                     unusual_time=unusual_time_flag, warnings=1)
                    update_warnings(employee_name, 1)
                elif warnings == 1:
                    send_gmail_alert(service, employee_name, trust_score, "block",
                                     suspicious_words=[w for w in suspicious_words if w != "Unusual login time"],
                                     unusual_time=unusual_time_flag, warnings=2)
                    update_warnings(employee_name, 2)
                    block_employee(employee_name)
                    break

            if cv2.waitKey(1000) & 0xFF == ord("q"):
                break

    finally:
        cap.release()
        cv2.destroyAllWindows()


if __name__ == "__main__":
    current_user = getpass.getuser()   # Auto-detect employee name from system login

    monitor_employee(current_user)
