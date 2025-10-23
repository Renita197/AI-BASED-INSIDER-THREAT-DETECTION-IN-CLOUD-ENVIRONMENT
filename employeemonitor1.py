import os
import cv2
import base64
import re
import csv
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
ADMIN_EMAIL = "renitaalan2005@gmail.com"   # 🔴 Replace with your real admin email
TRUST_THRESHOLD = 50
SUSPICIOUS_KEYWORDS = ["password", "hack", "leak", "resign", "confidential", "cheat", "login", "otp"]
LOG_FILE = "employee_log.csv"

# Office timings
OFFICE_START = time(9, 0, 0)   # 9:00 AM
OFFICE_END = time(18, 0, 0)    # 6:00 PM
# ------------------------------------


def init_log():
    """Create CSV log file if it doesn't exist."""
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, mode="w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["Timestamp", "Employee", "Behavior Score", "Email Score", "Final Trust Score", "Suspicious Keywords"])


def log_activity(employee_name, behavior_score, email_score, trust_score, suspicious_words):
    """Append activity details to CSV log file."""
    with open(LOG_FILE, mode="a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                         employee_name, behavior_score, email_score, trust_score, "; ".join(suspicious_words)])


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


def send_gmail_alert(service, employee_name, score, suspicious_words=None, unusual_time=False):
    subject = f"⚠ Alert: {employee_name}"
    body = f"Employee {employee_name} has a trust score of {score}.\n"

    if suspicious_words:
        body += f"Suspicious keywords found in emails: {', '.join(suspicious_words)}\n"
    if unusual_time:
        body += "Employee activity detected outside office hours.\n"

    body += "Please review their webcam behavior and email activity."

    message = MIMEText(body)
    message["to"] = ADMIN_EMAIL
    message["subject"] = subject

    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    service.users().messages().send(userId="me", body={"raw": raw}).execute()
    print("✅ Alert sent to admin via Gmail API")


def extract_message_text(payload):
    """Recursively extract plain text from Gmail message payload"""
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


def monitor_employee(employee_name="Employee1"):
    service = get_gmail_service()
    cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)   # DirectShow backend for Windows
    trust_score = 100
    init_log()

    while True:
        ret, frame = cap.read()
        if not ret:
            print("⚠️ Webcam not detected.")
            break

        # Webcam behavior
        behavior_score = analyze_behavior(frame)

        # Gmail check
        email_score, suspicious_words = analyze_gmail_messages(service, max_results=5)

        # Final trust score
        trust_score = int((behavior_score + email_score) / 2)

        # Check office hours
        now = datetime.now().time()
        unusual_time_flag = False
        if now < OFFICE_START or now > OFFICE_END:
            unusual_time_flag = True
            trust_score -= 20  # penalize trust score for working outside office hours
            suspicious_words.append("Unusual login time")

        # Display score on webcam
        cv2.putText(frame, f"Trust Score: {trust_score}", (30, 50),
                    cv2.FONT_HERSHEY_SIMPLEX, 1,
                    (0, 255, 0) if trust_score >= TRUST_THRESHOLD else (0, 0, 255), 2)
        cv2.imshow("Employee Monitor", frame)

        # Log activity
        log_activity(employee_name, behavior_score, email_score, trust_score, suspicious_words)

        # Alert if low trust, suspicious keywords, or unusual login time
        if trust_score < TRUST_THRESHOLD or suspicious_words:
            send_gmail_alert(service, employee_name, trust_score,
                             suspicious_words=[w for w in suspicious_words if w != "Unusual login time"],
                             unusual_time=unusual_time_flag)
            break

        if cv2.waitKey(1000) & 0xFF == ord("q"):  # check once per second
            break

    cap.release()
    cv2.destroyAllWindows()


if __name__ == "__main__":
    monitor_employee("John_Doe")


