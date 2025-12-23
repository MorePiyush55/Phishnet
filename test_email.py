
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import ssl
import sys

# Add backend to path to import settings if needed, or just use raw env vars
# Assuming the user runs this from the 'backend' directory or root
current_dir = os.getcwd()
if 'backend' not in current_dir:
    sys.path.append(os.path.join(current_dir, 'backend'))

def test_smtp_send():
    print("--- PhishNet SMTP Test Tool ---")
    
    sender = os.getenv("IMAP_USER")
    password = os.getenv("IMAP_PASSWORD")
    
    if not sender or not password:
        print("[ERROR] IMAP_USER or IMAP_PASSWORD not set in environment.")
        print("Please export them first:")
        print("  Windows: $env:IMAP_USER='phishnet.ai@gmail.com'; $env:IMAP_PASSWORD='...'; python test_email.py")
        return

    recipient = input(f"Enter recipient email (default: {sender}): ").strip() or sender
    
    print(f"\nAttempting to send email...")
    print(f"From: {sender}")
    print(f"To: {recipient}")
    
    msg = MIMEMultipart()
    msg['From'] = f"PhishNet Test <{sender}>"
    msg['To'] = recipient
    msg['Subject'] = "PhishNet SMTP Test Notification"
    
    body = """
    <h1>SMTP Configuration Verified</h1>
    <p>This email confirms that your PhishNet backend can successfully send emails via Gmail SMTP.</p>
    <ul>
        <li><b>Sender:</b> Verified</li>
        <li><b>App Password:</b> Verified</li>
        <li><b>Connection:</b> Secure (TLS)</li>
    </ul>
    <p><i>PhishNet Security Team</i></p>
    """
    msg.attach(MIMEText(body, 'html'))
    
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.set_debuglevel(1) # Verbose output
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(sender, password)
            server.send_message(msg)
            
        print("\n[SUCCESS] Test email sent successfully!")
        print(f"Check the inbox of {recipient}")
        
    except Exception as e:
        print(f"\n[FAILURE] Could not send email: {e}")

if __name__ == "__main__":
    test_smtp_send()
