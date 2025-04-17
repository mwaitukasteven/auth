import smtplib

try:
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    print("Connection successful!")
    server.quit()
except Exception as e:
    print(f"Connection failed: {e}")