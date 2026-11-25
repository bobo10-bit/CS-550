import re

# Opens Logs
file_path = r"C:\Users\eleme\Downloads\CS 550 Project Two Supporting Files\CS 550 Project Two Supporting Files\CS 550 Project Two Siem Correlation Log D.log"

logs = []

# Reads the log file and separates each entry
with open(file_path, "r") as file:
    for line in file:
        line = line.strip()

        # Skips empty lines and comments
        if line == "" or line.startswith("#"):
            continue

        # Separates each log entry into individual fields
        fields = line.split("|")

        # Adds entries that have all nine fields
        if len(fields) == 9:
            logs.append(fields)

# Counts failed login attempts
failed_logins = []

for log in logs:
    if log[3] == "LOGIN_FAILED":
        failed_logins.append(log)

# Displays failed login attempts with the time and source IP
print("Failed Login Attempts:")
for log in failed_logins:
    print(log[0], log[4], log[8])

# Identifies configuration changes
print("\nConfiguration Changes:")
for log in logs:
    if log[3] == "CONFIG_CHANGE":
        print(log[0], log[2], log[8])

# Identifies events marked as critical
print("\nCritical Events:")
for log in logs:
    if log[2] == "CRITICAL":
        print(log[0], log[3], log[8])

# Identifies external connections to the database server
print("\nExternal Database Connections:")
for log in logs:
    if log[5] == "10.2.2.25" and log[6] == "3306":
        if not log[4].startswith("10."):
            print(log[0], log[4], log[8])

# Identifies activity from the internal workstation
print("\nInternal Scanning:")
for log in logs:
    if log[4] == "10.1.1.67":
        print(log[0], log[5], log[6], log[8])

# Identifies possible DDoS and flooding activity
print("\nDDoS Activity:")
for log in logs:
    if "flood" in log[8].lower() or "ddos" in log[8].lower():
        print(log[0], log[5], log[8])

# Identifies log entries containing large data transfers
print("\nLarge Data Transfers:")
for log in logs:
    if re.search(r"\d+MB", log[8], re.IGNORECASE):
        print(log[0], log[4], log[5], log[8])

# Displays a summary of the log analysis
print("\nSummary")
print("Total Log Entries:", len(logs))
print("Failed Logins:", len(failed_logins))
print("Configuration Changes:", sum(1 for log in logs if log[3] == "CONFIG_CHANGE"))
print("Critical Events:", sum(1 for log in logs if log[2] == "CRITICAL"))
