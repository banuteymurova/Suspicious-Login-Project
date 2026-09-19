import csv
import sys
import ipaddress
from datetime import datetime, time


def load_logs(filename):
    logs = []

    try:
        with open(filename, newline="") as file:
            reader = csv.DictReader(file)

            required_columns = {"ip", "username", "time", "status"}

            if not required_columns.issubset(reader.fieldnames):
                print("Error: The file is missing required columns.")
                sys.exit(1)

            for row in reader:

                if (
                    not row["ip"]
                    or not row["username"]
                    or not row["time"]
                    or not row["status"]
                ):
                    print("Error: A row contains missing information.")
                    sys.exit(1)

                if row["status"] not in ["SUCCESS", "FAILED"]:
                    print("Error: Invalid login status.")
                    sys.exit(1)

                try:
                    ipaddress.ip_address(row["ip"])
                except ValueError:
                    print("Error: Invalid IP address.")
                    sys.exit(1)

                try:
                    datetime.strptime(row["time"], "%H:%M")
                except ValueError:
                    print("Error: Invalid time format.")
                    sys.exit(1)

                logs.append(row)

    except FileNotFoundError:
        print("Error: File not found.")
        sys.exit(1)

    return logs


def stats(logs):

    user_ips = {}
    ip_stats = {}
    user_attempts = {}

    total_logins = len(logs)

    successful_logins = sum(
        1 for row in logs if row["status"] == "SUCCESS"
    )

    failed_logins = total_logins - successful_logins
    suspicious_logins = 0

    for row in logs:

        ip = row["ip"]

        if ip not in ip_stats:
            ip_stats[ip] = {
                "attempts": 0,
                "success": 0,
                "failed": 0,
                "suspicious": 0,
                "usernames": set()
            }

        ip_stats[ip]["attempts"] += 1

        if row["status"] == "SUCCESS":
            ip_stats[ip]["success"] += 1
        else:
            ip_stats[ip]["failed"] += 1

        ip_stats[ip]["usernames"].add(row["username"])

        login_time = datetime.strptime(
            row["time"], "%H:%M"
        ).time()

        if login_time < time(7, 0) or login_time > time(23, 0):
            ip_stats[ip]["suspicious"] = 1
            suspicious_logins += 1

        username = row["username"]

        if username not in user_ips:
            user_ips[username] = {
                "ips": set(),
                "suspicious": 0,
                "total_attempts": 0,
                "failed_attempts": 0,
                "successful_attempts": 0
            }

        user_ips[username]["ips"].add(ip)
        user_ips[username]["total_attempts"] += 1

        if username not in user_attempts:
            user_attempts[username] = 0

        user_attempts[username] += 1

        if row["status"] == "SUCCESS":
            user_ips[username]["successful_attempts"] += 1

        else:
            user_ips[username]["failed_attempts"] += 1

            if login_time < time(7, 0) or login_time > time(23, 0):
                user_ips[username]["suspicious"] += 1

    unique_ips = len(ip_stats)
    unique_users = len(user_attempts)

    return (
        ip_stats,
        user_ips,
        user_attempts,
        total_logins,
        successful_logins,
        failed_logins,
        suspicious_logins,
        unique_ips,
        unique_users
    )


def print_stats(
    logs,
    ip_stats,
    user_ips,
    user_attempts,
    total_logins,
    successful_logins,
    failed_logins,
    suspicious_logins,
    unique_ips,
    unique_users
):

    print("////////////////////////////////\n")
    print("-------------------------------- ")
    print("\nLOGIN STATISTICS:")
    print("-------------------------------- ")
    print(f"Total logins: {total_logins}")
    print(f"Successful logins: {successful_logins}")
    print(f"Failed logins: {failed_logins}")
    print(f"Suspicious logins: {suspicious_logins}")
    print(f"Unique IPs: {unique_ips}")
    print(f"Unique users: {unique_users}\n")
    print("////////////////////////////////\n")
    print("\n")



    print("////////////////////////////////\n")
    print("-------------------------------- ")
    print("IP STATISTICS:")
    print("-------------------------------- ")

    for ip, stats in ip_stats.items():

        print("....................................... ")
        print(f"IP: {ip}")
        print(f"  Attempts: {stats['attempts']}")
        print(f"  Successful logins: {stats['success']}")
        print(f"  Failed logins: {stats['failed']}")
        print(f"  Suspicious logins: {stats['suspicious']}")
        print(f"  Usernames: {', '.join(stats['usernames'])}\n")
        print("....................................... ")
        print("\n")

    print("////////////////////////////////\n")
    print("\n")



    print("////////////////////////////////\n")
    print("-------------------------------- ")
    print("USER STATISTICS:")
    print("-------------------------------- ")

    for username, stats in user_ips.items():

        print("....................................... ")
        print(f"USERNAME: {username}")
        print(f"  IPs: {', '.join(stats['ips'])}")
        print(f"  Suspicious logins: {stats['suspicious']}\n")
        print(f"  Failed attempts: {stats['failed_attempts']}")
        print(f"  Successful attempts: {stats['successful_attempts']}\n")
        print(f"  Total attempts: {stats['total_attempts']}")
        print("....................................... ")
        print("\n")

    print("////////////////////////////////\n")
    print("\n")



    print("////////////////////////////////\n")
    print("-------------------------------- ")
    print("SUSPICIOUS USERS:")
    print("---------------------------------")

    found_suspicious_user = False

    for username, stats in user_ips.items():

        if stats["suspicious"] == 1:

            print("-------------------------------- ")
            print("LEVEL: LOW")
            print(f"Username: {username} (unusual login time)")
            print("-------------------------------- ")
            print("\n")

            found_suspicious_user = True

        if stats["failed_attempts"] > 3:

            print("-------------------------------- ")
            print("LEVEL: MEDIUM")
            print(
                f"Username: {username} "
                f"(more than 3 failed attempts)"
            )
            print("-------------------------------- ")
            print("\n")

            found_suspicious_user = True

        if len(stats["ips"]) > 2:

            print("-------------------------------- ")
            print("LEVEL: HIGH")
            print(
                f"Username: {username} "
                f"(more than 2 IPs)"
            )
            print("-------------------------------- ")
            print("\n")

            found_suspicious_user = True



    for i in range(len(logs) - 3):

        if (
            logs[i]["ip"] == logs[i + 1]["ip"]
            and logs[i]["ip"] == logs[i + 2]["ip"]
            and logs[i]["ip"] == logs[i + 3]["ip"]
            and logs[i]["username"] == logs[i + 1]["username"]
            and logs[i]["username"] == logs[i + 2]["username"]
            and logs[i]["username"] == logs[i + 3]["username"]
            and logs[i]["status"] == "FAILED"
            and logs[i + 1]["status"] == "FAILED"
            and logs[i + 2]["status"] == "FAILED"
            and logs[i + 3]["status"] == "SUCCESS"
        ):

            print("-------------------------------- ")
            print("LEVEL: HIGH")
            print(
                f"Username: {logs[i]['username']} "
                f"(3 failed attempts followed by successful login)"
            )
            print(f"IP: {logs[i]['ip']}")
            print("-------------------------------- ")
            print("\n")

            found_suspicious_user = True

    if not found_suspicious_user:
        print("None")

    print("////////////////////////////////\n")



    print("////////////////////////////////\n")
    print("-------------------------------- ")
    print("SUSPICIOUS IPs:")
    print("-------------------------------- ")

    found_suspicious_ip = False

    for ip, stats in ip_stats.items():

        if stats["suspicious"] == 1:

            print("-------------------------------- ")
            print("LEVEL: LOW")
            print(f"IP: {ip} (unusual login time)")
            print("-------------------------------- ")
            print("\n")

            found_suspicious_ip = True

        if stats["failed"] > 3:

            print("-------------------------------- ")
            print("LEVEL: MEDIUM")
            print(
                f"IP: {ip} "
                f"(more than 3 failed attempts)"
            )
            print("-------------------------------- ")
            print("\n")

            found_suspicious_ip = True

        if len(stats["usernames"]) > 3:

            print("-------------------------------- ")
            print("LEVEL: HIGH")
            print(
                f"IP: {ip} "
                f"(more than 3 usernames)"
            )
            print("-------------------------------- ")
            print("\n")

            found_suspicious_ip = True



    for i in range(len(logs) - 3):

        if (
            logs[i]["ip"] == logs[i + 1]["ip"]
            and logs[i]["ip"] == logs[i + 2]["ip"]
            and logs[i]["ip"] == logs[i + 3]["ip"]
            and logs[i]["username"] == logs[i + 1]["username"]
            and logs[i]["username"] == logs[i + 2]["username"]
            and logs[i]["username"] == logs[i + 3]["username"]
            and logs[i]["status"] == "FAILED"
            and logs[i + 1]["status"] == "FAILED"
            and logs[i + 2]["status"] == "FAILED"
            and logs[i + 3]["status"] == "SUCCESS"
        ):

            print("-------------------------------- ")
            print("LEVEL: HIGH")
            print(
                f"IP: {logs[i]['ip']} "
                f"(3 failed attempts followed by successful login)"
            )
            print(f"Username: {logs[i]['username']}")
            print("-------------------------------- ")
            print("\n")

            found_suspicious_ip = True

    if not found_suspicious_ip:
        print("None")

    print("////////////////////////////////\n")


def main():

    if len(sys.argv) != 2:
        print("Usage: python3 login_stats.py <logfile.csv>")
        sys.exit(1)

    filename = sys.argv[1]

    logs = load_logs(filename)

    (
        ip_stats,
        user_ips,
        user_attempts,
        total_logins,
        successful_logins,
        failed_logins,
        suspicious_logins,
        unique_ips,
        unique_users
    ) = stats(logs)

    print_stats(
        logs,
        ip_stats,
        user_ips,
        user_attempts,
        total_logins,
        successful_logins,
        failed_logins,
        suspicious_logins,
        unique_ips,
        unique_users
    )


if __name__ == "__main__":
    main()