import pytest
from login_stats import load_logs, stats, print_stats


def test_load_logs_valid_file(tmp_path):
    csv_file = tmp_path / "logs.csv"
    csv_file.write_text(
        "ip,username,time,status\n"
        "192.168.1.10,banu,10:30,SUCCESS\n"
        "192.168.1.10,banu,10:35,FAILED\n",
        encoding="utf-8"
    )

    logs = load_logs(str(csv_file))

    assert len(logs) == 2
    assert logs[0]["ip"] == "192.168.1.10"
    assert logs[0]["username"] == "banu"
    assert logs[0]["status"] == "SUCCESS"


def test_load_logs_invalid_status(tmp_path):
    csv_file = tmp_path / "logs.csv"
    csv_file.write_text(
        "ip,username,time,status\n"
        "192.168.1.10,banu,10:30,INVALID\n",
        encoding="utf-8"
    )

    with pytest.raises(SystemExit):
        load_logs(str(csv_file))


def test_load_logs_invalid_ip(tmp_path):
    csv_file = tmp_path / "logs.csv"
    csv_file.write_text(
        "ip,username,time,status\n"
        "not_an_ip,banu,10:30,SUCCESS\n",
        encoding="utf-8"
    )

    with pytest.raises(SystemExit):
        load_logs(str(csv_file))


def test_stats():
    logs = [
        {
            "ip": "192.168.1.10",
            "username": "banu",
            "time": "10:30",
            "status": "SUCCESS"
        },
        {
            "ip": "192.168.1.10",
            "username": "banu",
            "time": "10:35",
            "status": "FAILED"
        },
        {
            "ip": "10.0.0.5",
            "username": "ali",
            "time": "02:15",
            "status": "FAILED"
        }
    ]

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

    assert total_logins == 3
    assert successful_logins == 1
    assert failed_logins == 2
    assert suspicious_logins == 1
    assert unique_ips == 2
    assert unique_users == 2

    assert ip_stats["192.168.1.10"]["attempts"] == 2
    assert ip_stats["192.168.1.10"]["success"] == 1
    assert ip_stats["192.168.1.10"]["failed"] == 1

    assert user_ips["banu"]["total_attempts"] == 2
    assert user_attempts["banu"] == 2


def test_stats_detects_unusual_time():
    logs = [
        {
            "ip": "192.168.1.20",
            "username": "banu",
            "time": "03:00",
            "status": "SUCCESS"
        }
    ]

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

    assert suspicious_logins == 1
    assert ip_stats["192.168.1.20"]["suspicious"] == 1
    assert user_ips["banu"]["suspicious"] == 0


def test_print_stats(capsys):
    logs = [
        {
            "ip": "192.168.1.10",
            "username": "banu",
            "time": "10:30",
            "status": "SUCCESS"
        }
    ]

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

    output = capsys.readouterr().out

    assert "LOGIN STATISTICS:" in output
    assert "Total logins: 1" in output
    assert "Successful logins: 1" in output
    assert "Failed logins: 0" in output
    assert "Unique IPs: 1" in output
    assert "Unique users: 1" in output
    assert "SUSPICIOUS USERS:" in output
    assert "None" in output
