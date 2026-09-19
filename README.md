Suspicious Login Detector
Video URL: https://youtube.com/shorts/tqA2YNpkKBw?si=vUbPFxNjFw_fbM5l
Description

Suspicious Login Detector is a Python program that reads login records from a CSV file and analyzes them for potentially suspicious activity.

The program validates the input data, calculates login statistics, and reports suspicious users and IP addresses.

Input format

The CSV file must contain these four columns:

ip

username

time

status

The status value must be either SUCCESS or FAILED.

The time must use the HH:MM format.

Example:

ip,username,time,status
192.168.1.10,banu,10:30,SUCCESS
192.168.1.10,banu,10:35,FAILED
10.0.0.5,ali,02:15,FAILED

Validation

The program checks:

whether the file exists

whether all required columns are present

whether rows contain missing information

whether the login status is valid

whether IP addresses are valid

whether times use the correct HH:MM format

Statistics

The program calculates:

total logins

successful logins

failed logins

suspicious logins

unique IP addresses

unique users

attempts per IP

successful and failed attempts per IP

usernames associated with each IP

IP addresses associated with each user

total, successful, and failed attempts per user

Suspicious activity detection

The program reports several types of suspicious activity.

Unusual login time

A login is considered suspicious when it occurs before 07:00 or after 23:00.

This is reported as:

LEVEL: LOW

More than 3 failed attempts

A user or IP address with more than 3 failed attempts is reported as:

LEVEL: MEDIUM

More than 2 IP addresses

A user connected to more than 2 IP addresses is reported as:

LEVEL: HIGH

More than 3 usernames

An IP address associated with more than 3 usernames is reported as:

LEVEL: HIGH

Three failed attempts followed by a successful login

The program checks for the same username and IP address having three consecutive failed logins followed by a successful login.

This is reported as:

LEVEL: HIGH

Running the program

Place login_stats.py and your CSV file in the same directory.

Run:

python3 login_stats.py logs.csv

The program prints the statistics and suspicious activity to the terminal.

Running the tests

Install pytest if necessary:

pip install pytest

Then run:

pytest

The tests in test_project.py check the input validation, statistics calculations, unusual login-time detection, and printed output.

Files

login_stats.py — main Python program

test_project.py — pytest tests

logs.csv - example file

README.md — project documentation

The project uses separate functions for loading and validating logs, calculating statistics, and printing the results. The main() function connects these parts together and accepts the CSV filename from the command line.
