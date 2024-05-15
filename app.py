import re
import time 
import smtplib
import json
import subprocess
import urllib.request 
from email.message import EmailMessage

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def Send_Email(current_time:str, counter_fail:int, email_host_user:str, email_host_pass:str, target_addr:str):
    EMAIL_HOST          = 'smtp.gmail.com'
    EMAIL_HOST_USER     =  email_host_user
    EMAIL_HOST_PASSWORD =  email_host_pass           #App passwords
    EMAIL_PORT_SSL      = 465

    msg = EmailMessage()
    msg['Subject'] = 'The number of failed attempts to login into the Linux system(Severity:High)'
    msg['From']    =  EMAIL_HOST_USER
    msg['To']      =  target_addr
    msg.set_content(f'Number of failed logins: {counter_fail}, in this time: {current_time}')

    with smtplib.SMTP_SSL(EMAIL_HOST, EMAIL_PORT_SSL) as server:
        server.login(EMAIL_HOST_USER, EMAIL_HOST_PASSWORD)
        server.send_message(msg)

email_host_user = input(">> Please Enter your email host user: ")
email_host_pass = input(">> Enter app password: ")
target_addr     = input(">> Email Address target: ")

try:
    # Debian based systems
    fin = open("/var/log/auth.log", "r")    	
except FileNotFoundError:
    # Red Hat based systems
    fin = open("/var/log/secure", "r")		    

list_bad_ip = []

counter_fail = 0
counter_acce = 0

pattern_ipv4 = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

for line in fin:
    try:
        if re.findall("Failed password", line):
            # print(line.strip())
            counter_fail += 1

            bad_ips = re.findall(pattern_ipv4, line)
            
            for ip in bad_ips:
                if ip not in list_bad_ip:
                    list_bad_ip.extend([ip])
            
        elif re.findall("Accepted password", line):
            # print(line.strip())
            counter_acce += 1

    except Exception as e:
        print("Error:", e)
        print("Not found log success and failure login !!")
        exit()

print('-' * 40)

tm = time.time()
current_time = time.ctime(tm)
print("Date Time:", current_time)
print('-' * 40)

name_users  = "who | awk '{print $1}' | sort | uniq | tr '\n' ' ' "
count_users = "who | awk '{print $1}' | sort | uniq | wc -l"

output_name_users  = subprocess.run(name_users, shell=True, capture_output=True, text=True)
output_count_users = subprocess.run(count_users, shell=True, capture_output=True, text=True)

print("[x] Active Users:", output_name_users.stdout.strip())
print("[x] Count Active Users:", output_count_users.stdout.strip())
print('-' * 40)

print(bcolors.FAIL + "[x] Number of failed logins:", counter_fail)

for ip in list_bad_ip:
    try:
        u = urllib.request.urlopen(f"https://api.country.is/{ip}", timeout=10)
        ip_info = json.loads(str(u.read().decode('UTF-8')))
    
        cu = ip_info["country"]

    except urllib.error.HTTPError as err:
        if "404" in str(err):
            cu = "IP is unknown or IP appears to be private."
        else:
            cu = "Error!!"
            print(str(err))

    print(bcolors.WARNING + "[*] Bad IP:", ip, "=>", "Country:", cu)

print(bcolors.ENDC + ('-' * 40))
print(bcolors.OKCYAN + "[x] Number of accepted logins:", counter_acce)

print(bcolors.ENDC + ('-' * 40))

with open("failed-password-output.txt", "a") as file:
    file.write(("=" * 40) +
    f"\nDate Time: {current_time}\n" +
    ("=" * 40) + 
    f"\nActive Users: {output_name_users.stdout.strip()}\n" +
    f"Count Active Users: {output_count_users.stdout.strip()}\n" +
    f"Number of failed logins: {counter_fail}\n" +
    f"Number of accepted logins: {counter_acce}\n")
    
Send_Email(current_time, counter_fail, email_host_user, email_host_pass, target_addr)