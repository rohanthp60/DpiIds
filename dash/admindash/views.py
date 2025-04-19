from django.shortcuts import render
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
import subprocess
import json
import re

detectorRunning = False
detector = None
snort_process = None
dpi_detector = None
cpu_usage = None

def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('home')
        else:
            return render(request, 'login.html', {'error': 'Invalid username or password'})
    else:
        return render(request, 'login.html')

@login_required
def home_view(request):
    global detectorRunning
    context = {'detectorRunning': detectorRunning}
    return render(request, 'home.html', context)

def log_out(request):
    logout(request)
    return redirect('login')

def toggle_detector(request):
    global detectorRunning
    global detector
    global snort_process
    global dpi_detector
    global cpu_usage
    password = "rohan20603"
    snort_command = "sudo snort -A fast -q -c /etc/snort/snort.conf -r /home/vm3/Codes/DpiIds/snort_fifo.pcap"
    detector_command = 'sudo go run /home/vm3/Codes/DpiIds/snortFilter.go'
    dpi_command = 'sudo go run /home/vm3/Codes/DpiIds/dpi.go'
    cpu_usage_command = 'sudo go run /home/vm3/Codes/DpiIds/cpuUtil.go'
    if detectorRunning:
        snort_process.kill()
        detector.kill()
        dpi_detector.kill()
        cpu_usage.kill()
        detectorRunning = False
    else:
        subprocess.run("rm /home/vm3/Codes/DpiIds/snort_fifo.pcap", shell=True)
        subprocess.run("mkfifo /home/vm3/Codes/DpiIds/snort_fifo.pcap", shell=True)
        detector = subprocess.Popen(f"echo {password} | sudo -S {detector_command}", shell=True)
        snort_process = subprocess.Popen(f"echo {password} | sudo -S {snort_command}", shell=True)
        dpi_detector = subprocess.Popen(f"echo {password} | sudo -S {dpi_command}", shell=True)
        cpu_usage = subprocess.Popen(f"echo {password} | sudo -S {cpu_usage_command}", shell=True)
        detectorRunning = True
    return redirect('home')

def netowrk_usage(request):
    jsonFilePath = "/tmp/network_usage.json"
    with open(jsonFilePath, "r") as file:
        data = json.load(file)
    
    return render(request, 'network_usage.html', {'data': data})

def dpi_alerts(request):
    dpi_alerts_path = "/home/vm3/Codes/DpiIds/threat_log.txt"
    with open(dpi_alerts_path, "r") as file:
        data = file.read()
    alerts = data.strip().split('\n\n')
    parsed_alerts = []
    for alert in alerts:
        alert_dict = {}
        timestamp_match = re.search(r'\[(.*?)\]', alert)
        threat_level_match = re.search(r'\((.*?)\)', alert)
        ips_match = re.findall(r'IP: (\d+\.\d+\.\d+\.\d+)', alert)

        if timestamp_match:
            alert_dict['timestamp'] = timestamp_match.group(1)
        if threat_level_match:
            alert_dict['threat_level'] = threat_level_match.group(1)
        if len(ips_match) == 2:
            alert_dict['source_ip'] = ips_match[0]
            alert_dict['destination_ip'] = ips_match[1]

        parsed_alerts.append(alert_dict)
    alerts = parsed_alerts
    return render(request, 'dpi_alerts.html', {'alerts': alerts})


def snort_alerts(request):
    snort_alerts_path = "/var/log/snort/alert"
    
    with open(snort_alerts_path, "r") as file:
        lines = file.readlines()

    parsed_alerts = []
    
    for line in lines:
        alert_dict = {
            "timestamp": "NA",
            "sid": "NA",
            "attack_type": "NA",
            "priority": "NA",
            "source_ip": "NA",
            "destination_ip": "NA"
        }

        # Extract timestamp
        timestamp_match = re.search(r'(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d{6})', line)
        if timestamp_match:
            alert_dict["timestamp"] = timestamp_match.group(1)

        # Extract SID and attack type
        attack_type_match = re.search(r'\[\*\*\] \[(\d+:\d+:\d+)\] (.*?) \[\*\*\]', line)
        if attack_type_match:
            alert_dict["sid"] = attack_type_match.group(1)
            alert_dict["attack_type"] = attack_type_match.group(2)

        # Extract priority
        priority_match = re.search(r'\[Priority: (\d+)\]', line)
        if priority_match:
            alert_dict["priority"] = priority_match.group(1)

        # Extract source and destination IPs
        ips_match = re.findall(r'(\d+\.\d+\.\d+\.\d+):\d+', line)
        if len(ips_match) == 2:
            alert_dict["source_ip"] = ips_match[0]
            alert_dict["destination_ip"] = ips_match[1]
        


        parsed_alerts.append(alert_dict)

    return render(request, 'snort_alerts.html', {'alerts': parsed_alerts})
