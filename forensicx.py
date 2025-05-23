# ForensicX - Advanced Digital Forensics Toolkit
# Built by Lunix Web (https://lunixweb.in)

import os
import hashlib
import socket
import psutil
import platform
import datetime
import json
import shutil
import time
import zipfile
from pathlib import Path
from PIL import ImageGrab
from fpdf import FPDF

# -------------------- CONFIG ----------------------
REPORT_DIR = Path("ForensicX_Report")
REPORT_JSON = REPORT_DIR / "forensics_report.json"
REPORT_PDF = REPORT_DIR / "forensics_report.pdf"
REPORT_ZIP = Path("ForensicX_Complete_Report.zip")
SCREENSHOT_FILE = REPORT_DIR / "screenshot.png"

# ------------------ HELPERS ----------------------
def hash_file(file_path):
    hashes = {'MD5': '', 'SHA1': '', 'SHA256': ''}
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            hashes['MD5'] = hashlib.md5(data).hexdigest()
            hashes['SHA1'] = hashlib.sha1(data).hexdigest()
            hashes['SHA256'] = hashlib.sha256(data).hexdigest()
    except:
        pass
    return hashes


def collect_system_info():
    info = {
        "hostname": socket.gethostname(),
        "platform": platform.system(),
        "platform-release": platform.release(),
        "platform-version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "ip-address": socket.gethostbyname(socket.gethostname()),
        "boot-time": str(datetime.datetime.fromtimestamp(psutil.boot_time()))
    }
    return info


def collect_running_processes():
    return [proc.info for proc in psutil.process_iter(['pid', 'name', 'username'])]


def collect_open_ports():
    return [{
        "local_address": str(conn.laddr),
        "remote_address": str(conn.raddr) if conn.raddr else '',
        "status": conn.status,
        "pid": conn.pid
    } for conn in psutil.net_connections(kind='inet') if conn.status]


def hash_important_files():
    targets = [
        os.environ.get("SystemRoot", "C:/Windows") + "/System32/drivers/etc/hosts",
        os.environ.get("SystemRoot", "C:/Windows") + "/System32/cmd.exe"
    ]
    return {path: hash_file(path) for path in targets if os.path.exists(path)}


def capture_screenshot():
    try:
        img = ImageGrab.grab()
        img.save(SCREENSHOT_FILE)
        return str(SCREENSHOT_FILE)
    except:
        return "Failed"


def collect_usb_history():
    usb_devices = []
    try:
        drives = [d.device for d in psutil.disk_partitions(all=True)]
        for d in drives:
            if 'removable' in d.lower() or 'usb' in d.lower():
                usb_devices.append(d)
    except:
        pass
    return usb_devices


def extract_browser_history():
    history = []
    try:
        history_path = Path(os.environ['USERPROFILE']) / 'AppData/Local/Google/Chrome/User Data/Default/History'
        if history_path.exists():
            history.append(f"Found Chrome History file at: {history_path}")
        else:
            history.append("Chrome History not found or unsupported browser.")
    except:
        history.append("Error reading browser history.")
    return history


def collect_ram_snapshot():
    snapshot = []
    try:
        for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
            mem = proc.info['memory_info'].rss / (1024 * 1024)
            snapshot.append({"pid": proc.info['pid'], "name": proc.info['name'], "memory_MB": round(mem, 2)})
    except:
        pass
    return snapshot


def save_json_report(data):
    REPORT_DIR.mkdir(exist_ok=True)
    with open(REPORT_JSON, 'w') as f:
        json.dump(data, f, indent=4)


def convert_to_pdf(data):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="ForensicX - Digital Forensics Report", ln=True, align='C')
    pdf.ln(10)
    for section, content in data.items():
        pdf.set_font("Arial", 'B', size=12)
        pdf.cell(200, 10, txt=section.upper(), ln=True)
        pdf.set_font("Arial", size=10)
        if isinstance(content, list):
            for item in content[:20]:
                pdf.multi_cell(0, 10, txt=str(item))
        else:
            pdf.multi_cell(0, 10, txt=json.dumps(content, indent=2))
        pdf.ln(5)
    pdf.output(str(REPORT_PDF))


def zip_report():
    with zipfile.ZipFile(REPORT_ZIP, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for file in REPORT_DIR.glob('*'):
            zipf.write(file, arcname=file.name)


def collect_all_artifacts():
    print("[+] Collecting forensic artifacts...")
    report = {
        "collected_at": str(datetime.datetime.now()),
        "system_info": collect_system_info(),
        "running_processes": collect_running_processes(),
        "open_ports": collect_open_ports(),
        "file_hashes": hash_important_files(),
        "usb_device_history": collect_usb_history(),
        "browser_history": extract_browser_history(),
        "ram_snapshot": collect_ram_snapshot(),
        "screenshot_file": capture_screenshot()
    }
    save_json_report(report)
    convert_to_pdf(report)
    zip_report()
    print(f"[+] JSON Report: {REPORT_JSON}")
    print(f"[+] PDF Report: {REPORT_PDF}")
    print(f"[+] Full ZIP Report: {REPORT_ZIP}")


if __name__ == "__main__":
    collect_all_artifacts()
