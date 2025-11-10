#!/usr/bin/env python3
"""
monitor.py
SSH login monitor: deteksi login sukses & gagal.
Kirim notifikasi ke WhatsApp (Fonnte) dan minta analisis AI (Gemini 2.0 Flash).
"""

import os, re, time, requests, json
from datetime import datetime, timedelta
from collections import defaultdict

# ---------------- CONFIG ---------------- #
LOG_PATH = os.getenv("LOG_PATH", "/var/log/auth.log")

# Deteksi brute-force: window waktu & threshold
WINDOW_MINUTES = int(os.getenv("WINDOW_MINUTES", "5"))
THRESHOLD_ATTEMPTS = int(os.getenv("THRESHOLD_ATTEMPTS", "5"))

# API keys
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_ENDPOINT = os.getenv(
    "GEMINI_ENDPOINT",
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"
)

FONNTE_TOKEN = os.getenv("FONNTE_TOKEN")
FONNTE_API = os.getenv("FONNTE_API", "https://api.fonnte.com/send")
FONNTE_DEVICE_NO = os.getenv("FONNTE_DEVICE_NO")

# Notifikasi login sukses
NOTIFY_ON_SUCCESS = os.getenv("NOTIFY_ON_SUCCESS", "true").lower() in ("1","true","yes")
# ----------------------------------------- #

# Regex untuk detect login gagal & sukses
FAILED_RE = re.compile(r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)')
ACCEPTED_RE = re.compile(r'Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+)')

# ---------- Fungsi ---------- #

def send_whatsapp(message: str):
    if not FONNTE_TOKEN or not FONNTE_DEVICE_NO:
        print("[WARN] Fonnte token/device belum dikonfigurasikan.")
        return False
    try:
        headers = {"Authorization": FONNTE_TOKEN, "Content-Type": "application/json"}
        payload = {"target": FONNTE_DEVICE_NO, "message": message}
        r = requests.post(FONNTE_API, headers=headers, json=payload, timeout=10)
        print(f"[FONNTE] status={r.status_code}")
        return r.ok
    except Exception as e:
        print("[ERROR] gagal kirim WA:", e)
        return False

def analyze_with_gemini(prompt_text: str) -> str:
    if not GEMINI_API_KEY:
        return "(AI nonaktif: GEMINI_API_KEY tidak diset)"
    try:
        payload = {"contents": [{"parts": [{"text": prompt_text}]}]}
        url = f"{GEMINI_ENDPOINT}?key={GEMINI_API_KEY}"
        r = requests.post(url, headers={"Content-Type": "application/json"}, json=payload, timeout=10)
        r.raise_for_status()
        j = r.json()
        return j["candidates"][0]["content"]["parts"][0]["text"].strip()
    except Exception as e:
        return f"(AI error: {e})"

def tail_file(path):
    f = open(path, "r")
    f.seek(0, 2)  # mulai dari akhir file
    inode = None
    while True:
        line = f.readline()
        if line:
            yield line
        else:
            time.sleep(0.5)
            try:
                if inode is None:
                    inode = os.fstat(f.fileno()).st_ino
                if os.stat(path).st_ino != inode:
                    f.close()
                    f = open(path, "r")
                    inode = os.fstat(f.fileno()).st_ino
                    f.seek(0, 2)
            except Exception:
                pass

def main():
    print("[INFO] Mulai monitoring:", LOG_PATH)

    tail = tail_file(LOG_PATH)
    attempts = defaultdict(list)

    for line in tail:
        now = datetime.utcnow()

        # ---- Login gagal ----
        m = FAILED_RE.search(line)
        if m:
            user, ip = m.group(1), m.group(2)
            attempts[ip].append(now)
            cutoff = now - timedelta(minutes=WINDOW_MINUTES)
            attempts[ip] = [t for t in attempts[ip] if t >= cutoff]
            count = len(attempts[ip])
            print(f"[{now.isoformat()}] FAILED ip={ip} user={user} count={count}")

            if count >= THRESHOLD_ATTEMPTS:
                msg = (f"🚨 Percobaan login SSH mencurigakan\n"
                       f"IP: {ip}\nUser: {user}\nJumlah percobaan: {count}")
                ai = analyze_with_gemini(msg)
                send_whatsapp(msg + "\n\n🤖 Analisis AI:\n" + ai)
                attempts[ip] = []

            continue

        # ---- Login sukses ----
        m2 = ACCEPTED_RE.search(line)
        if m2 and NOTIFY_ON_SUCCESS:
            user, ip = m2.group(1), m2.group(2)
            msg = f"ℹ️ Login sukses\nUser: {user}\nIP: {ip}\nWaktu: {now.isoformat()}"
            ai = analyze_with_gemini(msg)
            send_whatsapp(msg + "\n\n🤖 Analisis AI:\n" + ai)

if __name__ == "__main__":
    main()
