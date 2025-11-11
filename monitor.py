#!/usr/bin/env python3
"""
monitor.py
SSH login monitor: deteksi login sukses & gagal.
Kirim notifikasi ke WhatsApp (Fonnte) dan minta analisis AI (Gemini 2.0 Flash).
"""

import os
import re
import time
import requests
import json
from datetime import datetime, timedelta, timezone
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
NOTIFY_ON_SUCCESS = os.getenv("NOTIFY_ON_SUCCESS", "true").lower() in ("1", "true", "yes")
# ----------------------------------------- #

# Regex untuk deteksi login gagal & sukses
FAILED_RE = re.compile(
    r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)'
)
ACCEPTED_RE = re.compile(
    r'Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+)'
)


# ---------- Fungsi Utility ---------- #

def format_wita():
    wita = timezone(timedelta(hours=8))
    now = datetime.now(wita)
    return now.strftime("%d %B %Y, %H:%M:%S") + " WITA"


def send_whatsapp(message: str):
    """Kirim pesan WA via Fonnte API."""
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


def analyze_with_gemini(prompt_text: str, short: bool = False) -> str:
    """Kirim prompt ke Gemini dan kembalikan hasil teks analisis."""
    if not GEMINI_API_KEY:
        return "(AI nonaktif: GEMINI_API_KEY tidak diset)"

    prompt = prompt_text[:300] + "..." if short and len(prompt_text) > 300 else prompt_text
    url = f"{GEMINI_ENDPOINT}?key={GEMINI_API_KEY}"
    payload = {"contents": [{"parts": [{"text": prompt}]}]}

    max_retries = 3
    for attempt in range(1, max_retries + 1):
        try:
            r = requests.post(url, headers={"Content-Type": "application/json"}, json=payload, timeout=10)
            r.raise_for_status()
            j = r.json()
            if "candidates" in j and len(j["candidates"]) > 0:
                return j["candidates"][0]["content"]["parts"][0]["text"].strip()
            return "(AI error: empty response)"
        except requests.exceptions.Timeout:
            print(f"[WARN] Gemini timeout, retry {attempt}/3")
            time.sleep(attempt * 2)
            continue
        except Exception as e:
            return f"(AI error: {e})"
    return "(AI error: request gagal setelah beberapa retry)"


def tail_file(path):
    """Pantau file log seperti `tail -f` dan handle logrotate."""
    f = open(path, "r")
    f.seek(0, 2)
    inode = os.fstat(f.fileno()).st_ino
    while True:
        line = f.readline()
        if line:
            yield line
        else:
            time.sleep(0.5)
            try:
                if os.stat(path).st_ino != inode:
                    f.close()
                    f = open(path, "r")
                    inode = os.fstat(f.fileno()).st_ino
                    f.seek(0, 2)
            except Exception:
                pass


# ---------- Main Program ---------- #

def main():
    print("[INFO] Mulai monitoring:", LOG_PATH)
    tail = tail_file(LOG_PATH)
    attempts = defaultdict(list)

    for line in tail:
        now = datetime.utcnow()
        waktu_str = format_wita()

        # ---- Login gagal ----
        m = FAILED_RE.search(line)
        if m:
            user, ip = m.group(1), m.group(2)
            attempts[ip].append(now)

            # Hapus percobaan lama
            cutoff = now - timedelta(minutes=WINDOW_MINUTES)
            attempts[ip] = [t for t in attempts[ip] if t >= cutoff]
            count = len(attempts[ip])

            print(f"[{waktu_str}] FAILED ip={ip} user={user} count={count}")

            if count >= THRESHOLD_ATTEMPTS:
                msg = (
                    f"🚨 Percobaan login SSH mencurigakan\n"
                    f"IP: {ip}\nUser: {user}\nJumlah percobaan: {count}\n"
                    f"Waktu: {waktu_str}"
                )
                ai_prompt = f"Analisis singkat percobaan login mencurigakan dari IP {ip}, user {user}, {count} kali."
                ai = analyze_with_gemini(ai_prompt, short=True)
                send_whatsapp(msg + "\n\n🤖 Analisis AI:\n" + ai)
                attempts[ip] = []
            continue

        # ---- Login sukses ----
        m2 = ACCEPTED_RE.search(line)
        if m2 and NOTIFY_ON_SUCCESS:
            user, ip = m2.group(1), m2.group(2)
            print(f"[{waktu_str}] SUCCESS ip={ip} user={user}")

            msg = (
                f"ℹ️ Login sukses\n"
                f"User: {user}\n"
                f"IP: {ip}\n"
                f"Waktu: {waktu_str}"
            )
            ai_prompt = (
                f"Anda berhasil login dengan informasi berikut:\n"
                f"- User: {user}\n"
                f"- IP: {ip}\n"
                f"- Waktu: {waktu_str}\n\n"
                "Buat analisis keamanan singkat dan rekomendasi jika diperlukan."
            )
            ai = analyze_with_gemini(ai_prompt, short=False)
            send_whatsapp(msg + "\n\n🤖 Analisis AI:\n" + ai)


if __name__ == "__main__":
    main()
