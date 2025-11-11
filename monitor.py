#!/usr/bin/env python3
"""
monitor.py
SSH login monitor: deteksi login sukses & gagal.
Kirim notifikasi ke WhatsApp (Fonnte) dan minta analisis AI (Gemini 2.0 Flash).

Perubahan utama:
- Tambah print untuk login sukses agar muncul di console.
- Untuk percobaan gagal, gunakan AI "ringkas" (short prompt) untuk mengurangi kemungkinan timeout/429.
- Fungsi analyze_with_gemini sekarang melakukan retry + exponential backoff untuk 429/timeout.
- Jika AI tetap gagal setelah retry, return string error yang aman — WA tetap dikirim.
"""

import os
import re
import time
import requests
import json
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
NOTIFY_ON_SUCCESS = os.getenv("NOTIFY_ON_SUCCESS", "true").lower() in ("1", "true", "yes")
# ----------------------------------------- #

# Regex untuk detect login gagal & sukses
FAILED_RE = re.compile(
    r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)'
)
ACCEPTED_RE = re.compile(
    r'Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+)'
)

# ---------- Fungsi ---------- #


def send_whatsapp(message: str):
    """
    Kirim pesan WA via Fonnte API.
    Jika FONNTE_TOKEN atau FONNTE_DEVICE_NO tidak diset, hanya print warning.
    """
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
    """
    Kirim prompt ke Gemini dan kembalikan teks jawaban.
    - short=True => prompt lebih ringkas (gunakan untuk percobaan gagal)
    - Lakukan retry jika kena 429 atau timeout (exponential backoff)
    - Jika tetap gagal, kembalikan pesan error singkat supaya WA tetap dikirim.
    """
    if not GEMINI_API_KEY:
        return "(AI nonaktif: GEMINI_API_KEY tidak diset)"

    # Safety: jika short requested, trim prompt to a short summary if it's long
    if short:
        # make sure prompt is short (<= 300 chars)
        prompt = prompt_text
        if len(prompt) > 300:
            prompt = prompt[:300] + "..."
    else:
        prompt = prompt_text

    url = f"{GEMINI_ENDPOINT}?key={GEMINI_API_KEY}"
    payload = {"contents": [{"parts": [{"text": prompt}]}]}

    max_retries = 3
    for attempt in range(1, max_retries + 1):
        try:
            r = requests.post(url, headers={"Content-Type": "application/json"}, json=payload, timeout=10)
            r.raise_for_status()
            j = r.json()
            # Safely parse candidate text
            if "candidates" in j and len(j["candidates"]) > 0:
                try:
                    return j["candidates"][0]["content"]["parts"][0]["text"].strip()
                except Exception:
                    return "(AI error: response parsing failed)"
            return "(AI error: empty response)"
        except requests.exceptions.HTTPError as http_e:
            status = getattr(http_e.response, "status_code", None)
            # 429: Too Many Requests -> retry with backoff
            if status == 429:
                wait = attempt * 2
                print(f"[WARN] Gemini 429 Too Many Requests — retry {attempt}/{max_retries} after {wait}s")
                time.sleep(wait)
                continue
            # Other HTTP errors -> return message
            print(f"[ERROR] AI HTTP error: {http_e}")
            return f"(AI error: {http_e})"
        except requests.exceptions.Timeout:
            # timeout -> retry
            wait = attempt * 2
            print(f"[WARN] Gemini request timed out — retry {attempt}/{max_retries} after {wait}s")
            time.sleep(wait)
            continue
        except Exception as e:
            print(f"[ERROR] AI unexpected error: {e}")
            return f"(AI error: {e})"

    return "(AI error: request gagal setelah beberapa retry)"


def tail_file(path):
    """
    Baca file log secara realtime (tail -f) dan handle logrotate.
    """
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
                # detect logrotate
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

            # cleanup window
            cutoff = now - timedelta(minutes=WINDOW_MINUTES)
            attempts[ip] = [t for t in attempts[ip] if t >= cutoff]
            count = len(attempts[ip])

            # console log untuk debug
            print(f"[{now.isoformat()}] FAILED ip={ip} user={user} count={count}")

            if count >= THRESHOLD_ATTEMPTS:
                # message untuk WA (human readable)
                msg = (
                    f"🚨 Percobaan login SSH mencurigakan\n"
                    f"IP: {ip}\nUser: {user}\nJumlah percobaan: {count}"
                )

                # AI ringkas untuk percobaan gagal: pendek & terfokus
                ai_prompt = f"Ringkas: IP {ip}, user {user}, percobaan {count}"
                ai = analyze_with_gemini(ai_prompt, short=True)

                # send WA (AI result bisa berisi error string, tetap dikirim)
                send_whatsapp(msg + "\n\n🤖 Analisis AI:\n" + ai)

                # reset attempts untuk IP ini supaya tidak spam berulang
                attempts[ip] = []

            continue

        # ---- Login sukses ----
        m2 = ACCEPTED_RE.search(line)
        if m2 and NOTIFY_ON_SUCCESS:
            user, ip = m2.group(1), m2.group(2)

            # PRINT ke console agar terlihat (diminta)
            print(f"[{now.isoformat()}] SUCCESS ip={ip} user={user}")

            # message untuk WA
            msg = f"ℹ️ Login sukses\nUser: {user}\nIP: {ip}\nWaktu: {now.isoformat()}"

            # AI lengkap untuk login sukses (lebih detail)
            ai_prompt = (
                f"Anda berhasil login dengan informasi berikut:\n"
                f"- User: {user}\n"
                f"- IP: {ip}\n"
                f"- Waktu: {now.isoformat()}\n\n"
                "Buat analisis singkat terkait keamanan (apakah ini mencurigakan?) "
                "dan rekomendasi tindakan jika diperlukan."
            )

            ai = analyze_with_gemini(ai_prompt, short=False)

            send_whatsapp(msg + "\n\n🤖 Analisis AI:\n" + ai)


if __name__ == "__main__":
    main()


#tes ci/cd