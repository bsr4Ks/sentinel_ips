import os
import sys
import time
import json
import sqlite3
import subprocess
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class SentinelHandler(FileSystemEventHandler):
    def __init__(self, log_path, db_path):
        self.whitelist = os.getenv("WHITELIST_IP", "").split(",")
        self.log_path = log_path
        self.db_path = db_path
        self.last_positions = {}
        self.init_db()
        super().__init__()

    def init_db(self):
        """SQLite veritabanını ve saldırı kayıt tablosunu hazırlar."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS bans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                event_id TEXT,
                timestamp TEXT,
                reason TEXT,
                raw_log TEXT
            )
        ''')
        conn.commit()
        conn.close()

    def ban_attacker(self, ip):
        """IP'yi Linux çekirdek seviyesinde (iptables) bloklar."""
        try:
            # Mükerrer banı önlemek için kontrol (Opsiyonel: iptables -C ile bakılabilir)
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            print(f"🛡️  [ACTION] {ip} çekirdek seviyesinde engellendi.")
        except Exception as e:
            print(f"❌ Ban Hatası ({ip}): {e}")

    def save_to_db(self, ip, event_id, reason, log_line):
        """Saldırı verisini kalıcı olarak veritabanına mühürler."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO bans (ip, event_id, timestamp, reason, raw_log) 
                VALUES (?, ?, ?, ?, ?)
            """, (ip, event_id, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), reason, log_line))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"❌ DB Kayıt Hatası: {e}")

    def on_modified(self, event):
        if not event.is_directory and "cowrie.json" in event.src_path:
            self.process_new_data(event.src_path)

    def process_new_data(self, file_path):
        current_size = os.path.getsize(file_path)
        last_pos = self.last_positions.get(file_path, 0)

        if current_size < last_pos:
            last_pos = 0 # Log rotation tespiti

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                f.seek(last_pos)
                new_lines = f.readlines()
                
                for line in new_lines:
                    if line.strip():
                        self.analyze_threat(line.strip())
                
                self.last_positions[file_path] = f.tell()
        except Exception as e:
            print(f"[!] Okuma hatası: {e}")

    def analyze_threat(self, log_line):
        try:
            data = json.loads(log_line)
            ip = data.get("src_ip")
            event_id = data.get("eventid")
            
            # Tehdit kriterleri: Bendi.py yükleme veya başarısız giriş
            reason = ""
            if "bendi.py" in str(data):
                reason = "Malware Upload (bendi.py)"
            elif event_id == "cowrie.login.failed":
                reason = "Brute Force Attempt"

            if reason:
                if ip in self.whitelist:
                    print(f"[-] Whitelisted IP detected ({ip}), skipping ban.")
                    return
                print(f"[{datetime.now().strftime('%H:%M:%S')}] ⚠️ Threat: {ip} | Reason: {reason}")
                self.ban_attacker(ip)
                self.save_to_db(ip, event_id, reason, log_line)
        except:
            pass

def main():
    load_dotenv()
    # Frankfurt sunucun için /var/lib/docker/volumes/... yolu
    path = os.getenv("PATH_PROD") if os.getenv("IS_PROD") == "True" else os.getenv("PATH_TEST")
    db_name = "sentinel_hits.db"

    if not os.path.isdir(path):
        print(f"❌ Error: Path {path} not found!")
        sys.exit(1)

    print(f"🚀 Sentinel-IPS Enforcer Started")
    print(f"📍 Monitoring: {path}")
    print(f"💾 Database: {os.path.abspath(db_name)}\n" + "-"*40)

    event_handler = SentinelHandler(path, db_name)
    observer = Observer()
    observer.schedule(event_handler, path, recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n👋 Sentinel-IPS stopped.")
    observer.join()

if __name__ == "__main__":
    main()