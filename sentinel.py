import os
import hashlib
import json
import datetime

class SentinelScanner:
    def __init__(self, db_path, log_path="scan_report.log"):
        self.db_path = db_path
        self.log_path = log_path
        self.signatures = self._load_signatures()
        # 啟發式分析規則集：可疑的字串與 API 呼叫特徵
        self.heuristic_rules = [
            b"CreateRemoteThread", 
            b"VirtualAllocEx", 
            b"WriteProcessMemory",
            b"SetWindowsHookEx"
        ]

    def _load_signatures(self):
        try:
            with open(self.db_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print("找不到特徵碼資料庫。")
            return {}

    def get_file_hashes(self, filepath):
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    md5_hash.update(byte_block)
                    sha256_hash.update(byte_block)
            return md5_hash.hexdigest(), sha256_hash.hexdigest()
        except (PermissionError, OSError) as e:
            print(f"無法讀取檔案 {filepath}: {e}")
            return None, None

    def heuristic_analysis(self, filepath):
        try:
            with open(filepath, "rb") as f:
                content = f.read(10240) # 只檢查檔案標頭與前段區塊
                for rule in self.heuristic_rules:
                    if rule in content:
                        return True, rule.decode('utf-8')
        except Exception:
            pass
        return False, None

    def log_alert(self, filepath, threat_name, threat_level, reason):
        """將受感染的路徑、威脅等級與時間戳記寫入日誌檔"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] ALERT: {filepath} | Threat: {threat_name} | Level: {threat_level} | Reason: {reason}\n"
        
        print(log_entry.strip())
        with open(self.log_path, "a", encoding="utf-8") as log_file:
            log_file.write(log_entry)

    def scan_directory(self, target_dir):
        print(f"開始掃描目錄: {target_dir}")
        for root, _, files in os.walk(target_dir):
            for file in files:
                filepath = os.path.join(root, file)
                md5_val, sha256_val = self.get_file_hashes(filepath)
                
                if not md5_val:
                    continue

                # 1. 特徵碼比對 (Signature-based)
                if md5_val in self.signatures:
                    info = self.signatures[md5_val]
                    self.log_alert(filepath, info['name'], info['threat_level'], "Signature Match (MD5)")
                    continue
                elif sha256_val in self.signatures:
                    info = self.signatures[sha256_val]
                    self.log_alert(filepath, info['name'], info['threat_level'], "Signature Match (SHA-256)")
                    continue
                
                # 2. 啟發式比對 (Heuristic Analysis)
                is_suspicious, api_call = self.heuristic_analysis(filepath)
                if is_suspicious:
                    self.log_alert(filepath, "Suspicious Behavior", "Medium", f"Unauthorized API/String found: {api_call}")

if __name__ == "__main__":
    scanner = SentinelScanner("signatures.json")
    scanner.scan_directory("./test_directory")
    print(f"掃描完成，詳細報告已儲存至 {scanner.log_path}")