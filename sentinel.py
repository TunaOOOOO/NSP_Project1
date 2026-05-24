# -*- coding: utf-8 -*-
import os
import sys
import hashlib
import json
import datetime
import threading
import time
import argparse
from typing import Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── 強制 stdout/stderr 使用 UTF-8（解決 Windows cp950 亂碼）──────────
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = open(sys.stdout.fileno(), mode="w", encoding="utf-8", buffering=1)
if sys.stderr.encoding and sys.stderr.encoding.lower() not in ("utf-8", "utf8"):
    sys.stderr = open(sys.stderr.fileno(), mode="w", encoding="utf-8", buffering=1)

# ─────────────────────────────────────────────────────────────────────
# ANSI 彩色輸出（自動啟用 Windows VT100）
# ─────────────────────────────────────────────────────────────────────
def _enable_windows_ansi():
    """在 Windows 上啟用 VT100 ANSI 序列支援。"""
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 0x0001 | 0x0004)
    except Exception:
        pass

_enable_windows_ansi()


class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    GREEN   = "\033[92m"
    MAGENTA = "\033[95m"
    GREY    = "\033[90m"
    WHITE   = "\033[97m"


# 威脅等級 → 顏色對應
LEVEL_COLORS = {
    "Critical": Colors.RED    + Colors.BOLD,
    "High":     Colors.RED,
    "Medium":   Colors.YELLOW,
    "Low":      Colors.CYAN,
    "Info":     Colors.GREY,
}


def colorize(text: str, color: str) -> str:
    """包裹 ANSI 色碼。"""
    return f"{color}{text}{Colors.RESET}"


def _progress_bar(completed: int, total: int, width: int = 30) -> str:
    """產生 ASCII 進度列字串（相容所有終端）。"""
    filled = int(width * completed / total)
    bar    = "#" * filled + "-" * (width - filled)
    pct    = completed / total * 100
    return f"[{bar}] {pct:5.1f}% ({completed}/{total})"


# ─────────────────────────────────────────────────────────────────────
# SentinelScanner
# ─────────────────────────────────────────────────────────────────────
class SentinelScanner:
    """
    多執行緒惡意程式掃描器。

    參數
    ----
    db_path    : 特徵碼資料庫 JSON 路徑
    log_path   : 掃描日誌輸出路徑
    max_workers: 並行執行緒數（預設 CPU 核心數 x2，適合 I/O-bound 任務）
    """

    # 可疑 Windows API 字串（啟發式規則）
    HEURISTIC_RULES: List[bytes] = [
        b"CreateRemoteThread",
        b"VirtualAllocEx",
        b"WriteProcessMemory",
        b"SetWindowsHookEx",
        b"NtCreateThreadEx",
        b"RtlCreateUserThread",
        b"ZwUnmapViewOfSection",
        b"IsDebuggerPresent",
    ]

    # 跳過啟發式分析的副檔名（媒體/壓縮檔，幾乎不含 PE 字串）
    SKIP_HEURISTIC_EXTENSIONS: Set[str] = {
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico",
        ".mp3", ".mp4", ".avi", ".mkv", ".mov",
        ".zip", ".gz", ".bz2", ".7z", ".rar",
        ".pdf", ".docx", ".xlsx", ".pptx",
    }

    # 超過此大小跳過啟發式分析（預設 50 MB）
    HEURISTIC_MAX_SIZE: int = 50 * 1024 * 1024

    def __init__(
        self,
        db_path: str,
        log_path: str = "scan_report.log",
        max_workers: int = None,
    ):
        self.db_path     = db_path
        self.log_path    = log_path
        self.max_workers = max_workers or (os.cpu_count() or 1) * 2
        self.signatures  = self._load_signatures()

        # 執行緒同步鎖
        self._log_lock   = threading.Lock()   # 保護 print + 日誌寫入
        self._stats_lock = threading.Lock()   # 保護統計計數器

        # 掃描統計
        self._stats = {
            "scanned": 0,
            "threats": 0,
            "errors":  0,
        }

    # ── 載入特徵碼資料庫 ──────────────────────────────────────────────
    def _load_signatures(self) -> dict:
        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                db = json.load(f)
            print(colorize(f"[*] 已載入特徵碼資料庫：{len(db)} 筆記錄", Colors.GREEN))
            return db
        except FileNotFoundError:
            print(colorize(f"[!] 找不到特徵碼資料庫：{self.db_path}", Colors.RED))
            return {}
        except json.JSONDecodeError as e:
            print(colorize(f"[!] 特徵碼資料庫格式錯誤：{e}", Colors.RED))
            return {}

    # ── 計算 MD5 + SHA-256（單次讀取，同步計算）──────────────────────
    def get_file_hashes(self, filepath: str) -> Tuple[Optional[str], Optional[str]]:
        md5_h    = hashlib.md5()
        sha256_h = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):  # 64 KB chunks
                    md5_h.update(chunk)
                    sha256_h.update(chunk)
            return md5_h.hexdigest(), sha256_h.hexdigest()
        except (PermissionError, OSError):
            return None, None

    # ── 啟發式分析 ────────────────────────────────────────────────────
    def heuristic_analysis(self, filepath: str) -> Tuple[bool, Optional[str]]:
        ext  = os.path.splitext(filepath)[1].lower()
        size = os.path.getsize(filepath)

        if ext in self.SKIP_HEURISTIC_EXTENSIONS:
            return False, None
        if size > self.HEURISTIC_MAX_SIZE:
            return False, None

        try:
            with open(filepath, "rb") as f:
                header = f.read(10240)  # 只讀取前 10 KB
            for rule in self.HEURISTIC_RULES:
                if rule in header:
                    return True, rule.decode("utf-8")
        except Exception:
            pass
        return False, None

    # ── 執行緒安全的警告日誌（含彩色輸出）───────────────────────────
    def log_alert(
        self,
        filepath: str,
        threat_name: str,
        threat_level: str,
        reason: str,
    ) -> None:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = (
            f"[{timestamp}] ALERT: {filepath} | "
            f"Threat: {threat_name} | Level: {threat_level} | Reason: {reason}\n"
        )

        level_color = LEVEL_COLORS.get(threat_level, Colors.WHITE)
        sep         = colorize("-" * 56, Colors.GREY)
        console_msg = (
            f"\n{sep}\n"
            f"  {colorize('[ALERT]', level_color)}  {filepath}\n"
            f"  {'Threat:':<10} {colorize(threat_name, level_color)}\n"
            f"  {'Level:':<10} {colorize(threat_level, level_color)}\n"
            f"  {'Reason:':<10} {reason}\n"
            f"{sep}"
        )

        with self._log_lock:
            # \r 清除進度列殘留，再印警告訊息
            print(f"\r{console_msg}")
            with open(self.log_path, "a", encoding="utf-8") as lf:
                lf.write(log_entry)

        with self._stats_lock:
            self._stats["threats"] += 1

    # ── 單一檔案完整掃描（由執行緒池呼叫）───────────────────────────
    def _scan_file(self, filepath: str) -> None:
        md5_val, sha256_val = self.get_file_hashes(filepath)

        with self._stats_lock:
            if md5_val is None:
                self._stats["errors"] += 1
                return
            self._stats["scanned"] += 1

        # 1. 特徵碼比對（MD5 優先，再比 SHA-256）
        if md5_val in self.signatures:
            info = self.signatures[md5_val]
            self.log_alert(filepath, info["name"], info["threat_level"], "Signature Match (MD5)")
            return

        if sha256_val in self.signatures:
            info = self.signatures[sha256_val]
            self.log_alert(filepath, info["name"], info["threat_level"], "Signature Match (SHA-256)")
            return

        # 2. 啟發式分析
        is_suspicious, api_call = self.heuristic_analysis(filepath)
        if is_suspicious:
            self.log_alert(
                filepath,
                "Suspicious Behavior",
                "Medium",
                f"Unauthorized API/String found: {api_call}",
            )

    # ── 主掃描入口 ────────────────────────────────────────────────────
    def scan_directory(self, target_dir: str) -> None:
        if not os.path.isdir(target_dir):
            print(colorize(f"[!] 目標目錄不存在：{target_dir}", Colors.RED))
            return

        # 遞迴收集所有檔案
        all_files: List[str] = []
        for root, _, files in os.walk(target_dir):
            for fname in files:
                all_files.append(os.path.join(root, fname))

        total = len(all_files)
        if total == 0:
            print(colorize("[*] 目錄內沒有任何檔案。", Colors.GREY))
            return

        print(colorize(
            f"[*] 開始掃描：{target_dir}  "
            f"(共 {total} 個檔案 | {self.max_workers} 個執行緒)",
            Colors.WHITE + Colors.BOLD,
        ))
        print(colorize("=" * 60, Colors.GREY))

        start_time = time.perf_counter()
        completed  = 0
        prog_lock  = threading.Lock()  # 進度列專用鎖（與 _log_lock 分開避免死鎖）

        def _task(fp: str) -> None:
            nonlocal completed
            self._scan_file(fp)
            with prog_lock:
                completed += 1
                bar = _progress_bar(completed, total)
                print(
                    f"\r  {colorize(bar, Colors.CYAN)}",
                    end="",
                    flush=True,
                )

        # 並行掃描
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(_task, fp): fp for fp in all_files}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    fp = futures[future]
                    with self._log_lock:
                        print(colorize(f"\n[!] 掃描 {fp} 時發生未預期錯誤：{exc}", Colors.RED))

        elapsed = time.perf_counter() - start_time
        s       = self._stats
        speed   = f"{s['scanned'] / elapsed:.1f} files/s" if elapsed > 0 else "N/A"

        # ── 掃描摘要 ──────────────────────────────────────────────────
        print(f"\n{colorize('=' * 60, Colors.GREY)}")
        print(colorize("  [ 掃描摘要 ]", Colors.WHITE + Colors.BOLD))
        print(colorize("-" * 60, Colors.GREY))
        print(f"  {'總掃描檔案':<14} {colorize(str(s['scanned']), Colors.WHITE)}")
        print(f"  {'發現威脅':<14} {colorize(str(s['threats']), Colors.RED if s['threats'] else Colors.GREEN)}")
        print(f"  {'讀取錯誤':<14} {colorize(str(s['errors']), Colors.YELLOW if s['errors'] else Colors.GREY)}")
        print(f"  {'執行時間':<14} {colorize(f'{elapsed:.3f} sec', Colors.CYAN)}")
        print(f"  {'掃描速度':<14} {colorize(speed, Colors.CYAN)}")
        print(colorize("=" * 60, Colors.GREY))
        if s["threats"] == 0:
            print(colorize("  [OK] 未發現任何威脅", Colors.GREEN + Colors.BOLD))
        else:
            print(colorize(
                f"  [!!] 發現 {s['threats']} 個威脅，詳情請查閱 {self.log_path}",
                Colors.RED + Colors.BOLD,
            ))
        print(colorize("=" * 60, Colors.GREY))


# ─────────────────────────────────────────────────────────────────────
# CLI 入口
# ─────────────────────────────────────────────────────────────────────
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel Scanner - 多執行緒惡意程式掃描工具",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-d", "--dir",
        default="./test_directory",
        metavar="PATH",
        help="要掃描的目標目錄路徑",
    )
    parser.add_argument(
        "--db",
        default="signatures.json",
        metavar="FILE",
        help="特徵碼資料庫 JSON 路徑",
    )
    parser.add_argument(
        "--log",
        default="scan_report.log",
        metavar="FILE",
        help="掃描日誌輸出路徑",
    )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=None,
        metavar="N",
        help="並行執行緒數（預設 CPU 核心數 x2）",
    )
    return parser


if __name__ == "__main__":
    args    = _build_parser().parse_args()
    scanner = SentinelScanner(
        db_path     = args.db,
        log_path    = args.log,
        max_workers = args.workers,
    )
    scanner.scan_directory(args.dir)