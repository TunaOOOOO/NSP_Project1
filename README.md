# NSP Project 1: Sentinel Scanner

## 專案介紹 (Introduction)
Sentinel Scanner 是一個基於 Python 的多執行緒防護與惡意程式掃描工具。它透過計算檔案的雜湊值並比對特徵碼資料庫，以及進行基礎的啟發式分析（尋找可疑的 Windows API 呼叫字串），來偵測指定目錄中的潛在威脅。此專案作為網路安全實務 (Network Security Practice, NSP) 課程的專題，用於演示現代防毒軟體的核心檢測機制。

## 主要功能 (Features)

1. **多執行緒掃描 (Multi-threaded Scanning)**：
   - 使用 `concurrent.futures.ThreadPoolExecutor` 並行處理多個檔案，顯著提升大量檔案時的掃描速度。
   - 執行緒數量預設為 CPU 核心數 × 2（適合 I/O-bound 任務），可透過 CLI 參數調整。

2. **特徵碼比對掃描 (Signature-based Scanning)**：
   - 支援 MD5 與 SHA-256 檔案雜湊值的計算與比對（單次讀取，同步計算兩種雜湊）。
   - 透過外部的 `signatures.json` 載入惡意程式的特徵碼資料庫。

3. **啟發式分析 (Heuristic Analysis)**：
   - 檢查檔案標頭區塊（前 10 KB）是否包含常被惡意程式濫用的 Windows API 呼叫字串：
     - `CreateRemoteThread`, `VirtualAllocEx`, `WriteProcessMemory`, `SetWindowsHookEx`
     - `NtCreateThreadEx`, `RtlCreateUserThread`, `ZwUnmapViewOfSection`, `IsDebuggerPresent`
   - 自動跳過媒體/壓縮檔副檔名與超過 50 MB 的大型檔案，節省資源。

4. **執行緒安全日誌記錄 (Thread-safe Logging)**：
   - 以 `threading.Lock` 保護日誌寫入，確保多執行緒環境下不發生 race condition。
   - 發現威脅時即時顯示彩色警告（ANSI 色碼，Windows VT100 自動啟用）。
   - 自動將掃描結果寫入 `scan_report.log`。

5. **即時進度顯示 & 掃描摘要 (Progress & Summary)**：
   - 掃描過程中顯示即時 ASCII 進度列。
   - 掃描結束後輸出統計摘要（總掃描數、威脅數、錯誤數、執行時間、掃描速度）。

6. **CLI 參數支援 (CLI Arguments)**：
   - 透過命令列參數靈活控制掃描行為（詳見使用說明）。

## 專案檔案結構 (Project Structure)

```text
.
├── sentinel.py          # 掃描器主要核心程式碼
├── signatures.json      # 惡意程式特徵碼 JSON 資料庫
├── test_directory/      # 用於測試掃描功能的樣本檔案目錄
├── .gitignore           # Git 忽略清單
└── README.md            # 專案說明文件
```
*(註：`scan_report.log` 會在程式執行後自動產生)*

## 系統需求 (Prerequisites)
- Python 3.6 或更新版本（僅依賴標準函式庫 `os`, `sys`, `hashlib`, `json`, `datetime`, `threading`, `time`, `argparse`, `concurrent.futures`，無須額外安裝套件）。

## 使用說明 (Usage)

### 快速執行（使用預設值）
```bash
python sentinel.py
```
預設掃描 `./test_directory`，使用 CPU 核心數 × 2 個執行緒。

### CLI 參數

| 參數 | 縮寫 | 預設值 | 說明 |
|------|------|--------|------|
| `--dir` | `-d` | `./test_directory` | 要掃描的目標目錄路徑 |
| `--db` | — | `signatures.json` | 特徵碼資料庫 JSON 路徑 |
| `--log` | — | `scan_report.log` | 掃描日誌輸出路徑 |
| `--workers` | `-w` | CPU 核心數 × 2 | 並行執行緒數 |

### 範例

```bash
# 掃描自訂目錄，使用 8 個執行緒
python sentinel.py --dir C:\Users\user\Downloads -w 8

# 指定自訂特徵碼庫與日誌路徑
python sentinel.py --dir ./target --db my_signatures.json --log results.log

# 顯示說明
python sentinel.py --help
```

## 特徵碼資料庫格式
`signatures.json` 使用鍵值對 (Key-Value) 格式，Key 為檔案的 MD5 或 SHA-256 雜湊值，Value 則包含威脅的詳細資訊：
```json
{
    "44d88612fea8a8f36de82e1278abb02f": {
        "name": "EICAR-Standard-Antivirus-Test-File",
        "type": "Mock Virus",
        "threat_level": "Low"
    }
}
```

