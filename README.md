# NSP Project 1: Sentinel Scanner

## 專案介紹 (Introduction)
Sentinel Scanner 是一個基於 Python 的簡易防護與惡意程式掃描工具。它透過計算檔案的雜湊值並比對特徵碼資料庫，以及進行基礎的啟發式分析（尋找可疑的 API 呼叫字串），來偵測指定目錄中的潛在威脅。此專案作為網路安全實務 (Network Security Practice, NSP) 課程的專題，用於演示現代防毒軟體的核心檢測機制。

## 主要功能 (Features)

1. **特徵碼比對掃描 (Signature-based Scanning)**：
   - 支援 MD5 與 SHA-256 檔案雜湊值的計算與比對。
   - 透過外部的 `signatures.json` 載入惡意程式的特徵碼資料庫（例如：EICAR 測試檔案、模擬勒索軟體等）。
2. **啟發式分析 (Heuristic Analysis)**：
   - 檢查檔案內容（標頭與前段區塊）是否包含常被惡意程式濫用的 Windows API 呼叫字串，例如：
     - `CreateRemoteThread`
     - `VirtualAllocEx`
     - `WriteProcessMemory`
     - `SetWindowsHookEx`
3. **詳細的掃描日誌記錄 (Detailed Logging)**：
   - 發現威脅時，即時在終端機發出警告。
   - 自動將掃描結果（包含時間戳記、受感染檔案路徑、威脅名稱與等級）寫入 `scan_report.log` 以供後續稽核。

## 專案檔案結構 (Project Structure)

```text
.
├── sentinel.py          # 掃描器主要核心程式碼
├── signatures.json      # 惡意程式特徵碼 JSON 資料庫
├── test_directory/      # 用於測試掃描功能的樣本檔案目錄（包含 EICAR 與模擬惡意行為的檔案）
├── .gitignore           # Git 忽略清單（排除快取、本地設定與掃描日誌）
└── README.md            # 專案說明文件
```
*(註：`scan_report.log` 會在程式執行後自動產生)*

## 系統需求 (Prerequisites)
- Python 3.6 或更新版本（僅依賴內建標準函式庫 `os`, `hashlib`, `json`, `datetime`，無須額外安裝套件）。

## 使用說明 (Usage)

1. **準備環境**：確認目錄中存在 `signatures.json` 與 `test_directory`。
2. **執行掃描**：
   打開終端機，移動到專案根目錄，執行以下指令開始掃描：
   ```bash
   python sentinel.py
   ```
3. **查看掃描報告**：
   程式執行完畢後，可以在專案目錄下打開 `scan_report.log` 查看所有被標記為威脅的詳細記錄。

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

## 開發者與授權
本專案為 NYCU NSP (網路安全實務) 課程作業。
