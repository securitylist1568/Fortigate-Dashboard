# 資安防護清單與威脅情資自動化更新系統 (`CTI Automated Threat Feeds & Defense System v2.2`)

本儲存庫為**資安防護清單與威脅情資自動化更新系統**之視覺化監控與 IP 封鎖狀態查詢前臺，基於 **Next.js (App Router, Node.js Runtime)** 建置並部署於 **Vercel Cloud**。

---

## 🔐 核心資安、架構對齊與加密查詢設計 (v2.2)

1. **完整對齊情資庫系統架構與腳本規格**：
   - 內建視覺化三層式「系統架構與自動化資料流向圖」（自動化排程主機 4 支腳本 ➔ 原子狀態/額度台帳與白名單過濾 ➔ EDL 情資發布庫 ➔ 邊界防火牆套用規則）。
   - 完整呈現「雙儲存庫職責對照表」、「4 支腳本功能與產出清單對照表」及「`LongTerm v1.0.1` 關鍵參數（`TTL_DAYS=30`、10天跨≥3日 OR AbuseIPDB）、產生標頭規範與六大工程特性」。
2. **伺服器端記憶體索引之「🔍 IP 封鎖狀態即時查詢器」**：
   - 提供 `/api/query-ip` 加密端點，支援單一或多個 IPv4 批次檢索（`< 1 ms` 毫秒級回應，零額外 GitHub API 額度消耗）。
   - 同時支援**精確 IP 比對**、**32-bit 子網遮罩 CIDR 網段包含檢測（如郵件閘道封鎖網段）**及**全域白名單 / 長期黑名單手動剔除清單保護狀態檢查**，並可一鍵複製本地 `python query_ip_history.py` 7 天深度歷史查詢指令。
3. **公開程式碼庫 ＋ 伺服器端 `AES-256-GCM` 安全金庫鎖定（Zero-Secret in Code）**：
   - 本儲存庫公開託管以利 **Vercel Free (Hobby)** 帳號直接連結部署，但**原始碼中絕不存放任何通行密鑰或明文數據**。
   - 後端 `/api/snapshot` 與 `/api/query-ip` 均讀取 Vercel 環境變數 `VAULT_PASSKEY`，以 `SHA-256(passkey)` 衍生 256-bit 金鑰，執行 **`AES-256-GCM` 加密**後才回傳 `{ encrypted: true, iv, ciphertext }`。
   - 瀏覽器端未解鎖前一律顯示 `🔒 解鎖後顯示` 與 **Security Vault Unlock Modal**；支援輸入通行密鑰或點擊專屬 **1-Click 快捷授權連結（`?auth=<VAULT_PASSKEY>`）** 解密，並支援右上角一鍵重新鎖定（`promptRelock`）。
4. **Commit SHA 釘住與 `<50 KB` 衍生快照快取**：
   - 透過 GitHub Commits API（攜帶 `ETag` 條件請求，HTTP 304 不扣配額）取得最新 Commit SHA。
   - 僅當 SHA 變動時，才以不可變 Commit SHA 網址抓取清單計算統計並快取 `<50 KB` 的彙總快照（`revalidate = 300s`），徹底避開 CDN 分支快取延遲與 Next.js 2 MB 快取上限。

---

## 🚀 Vercel 部署與環境變數設定

於 Vercel 匯入本專案後，請至 **Project Settings ➔ Environment Variables** 設定以下變數：

| 變數名稱 | 必填 | 說明 |
|---|:---:|---|
| `VAULT_PASSKEY` | ✅ | 安全金庫解鎖密鑰（用於伺服器端 `AES-256-GCM` 加密與 `?auth=` 1-Click 連結解鎖） |
| `GITHUB_TOKEN` | ✅ | GitHub Fine-Grained Read-Only Personal Access Token（將 API 限額提升至 5,000 次/小時） |
| `GITHUB_REPO` | 選填 | 目標情資發布庫（`owner/repo`） |

---

## 🧪 本地開發與測試

```bash
# 1. 安裝依賴
npm install

# 2. 建立本地環境變數 (.env.local)
cp .env.example .env.local

# 3. 執行單元測試 (Vitest)
npm test

# 4. 啟動開發伺服器
npm run dev
```
