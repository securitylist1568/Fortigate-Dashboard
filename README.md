# NTNU Fortigate-3001F 資安情資協防高階主管動態報表前臺 (`Fortigate-Dashboard`)

本儲存庫為 **國立臺灣師範大學（NTNU）資訊安全情資協防暨自動化縱深防禦體系** 之高階管理與督導稽核動態報表前臺，基於 **Next.js (App Router, Node.js Runtime)** 建置並部署於 **Vercel Cloud**。

---

## 🔗 三儲存庫職責分離架構 (Tri-Repository Architecture)

| 儲存庫名稱 | 角色與定位 | 寫入權限 | 說明 |
|---|---|---|---|
| [`securitylist1568/Fortigate`](https://github.com/securitylist1568/Fortigate) | FortiGate-3001F EDL 實體情資發布庫 | 僅 Kali Crontab 自動推送 | 存放 26 份純文字封鎖清單、白名單與治理清冊 |
| [`securitylist1568/Fortigate-Dev`](https://github.com/securitylist1568/Fortigate-Dev) | 自動化引擎原始碼與測試開發庫 | 開發人員與單元測試 | Python `v4.5` 與 `LongTerm v1.0.1` 腳本、驗證腳本 |
| [`securitylist1568/Fortigate-Dashboard`](https://github.com/securitylist1568/Fortigate-Dashboard) | 高階主管動態報表前臺 *(本儲存庫)* | **對上述兩庫 100% 唯讀（零寫入）** | 動態讀取 `Fortigate` 最新 Commit SHA 並產出加密彙總快照 |

---

## 🔐 核心資安與架構設計亮點 (v2.1 Audit Compliant)

1. **公開程式碼庫 ＋ 伺服器端 `AES-256-GCM` 安全金庫鎖定（Zero-Secret in Code）**：
   - 本儲存庫公開託管以利 **Vercel Free (Hobby)** 帳號直接連結部署，但**原始碼中絕不存放任何通行密鑰或明文數據**。
   - 後端 `/api/snapshot` 讀取 Vercel 環境變數 `VAULT_PASSKEY`，以 `SHA-256(passkey)` 衍生 256-bit 金鑰，將衍生統計 `Snapshot` JSON 執行 **`AES-256-GCM` 加密**後才回傳 `{ encrypted: true, iv, ciphertext }`。
   - 瀏覽器端未解鎖前一律顯示 `🔒 解鎖後顯示` 與 **Security Vault Unlock Modal**；支援輸入通行密鑰或點擊長官專屬 **1-Click 快捷授權連結（`?auth=<VAULT_PASSKEY>`）** 於瀏覽器透過 Web Crypto API 解密渲染，並支援右上角一鍵重新鎖定（`promptRelock`）。
2. **零機敏外洩契約（Zero-IP / Zero-Asset Leak）**：
   - 伺服器端完成去重聯集與重疊率計算後即刻釋放原始 IP 集合，產出之 `Snapshot` JSON **不含任何單一 IP、CIDR、MAC 或 FQDN 字串**，亦不提供 IP 查詢或內網資產下載連結。
3. **Commit SHA 釘住與 `<50 KB` 衍生快照快取**：
   - 透過 `GET /repos/securitylist1568/Fortigate/commits/main`（攜帶 `ETag` 條件請求，HTTP 304 不扣配額）取得最新 Commit SHA。
   - 僅當 SHA 變動時，才以不可變網址 `raw.githubusercontent.com/securitylist1568/Fortigate/<SHA>/<file>` 抓取清單計算統計並快取 `<50 KB` 的彙總快照（`revalidate = 300s`），徹底避開 CDN 分支快取延遲與 Next.js 2 MB 快取上限。

---

## 🚀 Vercel 部署與環境變數設定

於 Vercel 匯入 `securitylist1568/Fortigate-Dashboard` 後，請至 **Project Settings ➔ Environment Variables** 設定以下變數：

| 變數名稱 | 必填 | 說明 |
|---|:---:|---|
| `VAULT_PASSKEY` | ✅ | 安全金庫解鎖密鑰（用於伺服器端 `AES-256-GCM` 加密與 `?auth=` 1-Click 連結解鎖） |
| `GITHUB_TOKEN` | ✅ | GitHub Fine-Grained Read-Only Personal Access Token（公開 Repo 無須勾選特殊權限，將 API 限額提升至 5,000 次/小時） |
| `GITHUB_REPO` | 選填 | 預設為 `securitylist1568/Fortigate` |

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
