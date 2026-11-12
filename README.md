# 🛡️ 資安防護清單與威脅情資自動化更新系統 — 監控與查詢平台 (`Fortigate-Dashboard v2.5.0`)

本儲存庫（[`securitylist1568/Fortigate-Dashboard`](https://github.com/securitylist1568/Fortigate-Dashboard)）為**資安防護清單與威脅情資自動化更新系統**之視覺化管線監控、容量水位預警與全庫 `*.txt` 清單狀態即時查詢平台，基於 **Next.js 14 (App Router, Node.js Runtime)** 建置，並部署於 **Vercel Cloud**（線上網址：`https://fortigate-dashboard-tau.vercel.app/`）。

---

## 🏛️ 壹、三庫協同架構定位（Tri-Repository Architecture）

本系統採用「**開發庫、發布庫、監控查詢前臺**」三庫職責分離（Separation of Duties）架構：

| 儲存庫名稱 | 系統定位 | 核心職責與託管內容 | 資料讀寫權限 |
| :--- | :--- | :--- | :--- |
| **`Fortigate-Dev`** | 自動化引擎開發原始碼庫 | 託管 4 支核心 Python 自動化腳本（`v4.5`、`LongTerm v1.0.1`、`v2.1`）、共用模組 `ncloud_feed_utils.py`、歷史查詢工具 `query_ip_history.py` 與單元測試。 | 讀取日誌與外部 API ➔ 寫入 `Fortigate` |
| **`Fortigate`** | EDL 實體情資發布儲存庫 | 託管全部 **26 份** 防火牆 External Dynamic List (EDL) 清單檔案（**25 份 `*.txt`** 純文字檔 ＋ **1 份 `*.html`** DNS 阻斷警告頁）。供邊界防火牆定時讀取套用。 | 接收 `Fortigate-Dev` 自動推送 |
| **`Fortigate-Dashboard`** *(本庫)* | 資安情資監控與 IP 查詢平台 | 透過 GitHub API / Raw URL **純唯讀（Zero-Write）** 同步 `Fortigate` 最新 HEAD 與近 10 日滾動歷史，提供 `AES-256-GCM` 密文保護之視覺化監控與雙向 IP/網域查詢。 | **100% 純唯讀 (Read-Only)** |

---

## ✨ 貳、核心系統功能與架構設計（v2.5.0 現行規格）

### 1. 🏗️ 互動式三層系統架構圖與 CrossOver 技術規格檢視器
- **淺色高對比互動節點切換區**：將第 1 層（4 支 Python 排程引擎）、第 2 層（4 大類共 26 份 EDL 情資清單群）與第 3 層（邊界防火牆與本監控平台）設計為淺色選項卡片，並配置醒目的**琥珀橘金漸層大型向下流程箭頭（`⬇️ 往下同步流程` / `⬇️ 往下讀取與套用流程`）**。
- **CrossOver 動態檢視窗**：滑鼠移過（Hover）或點擊任一架構卡片，下方檢視窗即動態呈現該模組之 Crontab 排程時間、負責清單檔案（`*.txt`）與關鍵防呆機制；底層細節表格（雙庫對照表、`LongTerm v1.0.1` 參數與標頭規範）採可收合抽屜設計，確保版面清爽易讀。
- **全面採用台灣在地資安與工程慣用語**：統一使用「安全完整寫入」、「定時讀取」、「狀態紀錄檔／配額紀錄檔」、「剔除重複聯集」、「監控平台」等台灣自然用語，並去除不適用公家學術單位之商業字眼。

### 2. 🔍 全庫 25 份 `*.txt` ＋ 近 10 日滾動歷史雙向查詢工具（`/api/query-ip`）
- **高對比反白查詢主介面**：採用大型等寬粗體字型（`text-lg sm:text-xl font-mono`），支援單筆或多筆（空白/逗號分隔，單次最多 50 筆）**IPv4 位址、CIDR 子網段、FQDN 網域（含 `*.domain` 萬用字元）、主機註解關鍵字與 MAC 位址**檢索。
- **100% 原始檔名對齊與三大命中分類**：
  - **🔴 A1. 落在現行封鎖清單（HEAD `blockMatches`）**：精準列出所在 `Fortigate` 原始檔案名稱（如 `g-BLACK_IP_AutoLongTerm-v1.txt`、`emailsys_block_ipset.txt`、`g-NetworkDevices_Block-v1.txt`）、命中型態（精確 IP、32-bit CIDR 子網段涵蓋、萬用字元網域、MAC）、**檔案行號（Line Number）** 與 **`#註解` 內容**。
  - **🟠 A2. 落在近 10 日動態封鎖清單歷史（`historicalBlockMatches`）**：針對每日 `00:00` 自動歸零重算的 10 份動態清單（如 `ncloud_block_src_cert_remote.txt`、`ncloud_block_src_topn.txt` 等），自動建立過去 10 天每日收盤快照索引。即使某 IP（如 `104.16.102.112`）因當日歸零而不在今日最新 HEAD 中，仍能查出其過去 10 天最後出現之日期、Commit SHA 與當時行號，解決本機舊檔與雲端即時狀態之落差。
  - **🟢 B. 不在封鎖清單內 — 位於允許/網站/維護名單（`allowMatches`）**：精準定位並列舉位於全域允許清單、手動剔除清單或重要服務維護名單之行號與主機用途註解。

### 3. 🔐 公開儲存庫 ＋ 伺服器端 `AES-256-GCM` 零知識金庫（Zero-Secret in Code）
- 原始碼與公開網路傳輸中**絕不暴露任何明文統計或內網資產明細**。
- 後端 `/api/snapshot` 與 `/api/query-ip` 均讀取環境變數 `VAULT_PASSKEY`，以 `SHA-256` 衍生 256-bit 金鑰並執行 **`AES-256-GCM` 認證加密**（回傳 `{ encrypted: true, iv, ciphertext }`）。
- 前端內建簡潔之安全金庫驗證視窗（已移除外部人員申請密鑰入口，僅供授權人員輸入密鑰或透過 `?auth=` 參數解鎖），於瀏覽器端透過 Web Crypto API 解密。

### 4. ⚡ Vercel 配額保護與邊緣快取架構（v2.5.0 Quota-Safe Architecture）
為確保在 **Vercel Hobby 免費方案（每月 `10 GB` Fast Origin Transfer 上限）** 下穩定運作且絕不超額：
1. **Edge CDN 密文快取轉移（將 99% 流量轉移至免費 `100 GB` Fast Data Transfer）**：
   - 由於 API 回傳皆為 `AES-256-GCM` 密文，`/api/snapshot` 設置 `Cache-Control: public, max-age=60, s-maxage=180, stale-while-revalidate=600`；`/api/query-ip`（`GET`）設置 `s-maxage=300, stale-while-revalidate=600`。
   - 實測 `X-Vercel-Cache: HIT` 達 99% 以上，3 分鐘內無論多少人訪問，Origin Serverless Function 僅需執行 1 次。
2. **前端單次初始化鎖定與查詢結果記憶（Client Memoization）**：
   - 透過 `hasInitializedRef` 與 `encryptedPayloadRef` 切斷 React `useEffect` 重複請求迴圈，並移除 `?t=Date.now()` 破快取參數；同一工作階段重複查詢相同 IP 由前端 `ipQueryCacheRef` 直接秒回。
3. **10 日歷史索引按需載入（Lazy On-Demand Historical Index）**：
   - 僅當查詢目標在現行 HEAD 未命中任何封鎖清單時，才按需載入過去 10 日歷史索引，且快取週期延長為 **2 小時（7,200 秒）**。
4. **靜態圖示與爬蟲檔長效快取**：
   - 內建輕量級 [`src/app/icon.svg`](file:///d:/NTNU-DevOps/Gitbash/Fortigate-Dashboard/src/app/icon.svg)（`296 Bytes`）並為 `favicon.ico` / `icon.svg` / `robots.txt` 配置 `s-maxage=604800, immutable`（7 天快取），消除 `404` 快取穿透。

---

## 📂 參、全庫 26 份監控與檢索清單對照表（`src/lib/feeds.manifest.ts`）

本系統 `src/lib/feeds.manifest.ts` 與來源儲存庫 `Fortigate` 保持 **100% 原始檔名對齊**：

| 類別 | 檔案數量 | 對應 `Fortigate` 原始檔案名稱 (`*.txt` / `*.html`) | 產生腳本 / 維護方式 |
| :--- | :---: | :--- | :--- |
| **🔴 外部威脅 IP 封鎖清單 (`ext_ip`)** | **10 份** | 自動化長期黑名單、人工維護黑名單、外部威脅種子、CERT 外部情資與 6 份流量異常偵測清單 (`*.txt`) | `longterm`、`topn`、`ntech`、人工維護 |
| **📧 郵件與惡意網域封鎖 (`fqdn_mail`)** | **5 份** | 郵件閘道 CIDR 封鎖集、郵件惡意網域、CERT 惡意網域、DNS FQDN 封鎖清單与阻斷警告頁 (`*.txt` / `*.html`) | `emailsys`、`ntech`、人工維護 |
| **🖥️ 內部設備封鎖控管 (`internal`)** | **4 份** | 內部 IoT、網通設備、伺服器群對外連線與特定設備存取控管清單 | 內部微隔離控管（人工造冊維護） |
| **✅ 允許清單與服務維護 (`allow`)** | **7 份** | 全域實體允許清單、長期黑名單手動剔除清單與重要網路服務維護清冊 | 全域防誤封白名單與服務維護清冊 |

---

## 📜 肆、完整改版歷程與版本演進表（Version History & Changelog）

| 版本號 | 日期 | Git Commit | 改版核心主題 | 關鍵推進成果與解決問題 |
| :---: | :---: | :---: | :--- | :--- |
| **v2.1.0** | 2026-11-06 | `0cdf9f1` ~ `ae4cd0c` | **初版建置、組織去識別化與 Vercel 建置穩定化** | 建立 Next.js 14 + `AES-256-GCM` 安全金庫基礎架構；移除所有敏感組織與內網識別字眼；配置 `next.config.mjs` 確保 Vercel 零錯誤高速建置。 |
| **v2.2.0** | 2026-11-10 | `0818947` | **對齊 `Fortigate` 架構圖、政府學研用語改造與 IP 查詢器上線** | 1. 新增對應 `Fortigate/README.md` 之三層式系統架構與腳本規格表。<br>2. 移除「高階管理摘要報告」等商業用語，改為適合學研/政府機關之資安治理表述。<br>3. 首度實作 `/api/query-ip` 加密 IP/CIDR 封鎖狀態查詢器。 |
| **v2.3.0** | 2026-11-10 | `0384b15` | **淺色功能選項導覽列與全庫 25 份 `*.txt` 100% 原始檔名雙向比對** | 1. 將中間「🧭 功能選項切換區」改為淺色高對比漸層背景，明確凸顯可點擊選項。<br>2. 廢除前臺自訂別名，100% 採用 `Fortigate` 原始 `*.txt` 檔名，並支援 **Case A（在封鎖清單）** 與 **Case B（不在封鎖清單，如正式/學術網站與維運清單）** 行號與 `#註解` 定位。 |
| **v2.3.8** | 2026-11-10 | `689a95d` | **互動式 CrossOver 架構檢視窗與近 10 日動態封鎖清單歷史回溯** | 1. 將架構圖改為清爽卡片＋「🔍 CrossOver 技術規格檢視窗」，滑鼠移過即動態顯示細節，消除文字擁擠感。<br>2. 新增 `ensureHistoricalDynamicIndex()` 近 10 日滾動歷史索引，解決如 `ncloud_block_src_cert_remote.txt` 內 IP（`104.16.102.112`）於每日 `00:00` 歸零後查無紀錄之問題（歸類於 **A2. 近 10 日動態封鎖清單歷史**）。 |
| **v2.4.1** | 2026-11-11 | `03f00ba` ~ `852c781` | **架構圖淺色化＋大箭頭流程、高對比反白大字體查詢框、金庫介面精簡與台灣慣用語全面校正** | 1. 系統架構圖套用與功能選項區一致之淺色主題，並將層間連接器升級為**醒目琥珀橘金向下大箭頭流程**。<br>2. 移除查詢頁多餘之白色測試範例框，將「🔍 查詢主介面」升級為反白高對比大字體輸入框。<br>3. 移除解鎖視窗中之「申請密鑰 / 1-Click 授權說明」區塊。<br>4. 全面將大陸用語（原子寫入、拉取、台帳、看板、去重）替換為台灣自然慣用語。 |
| **v2.5.0** | 2026-11-11 | `37f5941` ~ `85ffe77` | **Vercel Fast Origin Transfer 配額優化與 Edge CDN 快取止血架構** | 1. 修復 `page.tsx` 之 `useEffect` 依賴重複請求迴圈並移除 `?t=Date.now()`。<br>2. 為 `/api/snapshot`（`s-maxage=180`）與 `GET /api/query-ip`（`s-maxage=300`）啟用 Vercel Edge CDN 密文快取，實測 `X-Vercel-Cache: HIT`，將 99% 流量轉移至免費 100GB `Fast Data Transfer`。<br>3. 將 10 日歷史索引改為按需載入（2 小時快取），並補齊靜態 `icon.svg` 消除 `404` 流量消耗。 |

---

## 🔄 伍、未來滾動式開發與變更管理規範（Rolling Development SOP）

為確保後續專案管理與改版有所依循，任何後續調整請遵循以下標準作業程序：

1. **清單檔案異動同步（Feed Manifest Sync）**：
   - 當上游 `Fortigate` 儲存庫新增、刪除或更名任何 `*.txt` 清單時，必須同步更新本庫之 [`src/lib/feeds.manifest.ts`](file:///d:/NTNU-DevOps/Gitbash/Fortigate-Dashboard/src/lib/feeds.manifest.ts)，確保 `file` 與 `displayName` 100% 對齊原始檔名。
2. **Vercel 配額安全紅線（Quota Guardrails）**：
   - **嚴禁**在前端 `fetch('/api/snapshot')` 加入動態時間戳（如 `?t=Date.now()`）或 `cache: 'no-store'`。
   - **嚴禁**移除 [`src/app/api/snapshot/route.ts`](file:///d:/NTNU-DevOps/Gitbash/Fortigate-Dashboard/src/app/api/snapshot/route.ts) 與 [`src/app/api/query-ip/route.ts`](file:///d:/NTNU-DevOps/Gitbash/Fortigate-Dashboard/src/app/api/query-ip/route.ts) 的 `s-maxage` 與 `stale-while-revalidate` 標頭，確保所有公開讀取皆由 Edge CDN 快取吸收。
3. **文案與術語一致性（Terminology Standard）**：
   - 所有新增 UI 文字一律採用繁體中文（台灣慣用語），避免大陸技術詞彙（如：使用「安全完整寫入」而非「原子寫入」、使用「讀取/同步」而非「拉取」、使用「紀錄檔」而非「台帳」、使用「剔除重複」而非「去重」）。
4. **改版紀錄留存**：
   - 每次完成小版本（如 `v2.5.x` / `v2.6.0`）推進後，應同步於本 `README.md` 之「肆、完整改版歷程與版本演進表」及對應之 HTML 專案管理報告追加紀錄。

---

## 🚀 陸、Vercel 部署與本地開發指令

### 環境變數設定（Vercel Project Settings ➔ Environment Variables）

| 變數名稱 | 必填 | 說明 |
| :--- | :---: | :--- |
| `VAULT_PASSKEY` | ✅ | 安全金庫解鎖密鑰（用於伺服器端 `AES-256-GCM` 密文加密與瀏覽器端解密驗證） |
| `GITHUB_TOKEN` | ✅ | GitHub Fine-Grained Read-Only Personal Access Token（將上游 API 限額提升至 5,000 次/小時） |
| `GITHUB_REPO` | 選填 | 目標情資發布儲存庫（預設為 `securitylist1568/Fortigate`） |

### 本地啟動與建置驗證

```bash
# 1. 安裝相依套件
npm install

# 2. 建立本地環境變數 (.env.local)
cp .env.example .env.local

# 3. 啟動開發伺服器 (http://localhost:3000)
npm run dev

# 4. 執行正式環境建置檢查
npm run build
```
