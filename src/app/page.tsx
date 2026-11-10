'use client';

import React, { useEffect, useState, useCallback } from 'react';
import type {
  DashboardSnapshot,
  FeedCategory,
  LongTermTrendPoint,
  IpQueryResponsePayload,
} from '@/lib/types';
import type { EncryptedVaultPayload } from '@/lib/vault-crypto';

const SESSION_STORAGE_KEY = 'cti_defense_vault_key';

function base64ToUint8Array(base64: string): Uint8Array {
  const binaryString = window.atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

async function deriveWebCryptoKey(passkey: string): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const hashBuffer = await window.crypto.subtle.digest(
    'SHA-256',
    enc.encode(passkey.trim())
  );
  return await window.crypto.subtle.importKey(
    'raw',
    hashBuffer,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );
}

async function decryptVaultPayloadClient<T = DashboardSnapshot>(
  encObj: EncryptedVaultPayload,
  passkey: string
): Promise<T> {
  const cryptoKey = await deriveWebCryptoKey(passkey);
  const iv = base64ToUint8Array(encObj.iv);
  const ciphertext = base64ToUint8Array(encObj.ciphertext);
  const decryptedBuf = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as BufferSource, tagLength: 128 },
    cryptoKey,
    ciphertext as BufferSource
  );
  const dec = new TextDecoder('utf-8');
  return JSON.parse(dec.decode(decryptedBuf)) as T;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const kb = bytes / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB`;
  return `${(kb / 1024).toFixed(2)} MB`;
}

export default function ThreatDefenseDashboardPage() {
  const [encryptedPayload, setEncryptedPayload] =
    useState<EncryptedVaultPayload | null>(null);
  const [snapshot, setSnapshot] = useState<DashboardSnapshot | null>(null);
  const [isUnlocked, setIsUnlocked] = useState<boolean>(false);
  const [showVaultModal, setShowVaultModal] = useState<boolean>(true);
  const [showApplyModal, setShowApplyModal] = useState<boolean>(false);

  const [passInput, setPassInput] = useState<string>('');
  const [showPassText, setShowPassText] = useState<boolean>(false);
  const [vaultError, setVaultError] = useState<string | null>(null);
  const [loadingApi, setLoadingApi] = useState<boolean>(true);
  const [serverError, setServerError] = useState<string | null>(null);

  // Interactive UI states
  const [activeTab, setActiveTab] = useState<
    'overview' | 'ip_lookup' | 'trend' | 'inventory' | 'compliance' | 'methodology'
  >('overview');
  const [chartMode, setChartMode] = useState<'cumulative' | 'added'>('cumulative');
  const [selectedPoint, setSelectedPoint] = useState<LongTermTrendPoint | null>(
    null
  );
  const [selectedCategory, setSelectedCategory] = useState<'all' | FeedCategory>(
    'all'
  );

  // IP Block Status Lookup states
  const [ipQueryInput, setIpQueryInput] = useState<string>('');
  const [ipQueryResult, setIpQueryResult] =
    useState<IpQueryResponsePayload | null>(null);
  const [ipQueryLoading, setIpQueryLoading] = useState<boolean>(false);
  const [ipQueryError, setIpQueryError] = useState<string | null>(null);
  const [copiedCmd, setCopiedCmd] = useState<boolean>(false);

  // Interactive Architecture Crossover Inspector states (v2.3.8)
  const [activeArchNode, setActiveArchNode] = useState<string>('script_topn');
  const [showTechDeepDive, setShowTechDeepDive] = useState<boolean>(false);

  const fetchEncryptedSnapshot = useCallback(async () => {
    setLoadingApi(true);
    setServerError(null);
    try {
      const res = await fetch('/api/snapshot?t=' + Date.now(), {
        cache: 'no-store',
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || `HTTP ${res.status}`);
      }
      setEncryptedPayload(data as EncryptedVaultPayload);
      return data as EncryptedVaultPayload;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setServerError(msg);
      return null;
    } finally {
      setLoadingApi(false);
    }
  }, []);

  const attemptUnlockWithKey = useCallback(
    async (
      key: string,
      payloadToUse?: EncryptedVaultPayload | null,
      fromSession: boolean = false
    ) => {
      const trimmed = key.trim();
      if (!trimmed) {
        setVaultError('⚠️ 請輸入金庫通行密鑰 (Passkey)！');
        return false;
      }

      try {
        const targetPayload =
          payloadToUse ?? encryptedPayload ?? (await fetchEncryptedSnapshot());
        if (!targetPayload) {
          setVaultError('⚠️ 無法取得伺服器加密快照，請確認環境變數設定。');
          return false;
        }

        const dec = await decryptVaultPayloadClient(targetPayload, trimmed);
        sessionStorage.setItem(SESSION_STORAGE_KEY, trimmed);
        setSnapshot(dec);
        if (dec.longTermTrend.points.length > 0) {
          setSelectedPoint(
            dec.longTermTrend.points[dec.longTermTrend.points.length - 1]
          );
        }
        setIsUnlocked(true);
        setShowVaultModal(false);
        setVaultError(null);
        return true;
      } catch {
        sessionStorage.removeItem(SESSION_STORAGE_KEY);
        setIsUnlocked(false);
        setShowVaultModal(true);
        setVaultError(
          fromSession
            ? '⚠️ 先前儲存之通行密鑰已失效或變更，請重新輸入！'
            : '⚠️ 通行密鑰錯誤，無法解密資安情資金庫，請重新確認！'
        );
        return false;
      }
    },
    [encryptedPayload, fetchEncryptedSnapshot]
  );

  useEffect(() => {
    (async () => {
      // Check URL 1-Click parameters (?auth=, ?key=, ?token=) just like finance-free-xq-pub
      const urlParams = new URLSearchParams(window.location.search);
      const urlToken =
        urlParams.get('auth') || urlParams.get('key') || urlParams.get('token');

      if (urlToken && urlToken.trim()) {
        sessionStorage.setItem(SESSION_STORAGE_KEY, urlToken.trim());
        urlParams.delete('auth');
        urlParams.delete('key');
        urlParams.delete('token');
        const newQuery = urlParams.toString() ? '?' + urlParams.toString() : '';
        window.history.replaceState(
          {},
          document.title,
          window.location.pathname + newQuery + window.location.hash
        );
      }

      const savedKey = sessionStorage.getItem(SESSION_STORAGE_KEY);
      const payload = await fetchEncryptedSnapshot();

      if (savedKey && payload) {
        await attemptUnlockWithKey(savedKey, payload, true);
      } else {
        setShowVaultModal(true);
      }
    })();
  }, [fetchEncryptedSnapshot, attemptUnlockWithKey]);

  const handlePromptRelock = () => {
    if (isUnlocked) {
      if (
        window.confirm(
          '是否要重新鎖定資安情資金庫？\n鎖定後將清除本機暫存金鑰並隱藏所有統計數據。'
        )
      ) {
        sessionStorage.removeItem(SESSION_STORAGE_KEY);
        setSnapshot(null);
        setIsUnlocked(false);
        setPassInput('');
        setVaultError(null);
        setShowVaultModal(true);
      }
    } else {
      setShowVaultModal(true);
    }
  };

  const scrollToMethodology = () => {
    setActiveTab('methodology');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleQueryIps = async (customInput?: string) => {
    const targetText = (customInput ?? ipQueryInput).trim();
    if (!targetText) {
      setIpQueryError('⚠️ 請先輸入至少一個要查詢的 IPv4 位址！');
      return;
    }
    const savedKey = sessionStorage.getItem(SESSION_STORAGE_KEY);
    if (!isUnlocked || !savedKey) {
      setShowVaultModal(true);
      return;
    }

    setIpQueryLoading(true);
    setIpQueryError(null);
    try {
      const res = await fetch('/api/query-ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ queryText: targetText }),
        cache: 'no-store',
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || `HTTP ${res.status}`);
      }
      const decrypted = await decryptVaultPayloadClient<IpQueryResponsePayload>(
        data as EncryptedVaultPayload,
        savedKey
      );
      setIpQueryResult(decrypted);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setIpQueryError(`查詢失敗：${msg}`);
    } finally {
      setIpQueryLoading(false);
    }
  };

  const handleCopyLocalCmd = (ips: string[]) => {
    const validIps = ips.filter((x) => x.trim().length > 0).join(' ');
    const cmd = `python query_ip_history.py ${validIps || '<IP>'} --days 7`;
    if (navigator.clipboard) {
      navigator.clipboard.writeText(cmd);
      setCopiedCmd(true);
      setTimeout(() => setCopiedCmd(false), 2000);
    }
  };

  const filteredFeeds =
    snapshot?.feeds.filter((f) =>
      selectedCategory === 'all' ? true : f.category === selectedCategory
    ) ?? [];

  const allHealthy =
    snapshot?.pipelineHealth.every((h) => h.status === 'healthy') ?? false;

  return (
    <div className="min-h-screen pb-16">
      {/* Top Technical Notice Strip */}
      <aside className="bg-slate-900/90 border-b border-slate-800 px-4 py-2 text-xs text-slate-300">
        <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="text-amber-400 font-bold">🛡️ 系統統計聲明：</span>
            <span>
              <strong>本頁呈現「防護清單規模（Feed Inventory Size）」，而非「防火牆實際攔截封包次數（Traffic Hits）」。</strong>
              全量統計快照與 IP 查詢均經伺服器端 <code>AES-256-GCM</code> 加密傳輸，且嚴格排除任何敏感組織識別與內網資產明細。
            </span>
          </div>
          <span className="font-mono text-sky-400">
            Automated Threat Feeds &amp; Defense System v2.3.8
          </span>
        </div>
      </aside>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 pt-6 space-y-6">
        {/* Stale Fallback Warning Banner */}
        {isUnlocked && snapshot?.isStaleFallback && (
          <div className="rounded-xl bg-amber-500/20 border border-amber-400/50 p-4 text-amber-200 text-sm flex items-center justify-between gap-4">
            <div>
              <strong>⚠️ 資料時效過時警示（Stale Snapshot Fallback）：</strong>{' '}
              {snapshot.staleReason}
            </div>
            <span className="font-mono text-xs whitespace-nowrap">
              最後成功快照：{snapshot.fetchedAtDisplay}
            </span>
          </div>
        )}

        {/* System Header Container */}
        <header className="glass-panel p-6">
          <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-800 pb-5">
            <div className="space-y-2">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sky-500/15 border border-sky-400/30 text-sky-300 text-xs font-semibold">
                <span>🛡️ 資安威脅情資與自動化封鎖清單監控平台</span>
                <span>•</span>
                <span>EDL Threat Feeds 動態發布系統 (v2.3.8)</span>
              </div>
              <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight bg-gradient-to-r from-white via-sky-200 to-sky-400 bg-clip-text text-transparent">
                資安防護清單與威脅情資自動化更新系統
              </h1>
              <p className="text-xs sm:text-sm text-slate-400">
                架構模式：<code>雙儲存庫職責分離（開發原始碼庫 ↔ EDL 情資發布庫）</code> ｜ 執行機制：
                <strong className="text-slate-200">Crontab 錯峰排程 (Asia/Taipei) + 狀態/額度台帳原子寫入 + Git Auto Push</strong>
              </p>
            </div>

            {/* Meta Status Pills */}
            <div className="flex flex-wrap items-center gap-2.5">
              <button
                type="button"
                onClick={() => setActiveTab('ip_lookup')}
                className="glass-card px-3.5 py-2 flex flex-col items-start cursor-pointer border-sky-500/40 bg-sky-500/10 hover:bg-sky-500/20 transition-all"
              >
                <span className="text-[11px] text-sky-300">快速檢索工具</span>
                <span className="mt-0.5 inline-flex items-center gap-1 text-xs font-bold text-white">
                  🔍 查詢 IP 是否被封鎖 →
                </span>
              </button>

              <button
                type="button"
                onClick={handlePromptRelock}
                title={
                  isUnlocked
                    ? '已通過金庫驗證 · 點擊可重新鎖定'
                    : '點擊輸入通行密鑰解鎖系統'
                }
                className="glass-card px-3.5 py-2 flex flex-col items-start cursor-pointer hover:border-sky-400/50"
              >
                <span className="text-[11px] text-slate-400">安全金庫狀態</span>
                <span
                  className={`mt-0.5 inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-bold border ${
                    isUnlocked
                      ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                      : 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                  }`}
                >
                  {isUnlocked ? '🔐 金庫已解鎖' : '🔒 金庫未解鎖'}
                </span>
              </button>

              <div className="glass-card px-3.5 py-2 flex flex-col items-start">
                <span className="text-[11px] text-slate-400">
                  最新情資同步版本 (Asia/Taipei)
                </span>
                <span className="mt-0.5 text-xs font-mono font-bold text-slate-100">
                  {isUnlocked && snapshot
                    ? `${snapshot.headTimeDisplay} (${snapshot.shortHeadSha})`
                    : '🔒 解鎖後顯示'}
                </span>
              </div>

              <div className="glass-card px-3.5 py-2 flex flex-col items-start">
                <span className="text-[11px] text-slate-400">自動化管線健康度</span>
                <span
                  className={`mt-0.5 inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-bold ${
                    !isUnlocked
                      ? 'bg-slate-700 text-slate-300'
                      : allHealthy
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                      : 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                  }`}
                >
                  {isUnlocked
                    ? allHealthy
                      ? '🟢 4 支排程全數正常'
                      : '🟡 部分引擎逾時關注'
                    : '🔒 解鎖後顯示'}
                </span>
              </div>
            </div>
          </div>

          {/* System Introduction Callout (Directly aligned with Fortigate/README.md) */}
          <div className="mt-5 p-4 rounded-xl bg-slate-900/70 border border-slate-800 text-xs sm:text-sm leading-relaxed text-slate-300">
            <div className="font-bold text-white mb-1 flex flex-wrap items-center justify-between gap-2">
              <span>📘 系統簡介與運作機制（System Overview）</span>
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => setActiveTab('ip_lookup')}
                  className="text-xs text-emerald-400 hover:underline font-semibold"
                >
                  🔍 進入 IP 封鎖狀態查詢器 →
                </button>
                <button
                  type="button"
                  onClick={scrollToMethodology}
                  className="text-xs text-sky-400 hover:underline font-normal"
                >
                  📖 檢視指標計算公式與資料來源說明 →
                </button>
              </div>
            </div>
            <p>
              本系統透過部署於自動化排程主機上的 Python 腳本（獨立託管於
              <strong className="text-sky-300">「開發原始碼庫」</strong>），定期經由{' '}
              <strong className="text-white">Crontab 錯峰排程</strong> 執行，自動分析
              <strong className="text-sky-300">「郵件系統封鎖統計」、「CERT 外部聯防情資」、「骨幹流量 Top-N 異常行為」與「跨日重複犯案 ∪ AbuseIPDB 全球高信賴黑名單」</strong>，產出並 Git Push 同步至
              <strong className="text-emerald-300">「EDL 實體情資發布庫」</strong>，專責提供邊界防火牆{' '}
              <strong>External Dynamic List (EDL / Threat Feeds)</strong> 讀取套用封鎖規則，並彙整所有 IP 封鎖清單、FQDN 網域封鎖清單、內部設備存取控制清單與 DNS 封鎖警告訊息頁面。
              {isUnlocked && snapshot ? (
                <>
                  {' '}截至最新同步時間（<code>{snapshot.headTimeDisplay}</code>），全庫共維運{' '}
                  <strong className="text-emerald-300">{snapshot.totalFeedsCount} 份清單</strong>，其中去重後唯一外部封鎖 IPv4 達{' '}
                  <strong className="text-emerald-300">
                    {snapshot.uniqueExternalBlockIPv4.toLocaleString()} 筆
                  </strong>
                  （含自動化長期黑名單{' '}
                  <strong className="text-sky-300">
                    {snapshot.capacity.longTermCount.toLocaleString()} 筆
                  </strong>
                  ），受保護白名單與內部微隔離控管項目共{' '}
                  <strong className="text-amber-300">
                    {snapshot.protectedAndInternalEntries.toLocaleString()} 筆
                  </strong>
                  ，累計留存{' '}
                  <strong className="text-white">
                    {snapshot.totalCommitsCount.toLocaleString()} 次
                  </strong>{' '}
                  Git 版本異動紀錄。
                </>
              ) : (
                <span className="text-amber-300 font-semibold ml-1">
                  （請先解鎖安全金庫以檢視即時統計數據與使用 IP 查詢功能）
                </span>
              )}
            </p>
          </div>

          {/* 5 Top-Level Governance KPIs */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 mt-5">
            <div className="glass-card p-4 border-l-4 border-l-sky-400">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>外部封鎖唯一 IPv4 (去重聯集)</span>
                <button
                  type="button"
                  onClick={scrollToMethodology}
                  className="text-sky-400 hover:underline"
                >
                  [定義]
                </button>
              </div>
              <div className="text-2xl font-extrabold text-white mt-1.5">
                {isUnlocked && snapshot
                  ? `${snapshot.uniqueExternalBlockIPv4.toLocaleString()} 筆`
                  : '🔒 解鎖後顯示'}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                {isUnlocked && snapshot
                  ? `外部封鎖總項次(含網域/CIDR)：${snapshot.rawExternalBlockEntries.toLocaleString()}`
                  : '排除白名單與內網資產後之純封鎖數'}
              </div>
            </div>

            <div className="glass-card p-4 border-l-4 border-l-indigo-400">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>長期聯防黑名單 (TTL 30天)</span>
                <button
                  type="button"
                  onClick={scrollToMethodology}
                  className="text-sky-400 hover:underline"
                >
                  [定義]
                </button>
              </div>
              <div className="text-2xl font-extrabold text-white mt-1.5">
                {isUnlocked && snapshot
                  ? `${snapshot.capacity.longTermCount.toLocaleString()} 筆`
                  : '🔒 解鎖後顯示'}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                {isUnlocked && snapshot
                  ? `近24h 新增 +${snapshot.longTermTrend.last24hAdded.toLocaleString()} / 退場 -${snapshot.longTermTrend.last24hRemoved}`
                  : '全球高危情資 ∪ 10天跨≥3日累犯'}
              </div>
            </div>

            <div className="glass-card p-4 border-l-4 border-l-emerald-400">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>受保護資產與內網微隔離</span>
                <button
                  type="button"
                  onClick={scrollToMethodology}
                  className="text-sky-400 hover:underline"
                >
                  [定義]
                </button>
              </div>
              <div className="text-2xl font-extrabold text-white mt-1.5">
                {isUnlocked && snapshot
                  ? `${snapshot.protectedAndInternalEntries.toLocaleString()} 筆`
                  : '🔒 解鎖後顯示'}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                {isUnlocked && snapshot
                  ? `內網網段誤入外部黑名單數：${snapshot.internalMisblockCount} 筆`
                  : '與外部封鎖指標嚴格分開統計'}
              </div>
            </div>

            <div className="glass-card p-4 border-l-4 border-l-amber-400">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>自動化排程巡檢頻率</span>
                <button
                  type="button"
                  onClick={scrollToMethodology}
                  className="text-sky-400 hover:underline"
                >
                  [定義]
                </button>
              </div>
              <div className="text-2xl font-extrabold text-white mt-1.5">
                {isUnlocked && snapshot
                  ? `${snapshot.dailyScheduledRuns} 次/日`
                  : '🔒 解鎖後顯示'}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                3 支 10分鐘級 (×144) + 1 支 3小時級 (×8)
              </div>
            </div>

            <div className="glass-card p-4 border-l-4 border-l-purple-400">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>GitOps 版本控管軌跡</span>
                <button
                  type="button"
                  onClick={scrollToMethodology}
                  className="text-sky-400 hover:underline"
                >
                  [定義]
                </button>
              </div>
              <div className="text-2xl font-extrabold text-white mt-1.5">
                {isUnlocked && snapshot
                  ? `${snapshot.totalCommitsCount.toLocaleString()} 次`
                  : '🔒 解鎖後顯示'}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                每次清單新增/退場皆留存可追溯紀錄
              </div>
            </div>
          </div>
        </header>

        {/* Navigation Tabs (v2.3 High-Contrast Light Option Bar) */}
        <nav
          aria-label="系統功能選項導覽列"
          className="rounded-2xl bg-gradient-to-r from-slate-100 via-sky-50 to-indigo-100 border-2 border-sky-300/90 shadow-xl shadow-sky-950/50 p-3.5 sm:p-4 no-print"
        >
          <div className="flex flex-wrap items-center justify-between gap-2 mb-2.5 px-1">
            <div className="inline-flex items-center gap-2">
              <span className="px-2.5 py-0.5 rounded-full bg-sky-600 text-white text-[11px] font-extrabold tracking-wide shadow-sm">
                🧭 功能選項切換區
              </span>
              <span className="text-xs font-bold text-slate-700">
                點擊下方淺色選項卡切換檢視模組或執行全庫清單 (`*.txt`) 封鎖/白名單查詢：
              </span>
            </div>
            <span className="text-[11px] font-mono font-semibold text-slate-600">
              目前檢視模組：{
                {
                  overview: '🏗️ 系統架構、資料流與腳本規格',
                  ip_lookup: '🔍 IP / 網域封鎖與清單狀態查詢',
                  trend: '📈 長期黑名單趨勢與 24h 異動',
                  inventory: '📂 全庫清單分類彙總表 (原始檔名)',
                  compliance: '⚖️ 容量水位預警與 ISO 27001:2022',
                  methodology: '📘 方法論、公式與資料來源說明',
                }[activeTab]
              }
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-2.5">
            {[
              {
                id: 'overview',
                icon: '🏗️',
                label: '系統架構、資料流與腳本規格',
                sub: '三層架構與 4 支排程',
              },
              {
                id: 'ip_lookup',
                icon: '🔍',
                label: 'IP 封鎖狀態查詢',
                sub: '全庫 25 份 *.txt 雙向比對',
              },
              {
                id: 'trend',
                icon: '📈',
                label: '長期黑名單趨勢與 24h 異動',
                sub: 'g-BLACK_IP_AutoLongTerm-v1.txt',
              },
              {
                id: 'inventory',
                icon: '📂',
                label: '全庫清單分類彙總表',
                sub: '100% 對應 Fortigate 原始檔名',
              },
              {
                id: 'compliance',
                icon: '⚖️',
                label: '容量水位預警與 ISO 27001:2022',
                sub: 'EDL 水位與法規控制項',
              },
              {
                id: 'methodology',
                icon: '📘',
                label: '方法論、公式與資料來源說明',
                sub: '去重聯集與驗證依據',
              },
            ].map((tab) => {
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() =>
                    setActiveTab(
                      tab.id as
                        | 'overview'
                        | 'ip_lookup'
                        | 'trend'
                        | 'inventory'
                        | 'compliance'
                        | 'methodology'
                    )
                  }
                  className={`px-3.5 py-2.5 rounded-xl text-left transition-all flex items-center justify-between gap-2 cursor-pointer border ${
                    isActive
                      ? 'bg-gradient-to-r from-sky-600 via-blue-600 to-indigo-700 text-white border-sky-700 shadow-lg shadow-sky-600/30 ring-2 ring-sky-400/60 scale-[1.01]'
                      : 'bg-white/95 hover:bg-sky-50 text-slate-800 hover:text-sky-900 border-slate-300/90 hover:border-sky-400 shadow-sm'
                  }`}
                >
                  <div className="flex items-start gap-2 min-w-0">
                    <span className="text-base leading-none mt-0.5">{tab.icon}</span>
                    <div className="min-w-0">
                      <div
                        className={`text-xs sm:text-[13px] font-extrabold leading-snug truncate ${
                          isActive ? 'text-white' : 'text-slate-800'
                        }`}
                      >
                        {tab.label}
                      </div>
                      <div
                        className={`text-[10px] font-mono truncate mt-0.5 ${
                          isActive ? 'text-sky-100' : 'text-slate-500'
                        }`}
                      >
                        {tab.sub}
                      </div>
                    </div>
                  </div>
                  <span
                    className={`w-2 h-2 rounded-full shrink-0 ${
                      isActive ? 'bg-amber-300 shadow-sm shadow-amber-200' : 'bg-slate-300'
                    }`}
                  />
                </button>
              );
            })}
          </div>
        </nav>

        {/* ==================== TAB: IP BLOCK STATUS LOOKUP (v2.3.8 Full-Repo *.txt + 10-Day Dynamic Rollover Lookup) ==================== */}
        {activeTab === 'ip_lookup' && (
          <section className="glass-panel p-6 space-y-5">
            <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-800 pb-4">
              <div>
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <span>🔍 IP / 網域 / 設備清單狀態即時查詢工具（Full-Repo `*.txt` + 近 10 日滾動歷史比對 v2.3.8）</span>
                </h2>
                <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                  100% 同步對齊來源儲存庫 <code>Fortigate</code> 內全部 <strong>25 份純文字清單檔 (`*.txt`)</strong> 之原始檔案名稱，並同時掃描<strong>現行最新 HEAD 版本</strong>與<strong>過去 10 天動態滾動清單歷史</strong>（解決本機未 `git pull` 或當日 00:00 歸零退場之查詢落差）：
                  <br />• <strong className="text-rose-300">A. 在封鎖清單內</strong>：明確列出現行落在哪幾個封鎖檔（如 <code>g-BLACK_IP_Manual-v5.txt</code>、<code>ncloud_block_src_cert_remote.txt</code>、<code>g-NetworkDevices_Block-v1.txt</code> 等）以及<strong>近 10 日曾出現在哪份動態清單與日期</strong>。
                  <br />• <strong className="text-sky-300">B. 不在封鎖清單內</strong>：自動檢索並列出落在哪幾個非封鎖之網站/維護/允許名單內（如 <code>NTNU-AcademicWebsites-CSIE-1.txt</code>、<code>NTNU-FormalWebsites-v2.txt</code>、<code>Security-UCP-maintenance-v1.txt</code>、<code>ncloud_allowlist.txt</code> 等）及檔案內該筆之 <code>#註解說明</code>。
                </p>
              </div>
              <div className="text-xs font-mono text-slate-400">
                比對基準版本：
                <strong className="text-sky-300 ml-1">
                  {isUnlocked && snapshot
                    ? `${snapshot.headTimeDisplay} (${snapshot.shortHeadSha})`
                    : '🔒 解鎖後顯示'}
                </strong>
              </div>
            </div>

            {!isUnlocked ? (
              <div className="text-center py-12 space-y-3">
                <div className="text-slate-300 text-sm font-semibold">
                  🔒 請先解鎖安全金庫以使用全庫 `*.txt` 清單狀態查詢功能
                </div>
                <button
                  type="button"
                  onClick={() => setShowVaultModal(true)}
                  className="px-4 py-2 rounded-xl bg-sky-500 hover:bg-sky-600 text-white text-xs font-bold"
                >
                  輸入通行密鑰解鎖
                </button>
              </div>
            ) : (
              <>
                <div className="glass-card p-4 space-y-3">
                  <label className="block text-xs font-bold text-slate-200">
                    輸入要查詢之 IPv4 位址、FQDN 網域/主機名稱或 MAC 位址（支援單筆或多筆查詢，以空白、逗號或換行分隔，單次最多 50 筆）：
                  </label>
                  <div className="flex flex-col sm:flex-row gap-3">
                    <input
                      type="text"
                      value={ipQueryInput}
                      onChange={(e) => setIpQueryInput(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') {
                          handleQueryIps();
                        }
                      }}
                      placeholder="例如：104.16.102.112, 176.123.1.163, 140.122.58.5, 140.122.251.74, 140.122.7.22, 140.122.111.3"
                      className="flex-1 rounded-xl bg-slate-900/90 border border-slate-700 focus:border-sky-400 px-4 py-2.5 text-sm font-mono text-white outline-none placeholder:text-slate-500"
                    />
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        disabled={ipQueryLoading}
                        onClick={() => handleQueryIps()}
                        className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-600 hover:to-blue-700 text-white font-bold text-xs sm:text-sm whitespace-nowrap shadow-lg shadow-sky-500/20 disabled:opacity-50"
                      >
                        {ipQueryLoading ? '⏳ 全庫 25 檔 + 10日歷史檢索中...' : '🔍 立即查詢清單位置'}
                      </button>
                      {ipQueryInput && (
                        <button
                          type="button"
                          onClick={() => {
                            setIpQueryInput('');
                            setIpQueryResult(null);
                            setIpQueryError(null);
                          }}
                          className="px-3 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold"
                        >
                          清除
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Light-themed Quick Option Box for Sample Queries */}
                  <div className="rounded-xl bg-slate-100 border border-sky-300 p-3 text-xs text-slate-800 space-y-2">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-extrabold text-slate-900">
                        ⚡ 一鍵帶入測試範例（點擊下方淺色按鈕立即實測 A 封鎖清單 / 歷史動態清單 / B 非封鎖名單）：
                      </span>
                      <span className="text-[11px] text-slate-600 font-mono">
                        🔒 查詢結果經伺服器端 AES-256-GCM 加密回傳
                      </span>
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <button
                        type="button"
                        onClick={() => {
                          const sample = '104.16.102.112, 101.108.82.173, 176.123.1.163, 140.122.58.5';
                          setIpQueryInput(sample);
                          handleQueryIps(sample);
                        }}
                        className="px-3 py-1.5 rounded-lg bg-white hover:bg-rose-50 text-rose-700 border border-rose-300 font-mono font-bold text-xs shadow-sm cursor-pointer transition-all"
                      >
                        🔴 範例 A (封鎖清單含 ncloud_block_src_cert_remote.txt)：104.16.102.112 / 101.108.82.173 / Manual-v5
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          const sample = '140.122.251.74, 140.122.7.22, 140.122.111.3, 8.8.8.8';
                          setIpQueryInput(sample);
                          handleQueryIps(sample);
                        }}
                        className="px-3 py-1.5 rounded-lg bg-white hover:bg-sky-50 text-sky-800 border border-sky-300 font-mono font-bold text-xs shadow-sm cursor-pointer transition-all"
                      >
                        🔵 範例 B (不在封鎖清單，位於允許/網站/維護清單)：CSIE-1 / FormalWebsites-v2 / UCP-maintenance-v1
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          const sample =
                            '104.16.102.112, 176.123.1.163, 140.122.58.5, 140.122.251.74, 140.122.7.22, 140.122.111.3';
                          setIpQueryInput(sample);
                          handleQueryIps(sample);
                        }}
                        className="px-3 py-1.5 rounded-lg bg-white hover:bg-indigo-50 text-indigo-800 border border-indigo-300 font-mono font-bold text-xs shadow-sm cursor-pointer transition-all"
                      >
                        🔄 綜合對照範例 (A 封鎖清單 + 近10日動態清單 + B 非封鎖清單)
                      </button>
                    </div>
                  </div>
                </div>

                {ipQueryError && (
                  <div className="p-3.5 rounded-xl bg-rose-500/20 border border-rose-500/40 text-rose-200 text-xs">
                    {ipQueryError}
                  </div>
                )}

                {ipQueryResult && (
                  <div className="space-y-4">
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-3">
                      <div className="glass-card p-3.5">
                        <div className="text-[11px] text-slate-400">
                          查詢總數 ({ipQueryResult.scannedFilesCount ?? 25} 檔 + 10日歷史)
                        </div>
                        <div className="text-xl font-extrabold text-white mt-0.5">
                          {ipQueryResult.totalQueried} 筆
                        </div>
                      </div>
                      <div className="glass-card p-3.5 border-l-4 border-l-rose-500">
                        <div className="text-[11px] text-slate-400">
                          A1. 現行封鎖中 (HEAD)
                        </div>
                        <div className="text-xl font-extrabold text-rose-400 mt-0.5">
                          {ipQueryResult.blockedCount} 筆
                        </div>
                      </div>
                      <div className="glass-card p-3.5 border-l-4 border-l-amber-400">
                        <div className="text-[11px] text-slate-400">
                          A2. 近10日動態清單曾封鎖
                        </div>
                        <div className="text-xl font-extrabold text-amber-300 mt-0.5">
                          {ipQueryResult.historicalBlockedCount ?? 0} 筆
                        </div>
                      </div>
                      <div className="glass-card p-3.5 border-l-4 border-l-sky-400">
                        <div className="text-[11px] text-slate-400">
                          B. 位於網站/維護/允許名單
                        </div>
                        <div className="text-xl font-extrabold text-sky-300 mt-0.5">
                          {ipQueryResult.inAllowlistCount ?? 0} 筆
                        </div>
                      </div>
                      <div className="glass-card p-3.5 border-l-4 border-l-emerald-500">
                        <div className="text-[11px] text-slate-400">
                          未出現在任何清單檔案
                        </div>
                        <div className="text-xl font-extrabold text-emerald-400 mt-0.5">
                          {Math.max(
                            0,
                            ipQueryResult.cleanCount - (ipQueryResult.inAllowlistCount ?? 0)
                          )}{' '}
                          筆
                        </div>
                      </div>
                      <div className="glass-card p-3.5 flex flex-col justify-between">
                        <div className="text-[11px] text-slate-400">
                          本地深度 Git 歷史調閱指令
                        </div>
                        <button
                          type="button"
                          onClick={() =>
                            handleCopyLocalCmd(
                              ipQueryResult.results
                                .filter((r) => r.isValidIp)
                                .map((r) => r.query)
                            )
                          }
                          className="mt-1 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-sky-300 text-xs font-mono text-left truncate"
                          title="複製 python query_ip_history.py 指令以調閱過去 7 天逐筆 Commit 統計"
                        >
                          {copiedCmd
                            ? '✅ 已複製 query_ip_history.py 指令！'
                            : '📋 複製 query_ip_history.py 指令'}
                        </button>
                      </div>
                    </div>

                    <div className="space-y-4">
                      {ipQueryResult.results.map((item) => {
                        const blockList = item.blockMatches ?? [];
                        const histBlockList = item.historicalBlockMatches ?? [];
                        const allowList = item.allowMatches ?? [];
                        return (
                          <div
                            key={item.query}
                            className={`glass-card p-5 space-y-4 border-l-4 ${
                              item.status === 'blocked'
                                ? 'border-l-rose-500'
                                : item.status === 'historical_blocked'
                                ? 'border-l-amber-400'
                                : item.status === 'in_allowlist_only'
                                ? 'border-l-sky-400'
                                : item.status === 'not_in_any_list'
                                ? 'border-l-emerald-400'
                                : 'border-l-slate-500'
                            }`}
                          >
                            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
                              <div className="flex flex-wrap items-center gap-2.5">
                                <span className="text-xs text-slate-400">查詢目標：</span>
                                <code className="text-base font-extrabold text-white bg-slate-900 px-3 py-0.5 rounded border border-slate-700">
                                  {item.query}
                                </code>
                                {blockList.length > 0 && (
                                  <span className="px-2.5 py-0.5 rounded-md bg-rose-500/20 border border-rose-500/40 text-rose-200 text-xs font-mono font-bold">
                                    現行封鎖檔：{blockList.map((m) => m.fileName).join(' , ')}
                                  </span>
                                )}
                                {histBlockList.length > 0 && (
                                  <span className="px-2.5 py-0.5 rounded-md bg-amber-500/20 border border-amber-500/40 text-amber-200 text-xs font-mono font-bold">
                                    近10日動態封鎖檔：{histBlockList.map((m) => m.fileName).join(' , ')}
                                  </span>
                                )}
                                {allowList.length > 0 && (
                                  <span className="px-2.5 py-0.5 rounded-md bg-sky-500/20 border border-sky-500/40 text-sky-200 text-xs font-mono font-bold">
                                    非封鎖名單：{allowList.map((m) => m.fileName).join(' , ')}
                                  </span>
                                )}
                              </div>
                              <div className="flex flex-wrap items-center gap-2">
                                {item.isAllowlisted && (
                                  <span className="px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-sky-500/20 text-sky-300 border border-sky-500/40">
                                    ✅ ncloud_allowlist.txt
                                  </span>
                                )}
                                {item.isExcludedFromLongTerm && (
                                  <span className="px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/40">
                                    🛡️ longterm_exclude.txt
                                  </span>
                                )}
                                <span
                                  className={`px-3 py-1 rounded-full text-xs font-bold border ${
                                    item.status === 'blocked'
                                      ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                                      : item.status === 'historical_blocked'
                                      ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                                      : item.status === 'in_allowlist_only'
                                      ? 'bg-sky-500/20 text-sky-300 border-sky-500/40'
                                      : item.status === 'not_in_any_list'
                                      ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                                      : 'bg-slate-800 text-slate-300 border-slate-700'
                                  }`}
                                >
                                  {item.statusLabel}
                                </span>
                              </div>
                            </div>

                            {/* Case A1: Current HEAD Blocklist Matches Table */}
                            {blockList.length > 0 && (
                              <div className="overflow-x-auto space-y-1.5">
                                <div className="text-xs font-bold text-rose-300 flex items-center gap-1.5">
                                  <span>🔴 A1. 落在現行封鎖清單 (`Fortigate` 最新 HEAD 封鎖檔案位置，共 {blockList.length} 份)：</span>
                                </div>
                                <table className="w-full text-left border-collapse text-xs">
                                  <thead>
                                    <tr className="border-b border-slate-700 bg-rose-950/40 text-slate-200">
                                      <th className="p-2.5">來源 `Fortigate` 原始檔案名稱 (`*.txt`)</th>
                                      <th className="p-2.5">清單類別</th>
                                      <th className="p-2.5">命中型態</th>
                                      <th className="p-2.5">命中規則 / 行號 / 註解</th>
                                      <th className="p-2.5">負責腳本與更新頻率</th>
                                      <th className="p-2.5">清單用途與退場機制</th>
                                    </tr>
                                  </thead>
                                  <tbody className="divide-y divide-slate-800/80">
                                    {blockList.map((m) => (
                                      <tr key={m.feedId} className="hover:bg-slate-800/40">
                                        <td className="p-2.5 font-mono font-extrabold text-rose-300 whitespace-nowrap">
                                          📄 {m.fileName}
                                        </td>
                                        <td className="p-2.5 whitespace-nowrap text-slate-300">
                                          {m.categoryLabel}
                                        </td>
                                        <td className="p-2.5 whitespace-nowrap">
                                          <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">
                                            {m.matchType === 'exact_ip'
                                              ? '精確 IP 命中'
                                              : m.matchType === 'cidr_subnet'
                                              ? 'CIDR 子網段涵蓋'
                                              : m.matchType === 'exact_fqdn'
                                              ? '精確 FQDN 命中'
                                              : m.matchType === 'wildcard_fqdn'
                                              ? '萬用字元網域命中'
                                              : m.matchType === 'exact_mac'
                                              ? '精確 MAC 命中'
                                              : '註解主機命中'}
                                          </span>
                                        </td>
                                        <td className="p-2.5 font-mono text-sky-300">
                                          <div>{m.matchedRule}</div>
                                          <div className="text-[11px] text-slate-400">
                                            {m.lineNumber ? `位於檔案第 ${m.lineNumber} 行` : ''}
                                            {m.commentNote ? ` · 註解：#${m.commentNote}` : ''}
                                          </div>
                                        </td>
                                        <td className="p-2.5 text-slate-300 whitespace-nowrap">
                                          {m.generatorLabel} ({m.cadenceLabel})
                                        </td>
                                        <td className="p-2.5 text-slate-300">
                                          <div className="font-semibold text-slate-200">{m.description}</div>
                                          <div className="text-[11px] text-slate-400">{m.retentionPolicy}</div>
                                        </td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            )}

                            {/* Case A2: 10-Day Historical Dynamic Blocklist Matches Table */}
                            {histBlockList.length > 0 && (
                              <div className="overflow-x-auto space-y-1.5">
                                <div className="text-xs font-bold text-amber-300 flex items-center gap-1.5">
                                  <span>
                                    🟠 A2. 落在近 10 日動態封鎖清單歷史（曾列入以下 `*.txt` 封鎖清單，已於當日 00:00 歸零重算退場，共 {histBlockList.length} 份）：
                                  </span>
                                </div>
                                <table className="w-full text-left border-collapse text-xs">
                                  <thead>
                                    <tr className="border-b border-slate-700 bg-amber-950/40 text-slate-200">
                                      <th className="p-2.5">來源 `Fortigate` 原始檔案名稱 (`*.txt`)</th>
                                      <th className="p-2.5">清單類別</th>
                                      <th className="p-2.5">狀態型態</th>
                                      <th className="p-2.5">最後出現日期 / Commit / 當時行號</th>
                                      <th className="p-2.5">負責腳本與更新頻率</th>
                                      <th className="p-2.5">動態歸零與退場說明</th>
                                    </tr>
                                  </thead>
                                  <tbody className="divide-y divide-slate-800/80">
                                    {histBlockList.map((m) => (
                                      <tr key={m.feedId} className="hover:bg-slate-800/40">
                                        <td className="p-2.5 font-mono font-extrabold text-amber-300 whitespace-nowrap">
                                          📄 {m.fileName}
                                        </td>
                                        <td className="p-2.5 whitespace-nowrap text-slate-300">
                                          {m.categoryLabel}
                                        </td>
                                        <td className="p-2.5 whitespace-nowrap">
                                          <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                                            近10日曾封鎖 (已歸零退場)
                                          </span>
                                        </td>
                                        <td className="p-2.5 font-mono text-sky-300">
                                          <div>
                                            最後出現：<strong className="text-white">{m.lastSeenDisplay}</strong>{' '}
                                            <span className="text-slate-400">({m.lastSeenSha})</span>
                                          </div>
                                          <div className="text-[11px] text-amber-200/90 mt-0.5">
                                            {m.lineNumber ? `當時位於檔案第 ${m.lineNumber} 行 · ` : ''}
                                            若本機資料夾尚未 <code>git pull</code>，仍會在此檔案看到該 IP
                                          </div>
                                        </td>
                                        <td className="p-2.5 text-slate-300 whitespace-nowrap">
                                          {m.generatorLabel} ({m.cadenceLabel})
                                        </td>
                                        <td className="p-2.5 text-slate-300">
                                          <div className="font-semibold text-slate-200">{m.description}</div>
                                          <div className="text-[11px] text-slate-400">{m.retentionPolicy}</div>
                                        </td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            )}

                            {/* Case B: Non-Blocklist (Allowlist / Website / Maintenance) Matches Table */}
                            {allowList.length > 0 && (
                              <div className="overflow-x-auto space-y-1.5">
                                <div className="text-xs font-bold text-sky-300 flex items-center gap-1.5">
                                  <span>
                                    🔵 B. {blockList.length === 0 ? '不在現行封鎖清單內 — ' : '同時'}落在允許 / 正式網站 / 學術網站 / 維護名單 (`Fortigate` 檔案位置，共 {allowList.length} 份)：
                                  </span>
                                </div>
                                <table className="w-full text-left border-collapse text-xs">
                                  <thead>
                                    <tr className="border-b border-slate-700 bg-sky-950/40 text-slate-200">
                                      <th className="p-2.5">來源 `Fortigate` 原始檔案名稱 (`*.txt`)</th>
                                      <th className="p-2.5">清單類別</th>
                                      <th className="p-2.5">命中型態</th>
                                      <th className="p-2.5">檔案內對應行號與 `#` 註解說明</th>
                                      <th className="p-2.5">維護方式與頻率</th>
                                      <th className="p-2.5">名單用途說明</th>
                                    </tr>
                                  </thead>
                                  <tbody className="divide-y divide-slate-800/80">
                                    {allowList.map((m) => (
                                      <tr key={m.feedId} className="hover:bg-slate-800/40">
                                        <td className="p-2.5 font-mono font-extrabold text-sky-300 whitespace-nowrap">
                                          📄 {m.fileName}
                                        </td>
                                        <td className="p-2.5 whitespace-nowrap text-slate-300">
                                          {m.categoryLabel}
                                        </td>
                                        <td className="p-2.5 whitespace-nowrap">
                                          <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-sky-500/20 text-sky-300 border border-sky-500/30">
                                            {m.matchType === 'exact_ip'
                                              ? '精確 IP 登錄'
                                              : m.matchType === 'cidr_subnet'
                                              ? 'CIDR 網段登錄'
                                              : m.matchType === 'comment_host'
                                              ? '註解網址/主機命中'
                                              : '精確項目登錄'}
                                          </span>
                                        </td>
                                        <td className="p-2.5 font-mono text-emerald-300">
                                          <div>
                                            {m.matchedRule}{' '}
                                            {m.lineNumber ? (
                                              <span className="text-slate-400">
                                                (第 {m.lineNumber} 行)
                                              </span>
                                            ) : null}
                                          </div>
                                          {m.commentNote && (
                                            <div className="text-[11px] text-amber-300 mt-0.5">
                                              📌 檔案內註解：<code>#{m.commentNote}</code>
                                            </div>
                                          )}
                                        </td>
                                        <td className="p-2.5 text-slate-300 whitespace-nowrap">
                                          {m.generatorLabel} ({m.cadenceLabel})
                                        </td>
                                        <td className="p-2.5 text-slate-300">
                                          <div className="font-semibold text-slate-200">{m.description}</div>
                                          <div className="text-[11px] text-slate-400">{m.retentionPolicy}</div>
                                        </td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            )}

                            <div className="p-3 rounded-xl bg-slate-900/70 border border-slate-800 text-xs text-slate-300 flex flex-wrap items-center justify-between gap-2">
                              <div>
                                <strong className="text-white">💡 查詢結論與處置指引：</strong>{' '}
                                {item.advisory}
                              </div>
                              {item.isValidIp && (
                                <span className="font-mono text-[11px] text-slate-400">
                                  本地歷史查詢：<code>python query_ip_history.py {item.query} --days 7</code>
                                </span>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </>
            )}
          </section>
        )}

        {/* ==================== TAB 1: ARCHITECTURE, DATA FLOW & PIPELINE HEALTH ==================== */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Section 1: Pipeline Health */}
            <section className="glass-panel p-6 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <h2 className="text-lg font-bold text-white">
                    🚦 自動化情資管線健康度與資料時效監控（Pipeline Health &amp; Freshness）
                  </h2>
                  <p className="text-xs text-slate-400">
                    即時解析 4 支自動化排程腳本最後一次同步距今時間（長期黑名單腳本若當輪無新增/退場則跳過無意義 Commit，故超過 9 小時才發警示）
                  </p>
                </div>
                <span className="text-xs font-mono text-slate-400">
                  快照抓取時間：{isUnlocked && snapshot ? snapshot.fetchedAtDisplay : '🔒 解鎖後顯示'}
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {(snapshot?.pipelineHealth ?? []).map((h) => (
                  <div key={h.id} className="glass-card p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs text-sky-300 font-bold">
                        {h.name} ({h.version})
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded-full text-[11px] font-bold ${
                          h.status === 'healthy'
                            ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                            : h.status === 'warning'
                            ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                            : 'bg-slate-700 text-slate-300'
                        }`}
                      >
                        {h.status === 'healthy'
                          ? '🟢 正常運作'
                          : h.status === 'warning'
                          ? '🟡 逾時關注'
                          : '⚪ 待確認'}
                      </span>
                    </div>
                    <div className="text-xs text-slate-300">
                      最後更新：{' '}
                      <strong className="font-mono text-white">
                        {h.lastCommitDisplay ?? '無近期變更'}
                      </strong>{' '}
                      {h.minutesAgo !== null && (
                        <span className="text-slate-400">({h.minutesAgo} 分鐘前)</span>
                      )}
                    </div>
                    <div className="text-[11px] text-slate-400">
                      排程：<code>{h.cronExpression}</code>（每日 {h.runsPerDay} 次）
                    </div>
                    <p className="text-[11px] text-slate-400 leading-relaxed pt-1 border-t border-slate-800">
                      {h.note}
                    </p>
                  </div>
                ))}
                {!isUnlocked && (
                  <div className="col-span-4 text-center py-8 text-slate-400 text-sm">
                    🔒 解鎖安全金庫後即顯示 4 支自動化引擎之即時健康狀態與最後同步時間
                  </div>
                )}
              </div>
            </section>

            {/* Section 2: Clean Visual System Architecture & Interactive CrossOver Inspector (v2.3.8) */}
            <section className="glass-panel p-6 space-y-5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <h2 className="text-lg font-bold text-white">
                    🏗️ 系統架構與自動化資料流向圖（System Architecture &amp; CrossOver Inspector）
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    精簡視覺化三層架構：將滑鼠移至（Hover / 點擊）任一節點，即可透過下方<strong>「🔍 節點技術規格 CrossOver 檢視窗」</strong>動態顯現該模組之排程、狀態檔與對應 <code>*.txt</code> 清單，畫面清爽不雜亂。
                  </p>
                </div>
                <span className="px-3 py-1 rounded-full bg-sky-500/15 border border-sky-400/30 text-sky-300 text-xs font-mono font-bold">
                  💡 滑鼠移過或點擊節點即時連動技術細節
                </span>
              </div>

              {(() => {
                const ARCH_NODES: Record<
                  string,
                  {
                    layer: string;
                    badge: string;
                    title: string;
                    subtitle: string;
                    scheduleOrRole: string;
                    summary: string;
                    files: string[];
                    techSpecs: string[];
                  }
                > = {
                  script_email: {
                    layer: '第一層：自動化排程主機（Fortigate-Dev）',
                    badge: 'Python v2.1 · 每 10 分鐘',
                    title: '📧 EmailSys_fortigate_block_v2_1.py',
                    subtitle: '郵件閘道封鎖統計 IP/CIDR 與惡意寄件網域產生器',
                    scheduleOrRole: 'Crontab: 0-59/10 * * * *（分鐘尾數 0，每日 144 次）',
                    summary:
                      '每 10 分鐘自動剖析郵件安全閘道封鎖紀錄，萃取高風險發信來源 CIDR 網段與惡意寄件網域，經標準化比對後自動 Git Push 至情資發布庫。',
                    files: ['emailsys_block_ipset.txt', 'emailsys_block_fqdn.txt'],
                    techSpecs: [
                      '支援 IPv4 單點與 /16~/32 CIDR 子網段格式輸出',
                      '錯峰排程固定於分鐘尾數 0 執行，避免與其他腳本競爭 Git Lock',
                      '無實質內容變更時自動跳過 Commit，保持版本庫乾淨',
                    ],
                  },
                  script_ntech: {
                    layer: '第一層：自動化排程主機（Fortigate-Dev）',
                    badge: 'Python v2.1 · 每 10 分鐘',
                    title: '🌐 ncloud_fortigate_ntech_block_v2_1.py',
                    subtitle: 'CERT 外部威脅情資 IP 與掃描器 PTR FQDN 產生器',
                    scheduleOrRole: 'Crontab: 2-59/10 * * * *（分鐘尾數 2，每日 144 次）',
                    summary:
                      '每 10 分鐘同步外部 CERT 聯防威脅指標與惡意掃描器反解紀錄，自動過濾內部受保護網段後發布至外部動態清單。',
                    files: ['ntech_blocklist.txt', 'ntech_blocklist_fqdn.txt'],
                    techSpecs: [
                      '自動分離純 IPv4 威脅指標與 PTR/FQDN 惡意域名指標',
                      '錯峰排程固定於分鐘尾數 2 執行（與郵件腳本錯開 2 分鐘）',
                      '內建公網 IPv4 嚴格校驗與 CRLF/LF 換行符正規化',
                    ],
                  },
                  script_topn: {
                    layer: '第一層：自動化排程主機（Fortigate-Dev）',
                    badge: 'Python v4.5 · 每 10 分鐘',
                    title: '⚡ ncloud_topn_feed_push_v4_5.py',
                    subtitle: '骨幹流量 Top-N 六大威脅行為即時感知推送器',
                    scheduleOrRole: 'Crontab: 5-59/10 * * * *（分鐘尾數 5，每日 144 次）',
                    summary:
                      '採用「每日 00:00 自動歸零重算 (00:00~now) ∪ 每 10 分鐘增量更新」雙軌模式，即時攔截外部未阻斷威脅、SSH 暴力破解、木馬 IRC、異常憑證與 DNS PTR 異常。',
                    files: [
                      'ncloud_block_src_topn.txt',
                      'ncloud_block_src_trojan_irc.txt',
                      'ncloud_block_src_cert_remote.txt',
                      'ncloud_block_src_ext_ssh_in.txt',
                      'ncloud_block_src_dns_ptr_anom.txt',
                      'ncloud_block_dst_topn.txt',
                    ],
                    techSpecs: [
                      '透過狀態檔記錄 last_reset_date，確保跨日 00:00 準時歸零重算',
                      '全面強制套用 ncloud_allowlist.txt 全域白名單與內部 /16 網段排除',
                      '所有輸出檔案均附帶標準化 # Generated by / # Mode / # Rules 標頭',
                    ],
                  },
                  script_longterm: {
                    layer: '第一層：自動化排程主機（Fortigate-Dev）',
                    badge: 'Python v1.0.1 · 每 3 小時',
                    title: '🛡️ ncloud_longterm_block_v1_0.py',
                    subtitle: '跨日重複累犯 ∪ AbuseIPDB 全球高信賴長期黑名單產生器',
                    scheduleOrRole: 'Crontab: 8 */3 * * *（每 3 小時於 08 分執行，每日 8 次）',
                    summary:
                      '將「過去 10 天內跨 ≥3 個不同日曆日重複出現之攻擊 IP」與「AbuseIPDB 100% 信心度全球黑名單」取聯集，實施 30 天 TTL 長期封鎖與自動退場。',
                    files: ['g-BLACK_IP_AutoLongTerm-v1.txt'],
                    techSpecs: [
                      '狀態先存後推：於 Git 推送前先行原子寫入 longterm_state_v1_0.json 與 CSV 統計',
                      '獨立額度台帳：abuseipdb_quota_v1.json 控管每日最多呼叫 4 次、最小間隔 6 小時',
                      '雙重防誤封：同時套用 ncloud_allowlist.txt 與 longterm_exclude.txt 手動剔除清單',
                    ],
                  },
                  repo_ext_ip: {
                    layer: '第二層：EDL 實體情資發布庫（Fortigate）',
                    badge: '10 份純文字檔 · 外部封鎖',
                    title: '🔴 外部威脅 IP 封鎖清單群',
                    subtitle: '提供防火牆 External IP Threat Feed 直接拉取阻斷',
                    scheduleOrRole: '自動 Git Push 更新 + 人工重點維護',
                    summary:
                      '涵蓋 30 天長期黑名單、人工永久黑名單、6 份骨幹流量動態清單、CERT 外部情資與端點惡意程式中繼站種子清單。',
                    files: [
                      'g-BLACK_IP_AutoLongTerm-v1.txt',
                      'g-BLACK_IP_Manual-v5.txt',
                      'ncloud_block_src_topn.txt',
                      'ncloud_block_src_cert_remote.txt',
                      'ncloud_block_src_ext_ssh_in.txt',
                      'ncloud_block_src_trojan_irc.txt',
                      'ncloud_block_src_dns_ptr_anom.txt',
                      'ncloud_block_dst_topn.txt',
                      'ntech_blocklist.txt',
                      'ips_malware_edr_seed.txt',
                    ],
                    techSpecs: [
                      '本查詢系統同時索引最新 HEAD 與近 10 日動態滾動歷史（如 ncloud_block_src_cert_remote.txt）',
                      '伺服器端自動執行 Set 去重聯集計算唯一封鎖 IPv4 總數',
                      '100% 零內網與零白名單洩漏驗證',
                    ],
                  },
                  repo_fqdn_mail: {
                    layer: '第二層：EDL 實體情資發布庫（Fortigate）',
                    badge: '5 份清單 · 網域與郵件 CIDR',
                    title: '🌐 FQDN 惡意網域與郵件封鎖清單群',
                    subtitle: 'DNS Filter 網域阻斷、郵件 CIDR 網段與阻斷警告頁',
                    scheduleOrRole: '每 10 分鐘動態同步 + 人工維護萬用字元網域',
                    summary:
                      '整合 DNS Filter 惡意網域清單（支援 *.domain 萬用字元）、CERT 掃描器反解域名、郵件系統 CIDR 子網段封鎖與自訂 HTML 警告頁。',
                    files: [
                      'DNS-FQDN-Blocklist-v6.txt',
                      'ntech_blocklist_fqdn.txt',
                      'emailsys_block_ipset.txt',
                      'emailsys_block_fqdn.txt',
                      'DNS-Blocked-Message-v7.html',
                    ],
                    techSpecs: [
                      'IP 查詢器支援 32-bit 子網遮罩位元運算，自動判斷單一 IP 是否落在 emailsys_block_ipset.txt 的 CIDR 網段內',
                      '支援萬用字元網域（如 *.example.com）後綴自動比對',
                    ],
                  },
                  repo_internal: {
                    layer: '第二層：EDL 實體情資發布庫（Fortigate）',
                    badge: '4 份清單 · 內部微隔離',
                    title: '🖥️ 內部設備微隔離控管清單群',
                    subtitle: '限制內部 IoT、網通設備、伺服器 SSH 與違規 MAC',
                    scheduleOrRole: '依資安管控政策人工造冊維護',
                    summary:
                      '針對內部網路設備、印表機、IoT 裝置及核心伺服器實施對外連線微隔離（如阻斷對外 Web 或對外直連 SSH），降低橫向移動與外洩風險。',
                    files: [
                      'g-NetworkDevices_Block-v1.txt',
                      'g-IoT_Block-v1.txt',
                      'g-Server_Outbound_SSH_Block-v1.txt',
                      'Block-MAC-List-v1.txt',
                    ],
                    techSpecs: [
                      '與外部威脅封鎖指標嚴格分開統計，不混入外部黑名單總數',
                      '於「🔍 IP 封鎖狀態查詢」輸入內網 IP 或 MAC 時可精準定位所在控管檔案與行號',
                    ],
                  },
                  repo_allow: {
                    layer: '第二層：EDL 實體情資發布庫（Fortigate）',
                    badge: '7 份清單 · 白名單與重要資產',
                    title: '✅ 允許清單與正式/學術網站維護名單群',
                    subtitle: '防誤封豁免白名單、系所學術網站、正式服務與維運主機清冊',
                    scheduleOrRole: '自動化腳本強制讀取豁免 + 人工造冊維護',
                    summary:
                      '包含全域白名單、長期黑名單手動剔除清單，以及正式網站、學術單位網站與資安維運平台清冊，確保關鍵服務絕不遭自動化腳本誤封。',
                    files: [
                      'ncloud_allowlist.txt',
                      'longterm_exclude.txt',
                      'NTNU-FormalWebsites-v2.txt',
                      'NTNU-AcademicWebsites-v2.txt',
                      'NTNU-AcademicWebsites-CSIE-1.txt',
                      'Security-UCP-maintenance-v1.txt',
                      'NTNU-Server-General-1.txt',
                      'Security-Assessment-v2.txt',
                    ],
                    techSpecs: [
                      '於「🔍 IP 封鎖狀態查詢」查詢時，會歸類於「B. 不在封鎖清單內」並顯示所在檔案、行號與 #註解說明',
                      '支援直接以註解內的網址或系所名稱反查對應 IP',
                    ],
                  },
                  enforce_fw: {
                    layer: '第三層：邊界執行與監控層',
                    badge: 'EDL 動態掛載執行',
                    title: '🛡️ 邊界核心防火牆（External Dynamic List）',
                    subtitle: '定時拉取發布庫 Raw URL 自動套用封鎖與豁免政策',
                    scheduleOrRole: '無須人工登入防火牆改規則，全自動同步生效',
                    summary:
                      '透過 External Connector 定時讀取第二層發布庫之純文字清單，即時執行邊界 IP/CIDR 阻斷、DNS 惡意網域過濾與內網微隔離策略。',
                    files: [
                      '單一清單標準上限：131,072 筆',
                      '單一檔案大小上限：10 MB',
                      '全機指標容量：30 萬～500 萬筆',
                    ],
                    techSpecs: [
                      '支援高併發邊界封包過濾與自訂 DNS 阻斷警告頁面回應',
                      '搭配本平台容量水位預警線（70% 黃燈 / 85% 紅燈）確保運作穩定',
                    ],
                  },
                  enforce_dash: {
                    layer: '第三層：邊界執行與監控層',
                    badge: 'AES-256-GCM 零知識金庫',
                    title: '📊 資安威脅情資監控與 IP 查詢平台（本系統 v2.3.8）',
                    subtitle: '唯讀同步、管線健康度監控、全庫 *.txt 與 10 日歷史查詢',
                    scheduleOrRole: 'ETag 條件式快取 + SHA 版本鎖定 + 密文傳輸',
                    summary:
                      '對上游情資庫採 100% 純唯讀（Zero-Write）架構，提供 4 支排程健康度監控、長期黑名單成長趨勢，以及涵蓋現行 25 份 *.txt 與近 10 日動態歷史的 IP 狀態查詢。',
                    files: ['/api/snapshot (AES-256-GCM)', '/api/query-ip (HEAD + 10d History)'],
                    techSpecs: [
                      '公開雲端零明文：所有 API 回應均經伺服器端 AES-256-GCM 加密，須通行密鑰始可瀏覽',
                      '100% 原始檔名對齊：完整對應 Fortigate 儲存庫內所有 *.txt 檔案與行號註解',
                    ],
                  },
                };

                const activeInfo =
                  ARCH_NODES[activeArchNode] ?? ARCH_NODES.script_topn;

                return (
                  <div className="space-y-4">
                    {/* Clean 3-Layer Visual Diagram */}
                    <div className="p-4 sm:p-5 rounded-2xl bg-slate-950/85 border border-slate-800 space-y-3">
                      {/* Layer 1 */}
                      <div className="rounded-xl border border-sky-500/35 bg-sky-950/15 p-3.5 space-y-2.5">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <span className="text-xs font-extrabold text-sky-300 flex items-center gap-1.5">
                            <span>第一層：自動化排程主機（開發庫 4 支 Python 引擎）</span>
                          </span>
                          <span className="text-[11px] font-mono text-slate-400">
                            錯峰分鐘尾數 0 / 2 / 5 / 8 · 每日 440 次巡檢
                          </span>
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
                          {[
                            {
                              id: 'script_email',
                              icon: '📧',
                              name: 'EmailSys_block_v2_1.py',
                              meta: '每 10 分鐘 (尾數 0) · 2 檔',
                            },
                            {
                              id: 'script_ntech',
                              icon: '🌐',
                              name: 'ntech_block_v2_1.py',
                              meta: '每 10 分鐘 (尾數 2) · 2 檔',
                            },
                            {
                              id: 'script_topn',
                              icon: '⚡',
                              name: 'topn_feed_push_v4_5.py',
                              meta: '每 10 分鐘 (尾數 5) · 6 檔',
                            },
                            {
                              id: 'script_longterm',
                              icon: '🛡️',
                              name: 'longterm_block_v1_0.py',
                              meta: '每 3 小時 (30天TTL) · 1 檔',
                            },
                          ].map((node) => {
                            const selected = activeArchNode === node.id;
                            return (
                              <button
                                key={node.id}
                                type="button"
                                onMouseEnter={() => setActiveArchNode(node.id)}
                                onClick={() => setActiveArchNode(node.id)}
                                className={`p-3 rounded-xl text-left transition-all cursor-pointer border ${
                                  selected
                                    ? 'bg-sky-500/25 border-sky-400 shadow-md shadow-sky-500/20 ring-1 ring-sky-400'
                                    : 'bg-slate-900/90 hover:bg-slate-900 border-slate-800 hover:border-sky-500/50'
                                }`}
                              >
                                <div className="flex items-center justify-between gap-1">
                                  <span className="font-mono text-xs font-bold text-white truncate">
                                    {node.icon} {node.name}
                                  </span>
                                  <span className="text-[10px] text-sky-400 shrink-0">
                                    詳情 ↗
                                  </span>
                                </div>
                                <div className="text-[11px] text-slate-400 mt-1 font-mono">
                                  {node.meta}
                                </div>
                              </button>
                            );
                          })}
                        </div>
                      </div>

                      {/* Compact Flow Connector 1 */}
                      <div className="flex items-center justify-center gap-2 text-[11px] font-mono text-sky-300 py-0.5">
                        <span>▼</span>
                        <span className="px-3 py-0.5 rounded-full bg-slate-900 border border-slate-700 text-slate-300">
                          狀態/額度原子寫入 + 全域白名單過濾 + Git Auto Push
                        </span>
                        <span>▼</span>
                      </div>

                      {/* Layer 2 */}
                      <div className="rounded-xl border border-emerald-500/35 bg-emerald-950/15 p-3.5 space-y-2.5">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <span className="text-xs font-extrabold text-emerald-300">
                            第二層：EDL 實體情資發布儲存庫（Fortigate 全庫 26 份清單檔案）
                          </span>
                          <span className="text-[11px] font-mono text-slate-400">
                            100% 原始 *.txt 檔名對齊 · 無異動自動跳過 Commit
                          </span>
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
                          {[
                            {
                              id: 'repo_ext_ip',
                              icon: '🔴',
                              name: '外部威脅 IP 封鎖清單',
                              meta: '10 份 *.txt (含 AutoLongTerm / TopN)',
                            },
                            {
                              id: 'repo_fqdn_mail',
                              icon: '🌐',
                              name: 'FQDN 網域與郵件封鎖',
                              meta: '4 份 *.txt + 1 份警告頁 HTML',
                            },
                            {
                              id: 'repo_internal',
                              icon: '🖥️',
                              name: '內部設備微隔離控管',
                              meta: '4 份 *.txt (網通 / IoT / SSH / MAC)',
                            },
                            {
                              id: 'repo_allow',
                              icon: '✅',
                              name: '允許清單與網站維護資產',
                              meta: '7 份 *.txt (白名單 / 正式與學術網站)',
                            },
                          ].map((node) => {
                            const selected = activeArchNode === node.id;
                            return (
                              <button
                                key={node.id}
                                type="button"
                                onMouseEnter={() => setActiveArchNode(node.id)}
                                onClick={() => setActiveArchNode(node.id)}
                                className={`p-3 rounded-xl text-left transition-all cursor-pointer border ${
                                  selected
                                    ? 'bg-emerald-500/25 border-emerald-400 shadow-md shadow-emerald-500/20 ring-1 ring-emerald-400'
                                    : 'bg-slate-900/90 hover:bg-slate-900 border-slate-800 hover:border-emerald-500/50'
                                }`}
                              >
                                <div className="flex items-center justify-between gap-1">
                                  <span className="text-xs font-bold text-white truncate">
                                    {node.icon} {node.name}
                                  </span>
                                  <span className="text-[10px] text-emerald-400 shrink-0">
                                    詳情 ↗
                                  </span>
                                </div>
                                <div className="text-[11px] text-slate-400 mt-1 font-mono">
                                  {node.meta}
                                </div>
                              </button>
                            );
                          })}
                        </div>
                      </div>

                      {/* Compact Flow Connector 2 */}
                      <div className="flex items-center justify-center gap-2 text-[11px] font-mono text-emerald-300 py-0.5">
                        <span>▼</span>
                        <span className="px-3 py-0.5 rounded-full bg-slate-900 border border-slate-700 text-slate-300">
                          EDL 定時拉取 Raw URL 套用阻斷 + 雲端看板 AES-256-GCM 唯讀監控
                        </span>
                        <span>▼</span>
                      </div>

                      {/* Layer 3 */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                        {[
                          {
                            id: 'enforce_fw',
                            icon: '🛡️',
                            name: '第三層 (A)：邊界核心防火牆 (EDL Threat Feeds)',
                            meta: '自動讀取純文字清單執行邊界阻斷与 DNS 警告頁回應',
                          },
                          {
                            id: 'enforce_dash',
                            icon: '📊',
                            name: '第三層 (B)：資安情資監控與 IP 查詢平台 (本系統)',
                            meta: '提供管線監控、容量水位預警與全庫 *.txt + 10日歷史雙向查詢',
                          },
                        ].map((node) => {
                          const selected = activeArchNode === node.id;
                          return (
                            <button
                              key={node.id}
                              type="button"
                              onMouseEnter={() => setActiveArchNode(node.id)}
                              onClick={() => setActiveArchNode(node.id)}
                              className={`p-3.5 rounded-xl text-left transition-all cursor-pointer border ${
                                selected
                                  ? 'bg-purple-500/25 border-purple-400 shadow-md shadow-purple-500/20 ring-1 ring-purple-400'
                                  : 'bg-slate-900/90 hover:bg-slate-900 border-slate-800 hover:border-purple-500/50'
                              }`}
                            >
                              <div className="flex items-center justify-between gap-2">
                                <span className="text-xs sm:text-sm font-extrabold text-white">
                                  {node.icon} {node.name}
                                </span>
                                <span className="text-[10px] text-purple-300 shrink-0 font-mono">
                                  詳情 ↗
                                </span>
                              </div>
                              <div className="text-[11px] text-slate-400 mt-1">
                                {node.meta}
                              </div>
                            </button>
                          );
                        })}
                      </div>
                    </div>

                    {/* CrossOver Technical Detail Inspector Card */}
                    <div className="rounded-2xl bg-gradient-to-br from-slate-900 via-slate-900 to-sky-950/60 border-2 border-sky-400/50 p-5 shadow-xl space-y-3 transition-all">
                      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
                        <div className="space-y-0.5">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="px-2.5 py-0.5 rounded-full bg-sky-500/20 border border-sky-400/40 text-sky-300 text-[11px] font-bold">
                              🔍 CrossOver 技術規格檢視窗
                            </span>
                            <span className="text-xs text-slate-400 font-mono">
                              {activeInfo.layer}
                            </span>
                          </div>
                          <h3 className="text-base sm:text-lg font-extrabold text-white pt-1">
                            {activeInfo.title}
                          </h3>
                          <p className="text-xs text-sky-300 font-semibold">
                            {activeInfo.subtitle}
                          </p>
                        </div>
                        <span className="px-3 py-1 rounded-xl bg-slate-950 border border-slate-700 text-xs font-mono text-amber-300">
                          {activeInfo.scheduleOrRole}
                        </span>
                      </div>

                      <p className="text-xs sm:text-sm text-slate-200 leading-relaxed">
                        {activeInfo.summary}
                      </p>

                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 pt-1">
                        <div className="rounded-xl bg-slate-950/80 border border-slate-800 p-3.5 space-y-2">
                          <div className="text-xs font-bold text-emerald-300">
                            📄 對應之 `Fortigate` 清單檔案 / 容量指標（共 {activeInfo.files.length} 項）：
                          </div>
                          <div className="flex flex-wrap gap-1.5">
                            {activeInfo.files.map((f) => (
                              <span
                                key={f}
                                className="px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-700 text-xs font-mono text-white"
                              >
                                {f}
                              </span>
                            ))}
                          </div>
                        </div>

                        <div className="rounded-xl bg-slate-950/80 border border-slate-800 p-3.5 space-y-1.5">
                          <div className="text-xs font-bold text-sky-300">
                            ⚙️ 關鍵工程與防呆機制：
                          </div>
                          <ul className="space-y-1 text-xs text-slate-300 list-disc list-inside">
                            {activeInfo.techSpecs.map((spec, idx) => (
                              <li key={idx} className="leading-relaxed">
                                {spec}
                              </li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    </div>

                    {/* Collapsible Deep-Dive Reference Drawer (keeps main screen clean!) */}
                    <div className="pt-1">
                      <button
                        type="button"
                        onClick={() => setShowTechDeepDive((v) => !v)}
                        className="w-full py-2.5 px-4 rounded-xl bg-slate-100 hover:bg-sky-50 border border-sky-300 text-slate-800 font-extrabold text-xs flex items-center justify-between cursor-pointer shadow-sm transition-all"
                      >
                        <span>
                          📋 {showTechDeepDive ? '收合' : '展開'}完整底層技術規格表（雙儲存庫對照表、`LongTerm v1.0.1` 環境變數與檔案標頭範例）
                        </span>
                        <span className="font-mono text-sky-700">
                          {showTechDeepDive ? '▲ 點擊收合細節' : '▼ 點擊展開完整表格'}
                        </span>
                      </button>

                      {showTechDeepDive && (
                        <div className="mt-4 space-y-5 p-4 rounded-2xl bg-slate-950/70 border border-slate-800">
                          {/* Dual-Repository Architecture Table */}
                          <div className="space-y-2">
                            <h3 className="text-sm font-bold text-white">
                              🔗 雙儲存庫架構職責對照表（Repository Architecture）
                            </h3>
                            <div className="overflow-x-auto">
                              <table className="w-full text-left border-collapse text-xs">
                                <thead>
                                  <tr className="border-b border-slate-700 bg-slate-900/60 text-slate-300">
                                    <th className="p-2.5">儲存庫角色</th>
                                    <th className="p-2.5">系統定位</th>
                                    <th className="p-2.5">主要託管內容</th>
                                  </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-800/80">
                                  <tr className="hover:bg-slate-800/40">
                                    <td className="p-2.5 font-mono font-bold text-emerald-300 whitespace-nowrap">
                                      EDL 實體 Feed 發布庫
                                    </td>
                                    <td className="p-2.5 text-white font-semibold whitespace-nowrap">
                                      防火牆 External Dynamic List 純文字情資發布端
                                    </td>
                                    <td className="p-2.5 text-slate-300">
                                      自動化產出之純文字封鎖清單（<code>ncloud_block_*.txt</code>、<code>g-BLACK_IP_AutoLongTerm-v1.txt</code>、<code>emailsys_block_*.txt</code>、<code>ntech_blocklist*.txt</code>）、全域白名單（<code>ncloud_allowlist.txt</code>）、手動剔除清單（<code>longterm_exclude.txt</code>）及人工維護清冊
                                    </td>
                                  </tr>
                                  <tr className="hover:bg-slate-800/40">
                                    <td className="p-2.5 font-mono font-bold text-sky-300 whitespace-nowrap">
                                      開發原始碼庫 (Dev)
                                    </td>
                                    <td className="p-2.5 text-white font-semibold whitespace-nowrap">
                                      自動化 Python 程式碼與驗證測試開發庫
                                    </td>
                                    <td className="p-2.5 text-slate-300">
                                      Python 主程式（<code>v4.5</code>、<code>longterm v1.0.1</code>、<code>v2.1</code>）、共用模組（<code>ncloud_feed_utils.py</code>）、IP 歷史查詢工具（<code>query_ip_history.py</code>）、單元測試（<code>tests/</code>）與自動化驗證腳本
                                    </td>
                                  </tr>
                                </tbody>
                              </table>
                            </div>
                          </div>

                          {/* LongTerm Env Vars & State Files Table */}
                          <div className="space-y-2">
                            <h3 className="text-sm font-bold text-white">
                              🆕 `LongTerm v1.0.1` 關鍵環境變數與狀態台帳規格
                            </h3>
                            <div className="overflow-x-auto">
                              <table className="w-full text-left border-collapse text-xs">
                                <thead>
                                  <tr className="border-b border-slate-700 bg-slate-900/60 text-slate-300">
                                    <th className="p-2.5">參數 / 狀態與日誌檔案</th>
                                    <th className="p-2.5">預設設定值</th>
                                    <th className="p-2.5">技術規格與運作說明</th>
                                  </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-800/80">
                                  <tr className="hover:bg-slate-800/40">
                                    <td className="p-2.5 font-mono font-bold text-sky-300">TTL_DAYS</td>
                                    <td className="p-2.5 font-mono text-white">30</td>
                                    <td className="p-2.5 text-slate-300">
                                      已納入之 IP 自 <code>last_seen</code> 起算超過 30 天自動退場移除
                                    </td>
                                  </tr>
                                  <tr className="hover:bg-slate-800/40">
                                    <td className="p-2.5 font-mono font-bold text-sky-300">
                                      RETENTION_DAYS / REPEAT_MIN_DAYS
                                    </td>
                                    <td className="p-2.5 font-mono text-white">10 / 3</td>
                                    <td className="p-2.5 text-slate-300">
                                      於過去 10 天滾動視窗內跨 ≥3 個不同日曆日出現即納入長期黑名單
                                    </td>
                                  </tr>
                                  <tr className="hover:bg-slate-800/40">
                                    <td className="p-2.5 font-mono font-bold text-sky-300">
                                      ABUSE_MIN_INTERVAL_HOURS / ABUSE_MAX_CALLS_PER_DAY
                                    </td>
                                    <td className="p-2.5 font-mono text-white">6 小時 / 4 次</td>
                                    <td className="p-2.5 text-slate-300">
                                      兩次 AbuseIPDB 呼叫最小間隔 6 小時；每個 UTC 日最多呼叫 4 次
                                    </td>
                                  </tr>
                                  <tr className="hover:bg-slate-800/40">
                                    <td className="p-2.5 font-mono font-bold text-emerald-300">
                                      state/longterm_state_v1_0.json &amp; abuseipdb_quota_v1.json
                                    </td>
                                    <td className="p-2.5 font-mono text-slate-300">原子寫入</td>
                                    <td className="p-2.5 text-slate-300">
                                      主狀態檔於 Git Push 前先行原子寫入；額度台帳於每次 HTTP 嘗試後立即寫入
                                    </td>
                                  </tr>
                                </tbody>
                              </table>
                            </div>
                          </div>

                          {/* Header Specification Examples */}
                          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                            <div className="glass-card p-3.5 space-y-1.5">
                              <div className="text-xs font-bold text-emerald-300">
                                📋 產生標頭規範 1：`ncloud_block_src_topn.txt`
                              </div>
                              <pre className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto leading-relaxed">
{`# ncloud_block_src_topn.txt
# Generated by ncloud_topn_feed_push_v4_5.py
# Mode: daily recompute (00:00~now) UNION 10min incremental per-job union (10m)
# TZ: Asia/Taipei
# Rules: public IPv4 only; internal subnet excluded; allowlist_file=ncloud_allowlist.txt`}
                              </pre>
                            </div>

                            <div className="glass-card p-3.5 space-y-1.5">
                              <div className="text-xs font-bold text-sky-300">
                                📋 產生標頭規範 2：`g-BLACK_IP_AutoLongTerm-v1.txt`
                              </div>
                              <pre className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto leading-relaxed">
{`# g-BLACK_IP_AutoLongTerm-v1.txt
# Generated by ncloud_longterm_block_v1_0.py
# Rules: ncloud_repeat>=3days/10d OR AbuseIPDB blacklist(confidence>=100); TTL=30d
# Count: ${isUnlocked && snapshot ? snapshot.capacity.longTermCount : '68423'}`}
                              </pre>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })()}
            </section>

            {/* Section 4: Four Pillars Summary */}
            <section className="glass-panel p-6 space-y-5">
              <div>
                <h2 className="text-lg font-bold text-white">
                  🛡️ 四大情資來源分類統計彙總（Four Defense Pillars）
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  整合國際黑名單、外部 CERT 聯防、內部流量探針與郵件閘道之四層防護規模統計
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="glass-card p-5 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-sm text-white">
                      🌐 支柱一：國際與外部聯防情資（AbuseIPDB ∪ CERT）
                    </span>
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-sky-500/20 text-sky-300 border border-sky-500/30">
                      {isUnlocked && snapshot
                        ? `${snapshot.pillars.externalIntelCount.toLocaleString()} 筆指標`
                        : '🔒 解鎖後顯示'}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    整合國際惡意 IP 資料庫 <strong>AbuseIPDB</strong>、<strong>CERT 外部威脅情資</strong> 與人工維護黑名單，預先阻斷全球活躍殭屍網路與高風險掃描源。
                  </p>
                </div>

                <div className="glass-card p-5 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-sm text-white">
                      ⚡ 支柱二：骨幹流量即時感知（Top-N 6 大威脅 Job）
                    </span>
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                      {isUnlocked && snapshot
                        ? `${snapshot.pillars.campusTrafficCount.toLocaleString()} 筆動態指標`
                        : '🔒 解鎖後顯示'}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    每 10 分鐘自動分析流量分析平台 6 大異常行為：外部未阻斷威脅 (Top-N)、對內 SSH 入侵嘗試、木馬/IRC C2 連線、可疑遠端憑證與 DNS PTR 異常；10 天內跨 3 日重複出現者自動晉升至 30 天長期黑名單。
                  </p>
                </div>

                <div className="glass-card p-5 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-sm text-white">
                      📧 支柱三：郵件系統與惡意 FQDN 網域封鎖
                    </span>
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                      {isUnlocked && snapshot
                        ? `${snapshot.pillars.emailAndFqdnCount.toLocaleString()} 筆網段/網域`
                        : '🔒 解鎖後顯示'}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    每 10 分鐘萃取郵件系統封鎖 IP/CIDR 網段集合，並維護主要 DNS FQDN 封鎖清單（含萬用字元 <code>*.domain</code> 格式与掃描器 PTR 紀錄）及 DNS 阻斷警告頁面。
                  </p>
                </div>

                <div className="glass-card p-5 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-sm text-white">
                      🔒 支柱四：內部設備控管與白名單防誤封治理
                    </span>
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30">
                      {isUnlocked && snapshot
                        ? `${snapshot.pillars.microSegAndAllowCount.toLocaleString()} 筆控管/保護項目`
                        : '🔒 解鎖後顯示'}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    實施內部 IoT 設備、網路設備、伺服器群對外連線控管與違規 MAC 封鎖；同時透過 <code>ncloud_allowlist.txt</code> 與 <code>longterm_exclude.txt</code> 確保重要外部與內部服務不被誤封。
                  </p>
                </div>
              </div>
            </section>
          </div>
        )}

        {/* ==================== TAB 2: LONGTERM TREND & 24H STATS ==================== */}
        {activeTab === 'trend' && (
          <section className="glass-panel p-6 space-y-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-lg font-bold text-white">
                  📈 貳、長期協防黑名單 (`g-BLACK_IP_AutoLongTerm-v1.txt`) 動態趨勢與近 24 小時異動
                </h2>
                <p className="text-xs text-slate-400">
                  由版本控管歷史 (`total= added= removed=`) 即時解析，無須逐筆暴露 IP 內容
                </p>
              </div>
              <div className="flex items-center gap-2 p-1.5 rounded-xl bg-slate-100 border border-sky-300 shadow-sm">
                <span className="text-[11px] font-extrabold text-slate-700 px-1.5">
                  圖表選項：
                </span>
                <button
                  type="button"
                  onClick={() => setChartMode('cumulative')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                    chartMode === 'cumulative'
                      ? 'bg-sky-600 text-white shadow'
                      : 'bg-white text-slate-800 hover:bg-sky-50 border border-slate-300'
                  }`}
                >
                  累計總筆數趨勢 (Total)
                </button>
                <button
                  type="button"
                  onClick={() => setChartMode('added')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                    chartMode === 'added'
                      ? 'bg-sky-600 text-white shadow'
                      : 'bg-white text-slate-800 hover:bg-sky-50 border border-slate-300'
                  }`}
                >
                  單次新增筆數拆解 (Added)
                </button>
              </div>
            </div>

            {!isUnlocked || !snapshot ? (
              <div className="text-center py-12 text-slate-400">
                🔒 解鎖安全金庫後即顯示動態成長曲線與每日收盤統計表
              </div>
            ) : (
              <>
                <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
                  <div className="glass-card p-4">
                    <div className="text-xs text-slate-400">目前長期黑名單總數</div>
                    <div className="text-xl font-extrabold text-white mt-1">
                      {snapshot.capacity.longTermCount.toLocaleString()} 筆
                    </div>
                  </div>
                  <div className="glass-card p-4">
                    <div className="text-xs text-slate-400">近 24 小時新增入庫</div>
                    <div className="text-xl font-extrabold text-sky-400 mt-1">
                      +{snapshot.longTermTrend.last24hAdded.toLocaleString()} 筆
                    </div>
                  </div>
                  <div className="glass-card p-4">
                    <div className="text-xs text-slate-400">
                      近 24 小時 TTL 期滿退場
                    </div>
                    <div className="text-xl font-extrabold text-emerald-400 mt-1">
                      -{snapshot.longTermTrend.last24hRemoved.toLocaleString()} 筆
                    </div>
                  </div>
                  <div className="glass-card p-4">
                    <div className="text-xs text-slate-400">
                      首批 30 天 TTL 預計退場日
                    </div>
                    <div className="text-xl font-extrabold text-amber-300 mt-1">
                      {snapshot.capacity.firstTtlExpiryDate}
                    </div>
                  </div>
                </div>

                {selectedPoint && (
                  <div className="glass-card px-4 py-3 flex flex-wrap items-center justify-between gap-3 text-xs">
                    <div>
                      <span className="text-slate-400">檢視節點：</span>
                      <span className="font-mono font-bold text-white">
                        {selectedPoint.displayTime}
                      </span>{' '}
                      <span className="font-mono text-sky-400">
                        ({selectedPoint.shortSha})
                      </span>
                    </div>
                    <div className="flex flex-wrap items-center gap-4">
                      <span>
                        累計總數：
                        <strong className="text-white text-sm">
                          {selectedPoint.total.toLocaleString()}
                        </strong>{' '}
                        筆
                      </span>
                      <span>
                        本輪新增：
                        <strong className="text-sky-300 text-sm">
                          +{selectedPoint.added.toLocaleString()}
                        </strong>{' '}
                        筆
                      </span>
                      <span>
                        本輪退場：
                        <strong className="text-emerald-300 text-sm">
                          -{selectedPoint.removed.toLocaleString()}
                        </strong>{' '}
                        筆
                      </span>
                    </div>
                  </div>
                )}

                <div className="w-full overflow-x-auto glass-card p-4">
                  {(() => {
                    const pts = snapshot.longTermTrend.points;
                    if (pts.length === 0) {
                      return (
                        <div className="text-center py-8 text-slate-400 text-xs">
                          尚無歷史趨勢點資料
                        </div>
                      );
                    }
                    const W = 960;
                    const H = 280;
                    const padL = 64;
                    const padR = 24;
                    const padT = 20;
                    const padB = 64;
                    const plotW = W - padL - padR;
                    const plotH = H - padT - padB;
                    const rawMax = Math.max(
                      ...pts.map((p) =>
                        chartMode === 'cumulative' ? p.total : p.added
                      ),
                      1000
                    );
                    const maxVal = Math.ceil(rawMax * 1.1);
                    const stepX = pts.length > 1 ? plotW / (pts.length - 1) : plotW;

                    let dLine = '';
                    pts.forEach((p, idx) => {
                      const x = padL + idx * stepX;
                      const val = chartMode === 'cumulative' ? p.total : p.added;
                      const y = padT + plotH - (val / maxVal) * plotH;
                      dLine += `${idx === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)} `;
                    });

                    return (
                      <svg
                        viewBox={`0 0 ${W} ${H}`}
                        className="w-full h-auto select-none"
                      >
                        {[0, 1, 2, 3, 4, 5].map((i) => {
                          const val = Math.round((maxVal / 5) * i);
                          const y = padT + plotH - (val / maxVal) * plotH;
                          return (
                            <g key={i}>
                              <line
                                x1={padL}
                                x2={W - padR}
                                y1={y}
                                y2={y}
                                stroke="#334155"
                                strokeDasharray="3 3"
                              />
                              <text
                                x={padL - 8}
                                y={y + 4}
                                textAnchor="end"
                                fill="#94a3b8"
                                fontSize="11"
                              >
                                {(val / 1000).toFixed(1)}k
                              </text>
                            </g>
                          );
                        })}

                        {chartMode === 'cumulative' && (
                          <path
                            d={dLine}
                            fill="none"
                            stroke="#38bdf8"
                            strokeWidth="2.5"
                          />
                        )}

                        {pts.map((p, idx) => {
                          const x = padL + idx * stepX;
                          const val =
                            chartMode === 'cumulative' ? p.total : p.added;
                          const y = padT + plotH - (val / maxVal) * plotH;
                          const color =
                            p.sourceType === 'global_or_batch'
                              ? '#38bdf8'
                              : '#10b981';

                          return (
                            <g
                              key={p.sha}
                              onMouseEnter={() => setSelectedPoint(p)}
                              onClick={() => setSelectedPoint(p)}
                              style={{ cursor: 'pointer' }}
                            >
                              {chartMode === 'added' ? (
                                <rect
                                  x={x - Math.max(4, stepX * 0.35)}
                                  y={Math.min(y, padT + plotH - 3)}
                                  width={Math.max(8, stepX * 0.7)}
                                  height={Math.max(3, padT + plotH - y)}
                                  fill={color}
                                  rx="2"
                                />
                              ) : (
                                <circle
                                  cx={x}
                                  cy={y}
                                  r={4}
                                  fill={color}
                                  stroke="#0f172a"
                                  strokeWidth="1.5"
                                />
                              )}
                              {(idx % Math.max(1, Math.floor(pts.length / 12)) ===
                                0 ||
                                idx === pts.length - 1) && (
                                <text
                                  transform={`translate(${x}, ${
                                    padT + plotH + 14
                                  }) rotate(-35)`}
                                  textAnchor="end"
                                  fill="#94a3b8"
                                  fontSize="10"
                                >
                                  {p.shortTime}
                                </text>
                              )}
                            </g>
                          );
                        })}
                      </svg>
                    );
                  })()}
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="border-b border-slate-700 text-slate-300 bg-slate-900/60">
                        <th className="p-3">日期 (Asia/Taipei)</th>
                        <th className="p-3 text-right">當日最終總筆數 (Closing Total)</th>
                        <th className="p-3 text-right">當日累計新增 (Added)</th>
                        <th className="p-3 text-right">當日累計退場 (Removed)</th>
                        <th className="p-3 text-right">當日生效推送次數</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/80">
                      {snapshot.longTermTrend.daily.map((d) => (
                        <tr key={d.date} className="hover:bg-slate-800/40">
                          <td className="p-3 font-mono font-semibold text-white">
                            {d.date}
                          </td>
                          <td className="p-3 text-right font-mono font-bold text-sky-300">
                            {d.closingTotal.toLocaleString()}
                          </td>
                          <td className="p-3 text-right font-mono text-emerald-300">
                            +{d.dailyAdded.toLocaleString()}
                          </td>
                          <td className="p-3 text-right font-mono text-amber-300">
                            -{d.dailyRemoved.toLocaleString()}
                          </td>
                          <td className="p-3 text-right font-mono text-slate-300">
                            {d.commitCount} 次
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </section>
        )}

        {/* ==================== TAB 3: FEED INVENTORY ==================== */}
        {activeTab === 'inventory' && (
          <section className="glass-panel p-6 space-y-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-lg font-bold text-white">
                  📂 參、全庫資安情資與治理清單分類彙總表（100% 對應 `Fortigate` 原始檔案名稱）
                </h2>
                <p className="text-xs text-slate-400">
                  依據雙庫名稱對齊規範：所有清單檔案名稱與來源儲存庫 <code>Fortigate</code> 之 <code>*.txt</code> / <code>*.html</code> 100% 一致，並可於「🔍 IP 封鎖狀態查詢」直接檢索對應內容。
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2 text-xs p-2 rounded-xl bg-slate-100 border border-sky-300 shadow-sm">
                <span className="text-[11px] font-extrabold text-slate-700 px-1">
                  類別篩選選項：
                </span>
                {[
                  { id: 'all', label: `全部類別 (${snapshot?.totalFeedsCount ?? 26} 檔)` },
                  { id: 'ext_ip', label: '🔴 外部威脅 IP' },
                  { id: 'fqdn_mail', label: '📧 郵件與惡意網域' },
                  { id: 'internal', label: '🖥️ 內網設備微隔離' },
                  { id: 'allow', label: '✅ 白名單與服務保護' },
                ].map((btn) => (
                  <button
                    key={btn.id}
                    type="button"
                    onClick={() =>
                      setSelectedCategory(btn.id as 'all' | FeedCategory)
                    }
                    className={`px-3 py-1.5 rounded-lg font-bold transition-all cursor-pointer ${
                      selectedCategory === btn.id
                        ? 'bg-sky-600 text-white shadow'
                        : 'bg-white text-slate-800 hover:bg-sky-50 border border-slate-300'
                    }`}
                  >
                    {btn.label}
                  </button>
                ))}
              </div>
            </div>

            {!isUnlocked || !snapshot ? (
              <div className="text-center py-12 text-slate-400">
                🔒 解鎖安全金庫後即顯示各類別清單彙總與即時有效筆數
              </div>
            ) : (
              <>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                  {snapshot.categories.map((cat) => (
                    <div key={cat.category} className="glass-card p-4 space-y-1">
                      <div className="text-xs font-bold text-slate-300">
                        {cat.label}
                      </div>
                      <div className="text-2xl font-extrabold text-white">
                        {cat.totalEntries.toLocaleString()}{' '}
                        <span className="text-xs font-normal text-slate-400">
                          筆 ({cat.fileCount} 檔)
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400">
                        合計大小：{formatBytes(cat.totalBytes)}
                      </div>
                    </div>
                  ))}
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="border-b border-slate-700 bg-slate-900/60 text-slate-300">
                        <th className="p-3">防護類別</th>
                        <th className="p-3">來源 `Fortigate` 原始檔案名稱 (`*.txt` / `*.html`)</th>
                        <th className="p-3 text-right">現行有效筆數</th>
                        <th className="p-3 text-right">與長期清單重疊數</th>
                        <th className="p-3 text-right">資料量大小</th>
                        <th className="p-3">更新頻率</th>
                        <th className="p-3">協防角色說明</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/80">
                      {filteredFeeds.map((f) => (
                        <tr key={f.id} className="hover:bg-slate-800/40">
                          <td className="p-3 whitespace-nowrap">
                            <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-200 font-semibold">
                              {f.categoryLabel}
                            </span>
                          </td>
                          <td className="p-3 font-mono font-bold text-white whitespace-nowrap">
                            <span>📄 {f.displayName}</span>
                            {f.headerMismatch && (
                              <span className="ml-2 px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 text-[10px]">
                                標頭差異 ({f.headerCount})
                              </span>
                            )}
                          </td>
                          <td className="p-3 text-right font-mono font-bold text-sky-300">
                            {f.count.toLocaleString()}
                          </td>
                          <td className="p-3 text-right font-mono text-slate-400">
                            {f.overlapWithLongTerm !== null
                              ? `${f.overlapWithLongTerm.toLocaleString()} 筆`
                              : '—'}
                          </td>
                          <td className="p-3 text-right font-mono text-slate-400">
                            {formatBytes(f.bytes)}
                          </td>
                          <td className="p-3 text-slate-300 whitespace-nowrap">
                            {f.cadenceLabel}
                          </td>
                          <td className="p-3 text-slate-300">{f.description}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </section>
        )}

        {/* ==================== TAB 4: CAPACITY WATERMARK & ISO 27001:2022 ==================== */}
        {activeTab === 'compliance' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <section className="glass-panel p-6 space-y-4">
              <h2 className="text-lg font-bold text-white">
                📊 肆、邊界防護設備容量水位監控與預警線（Capacity Watermarks）
              </h2>
              <p className="text-xs text-slate-400">
                針對單一外部動態清單 131,072 筆標準上限設置 70%（黃燈預警）與 85%（紅燈警戒）水位線
              </p>

              {!isUnlocked || !snapshot ? (
                <div className="py-10 text-center text-slate-400 text-sm">
                  🔒 解鎖安全金庫後即顯示容量水位與達標預估天數
                </div>
              ) : (
                <div className="space-y-4 pt-2">
                  <div>
                    <div className="flex justify-between text-xs mb-1.5">
                      <span className="text-slate-200 font-semibold">
                        1. 單一動態清單標準筆數上限 (LongTerm{' '}
                        {snapshot.capacity.longTermCount.toLocaleString()} /{' '}
                        {snapshot.capacity.singleListLimit.toLocaleString()} 筆)
                      </span>
                      <span
                        className={`font-bold ${
                          snapshot.capacity.singleListAlertLevel === 'critical'
                            ? 'text-rose-400'
                            : snapshot.capacity.singleListAlertLevel === 'warning'
                            ? 'text-amber-300'
                            : 'text-emerald-400'
                        }`}
                      >
                        {snapshot.capacity.singleListPct}% (
                        {snapshot.capacity.singleListAlertLevel === 'critical'
                          ? '🔴 超過 85% 警戒線'
                          : snapshot.capacity.singleListAlertLevel === 'warning'
                          ? '🟡 超過 70% 預警線'
                          : '🟢 安全水位 <70%'}
                        )
                      </span>
                    </div>
                    <div className="w-full h-3 rounded-full bg-slate-800 overflow-hidden relative">
                      <div
                        className="h-full rounded-full transition-all"
                        style={{
                          width: `${Math.min(100, snapshot.capacity.singleListPct)}%`,
                          background:
                            snapshot.capacity.singleListAlertLevel === 'critical'
                              ? '#ef4444'
                              : snapshot.capacity.singleListAlertLevel === 'warning'
                              ? '#f59e0b'
                              : '#38bdf8',
                        }}
                      />
                    </div>
                    <div className="text-[11px] text-slate-400 mt-1 flex flex-wrap justify-between gap-2">
                      <span>
                        • 首批 30 天 TTL 退場日：
                        <strong className="text-slate-200">
                          {snapshot.capacity.firstTtlExpiryDate}
                        </strong>
                      </span>
                      {snapshot.capacity.estimatedDaysTo100k !== null && (
                        <span>
                          • 按近3日增速預估：約{' '}
                          <strong className="text-amber-300">
                            {snapshot.capacity.estimatedDaysTo100k} 天
                          </strong>
                          後達 10 萬筆
                        </span>
                      )}
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between text-xs mb-1.5">
                      <span className="text-slate-200 font-semibold">
                        2. 單一清單檔案大小上限 (
                        {formatBytes(snapshot.capacity.longTermBytes)} / 10.00 MB)
                      </span>
                      <span className="font-bold text-emerald-400">
                        {snapshot.capacity.fileSizePct}% (極度充裕)
                      </span>
                    </div>
                    <div className="w-full h-2.5 rounded-full bg-slate-800 overflow-hidden">
                      <div
                        className="h-full rounded-full bg-emerald-500"
                        style={{
                          width: `${Math.min(100, snapshot.capacity.fileSizePct)}%`,
                        }}
                      />
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between text-xs mb-1.5">
                      <span className="text-slate-200 font-semibold">
                        3. 全系統總指標標準容量 (
                        {(
                          snapshot.rawExternalBlockEntries +
                          snapshot.protectedAndInternalEntries
                        ).toLocaleString()}{' '}
                        / 300,000 筆)
                      </span>
                      <span className="font-bold text-sky-400">
                        {snapshot.capacity.systemStandardPct}%
                      </span>
                    </div>
                    <div className="w-full h-2.5 rounded-full bg-slate-800 overflow-hidden">
                      <div
                        className="h-full rounded-full bg-sky-500"
                        style={{
                          width: `${Math.min(
                            100,
                            snapshot.capacity.systemStandardPct
                          )}%`,
                        }}
                      />
                    </div>
                  </div>

                  <div className="glass-card p-4 text-xs text-slate-300 space-y-1.5">
                    <div className="font-bold text-amber-300">
                      📌 容量治理建議（Operational Advisory）
                    </div>
                    <p className="leading-relaxed">
                      由於長期協防黑名單於 2026-10-30 啟用 30 天 TTL，在{' '}
                      <strong>2026-11-29 首批過期退場前</strong>屬「只進不出」累積期。當單一清單水位突破 70%（約 91,750 筆）時，可採取：(1) 將 TTL 由 30 天調降為 21 天，或 (2) 拆分為兩份動態清單分流掛載。
                    </p>
                  </div>
                </div>
              )}
            </section>

            <section className="glass-panel p-6 space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-bold text-white">
                  ⚖️ 伍、資通安全管理法與 ISO/IEC 27001:2022 對映矩陣
                </h2>
                <span className="px-2.5 py-0.5 rounded-full text-[11px] bg-purple-500/20 text-purple-300 border border-purple-500/30">
                  待資安官最終確認
                </span>
              </div>
              <p className="text-xs text-slate-400">
                對應《資通安全管理法》、主管機關資安稽核重點與 ISO/IEC 27001:2022 最新版控制項（編號供稽核對照參考，交由資安官確認後定稿）
              </p>

              <div className="space-y-3 text-xs">
                <div className="glass-card p-4 space-y-1">
                  <div className="font-bold text-sky-300">
                    1. ISO/IEC 27001:2022 A.5.7 — 威脅情資（Threat Intelligence）
                  </div>
                  <p className="text-slate-300 leading-relaxed">
                    自動匯集國際 AbuseIPDB 高信賴黑名單、國內 CERT 聯防情資與內部骨幹流量探針，建立跨層級情資收集、正規化清洗與自動化阻斷機制。
                  </p>
                </div>

                <div className="glass-card p-4 space-y-1">
                  <div className="font-bold text-sky-300">
                    2. ISO/IEC 27001:2022 A.8.20 — 網路安全（Networks Security）
                  </div>
                  <p className="text-slate-300 leading-relaxed">
                    透過邊界防火牆動態威脅清單 (EDL) 實施邊界動態隔離與內部 IoT / 網通設備 / 伺服器群微隔離控管。
                  </p>
                </div>

                <div className="glass-card p-4 space-y-1">
                  <div className="font-bold text-sky-300">
                    3. ISO/IEC 27001:2022 A.8.23 — 網頁過濾（Web Filtering）
                  </div>
                  <p className="text-slate-300 leading-relaxed">
                    維護惡意網域黑名單（支援萬用字元與掃描器反解紀錄），阻絕釣魚網站與木馬 C2 連線。
                  </p>
                </div>

                <div className="glass-card p-4 space-y-1">
                  <div className="font-bold text-sky-300">
                    4. ISO/IEC 27001:2022 A.8.32 — 變更管理（Change Management）
                  </div>
                  <p className="text-slate-300 leading-relaxed">
                    採用開發庫與發布庫職責分離架構，每次清單異動均留存 Git 版本控管軌跡，並具備白名單防誤封與異常暴跌保護機制。
                  </p>
                </div>
              </div>
            </section>
          </div>
        )}

        {/* ==================== TAB 5: METHODOLOGY & DATA SOURCES ==================== */}
        {activeTab === 'methodology' && (
          <section className="glass-panel p-6 space-y-5">
            <div>
              <h2 className="text-lg font-bold text-white">
                📘 陸、方法論、指標公式與資料來源透明化聲明（Methodology &amp; Audit Notes）
              </h2>
              <p className="text-xs text-slate-400">
                供資安維運人員與稽核人員核對各項統計數字之計算邏輯與邊界限制
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div className="glass-card p-4 space-y-2">
                <h3 className="font-bold text-sky-300 text-sm">
                  1. 「名單規模」與「實際攔截次數」之嚴格區分
                </h3>
                <p className="text-slate-300 leading-relaxed">
                  本前臺同步自自動化情資發布庫，所呈現之數字皆為
                  <strong>「生效中之防護規則／指標筆數（Active Indicators in EDL）」</strong>，而非邊界防火牆硬體之「封包攔截命中次數（Firewall Traffic Hits）」。實際封包攔截統計由日誌分析平台另行產出。
                </p>
              </div>

              <div className="glass-card p-4 space-y-2">
                <h3 className="font-bold text-sky-300 text-sm">
                  2. 外部封鎖唯一 IPv4（Unique External Block IPv4）計算公式
                </h3>
                <p className="text-slate-300 leading-relaxed">
                  由於當日短期快篩清單與 30 天長期黑名單之間存在部分重疊，本系統於伺服器端將 10 份「外部威脅 IP」清單載入記憶體執行 <code>Set</code> 去重聯集（Union），並將<strong>白名單與內部資產清冊完全排除於封鎖指標之外</strong>，確保絕不灌水重複計算。
                </p>
              </div>

              <div className="glass-card p-4 space-y-2">
                <h3 className="font-bold text-sky-300 text-sm">
                  3. 每日自動化排程巡檢次數（440 次/日）推導依據
                </h3>
                <p className="text-slate-300 leading-relaxed">
                  依據自動化排程實機設定：
                  <br />• <code>郵件閘道威脅封鎖引擎 (v2.1)</code>：每 10 分鐘執行 1 次 = <strong>144 次/日</strong>
                  <br />• <code>外部聯防情資同步引擎 (v2.1)</code>：每 10 分鐘執行 1 次 = <strong>144 次/日</strong>
                  <br />• <code>骨幹流量即時感知引擎 (v4.5)</code>：每 10 分鐘執行 1 次 = <strong>144 次/日</strong>
                  <br />• <code>長期累犯與全球黑名單引擎 (v1.0.1)</code>：每 3 小時執行 1 次 = <strong>8 次/日</strong>
                  <br />合計每日自動巡檢 <code>144 × 3 + 8 = 440</code> 次（僅在清單內容有實質異動時才會產生版本提交）。
                </p>
              </div>

              <div className="glass-card p-4 space-y-2">
                <h3 className="font-bold text-sky-300 text-sm">
                  4. 內網網段誤入外部黑名單數（Internal Leak Verification）
                </h3>
                <p className="text-slate-300 leading-relaxed">
                  為取代無法直接由情資庫量測的「誤封率 %」，本前臺於每次快照解析時，自動掃描全部 10 份外部 IP 封鎖清單是否含有受保護內部網段或私網（RFC 1918）IP。實測結果為 <strong>0 筆</strong>，提供百分之百可驗證之防誤封佐證。
                </p>
              </div>
            </div>
          </section>
        )}

        {/* Footer */}
        <footer className="pt-6 border-t border-slate-800/80 text-center text-xs text-slate-500 space-y-1">
          <div>
            © 2026 <strong>資安防護清單與威脅情資自動化更新系統</strong> ·
            Powered by Next.js &amp; AES-256-GCM Zero-Knowledge Security Vault
          </div>
          <div>
            本系統對上游情資發布庫採純唯讀架構（Zero-Write），並已執行組織與設備去識別化保護。
          </div>
        </footer>
      </main>

      {/* ==================== SECURITY VAULT UNLOCK MODAL ==================== */}
      {showVaultModal && (
        <div className="modal-backdrop no-print">
          <div className="vault-dialog">
            <div className="vault-glow-circle">🔐</div>
            <div className="inline-block px-3 py-0.5 rounded-full bg-sky-500/20 border border-sky-400/30 text-sky-300 text-[11px] font-bold tracking-wider mb-2">
              CTI DEFENSE AES-256-GCM SECURITY VAULT
            </div>
            <h2 className="text-xl font-extrabold text-white mb-2">
              資安情資系統 · 安全金庫驗證
            </h2>
            <p className="text-xs sm:text-sm text-slate-400 leading-relaxed mb-5">
              本系統統計數據與 IP 封鎖查詢資料採用{' '}
              <strong className="text-slate-200">AES-256-GCM 密文加密保護</strong>。<br />
              公開伺服器未儲存任何明文統計或金鑰，請輸入通行密鑰或點擊專屬授權連結解鎖。
            </p>

            {serverError && (
              <div className="mb-4 p-3 rounded-xl bg-amber-500/20 border border-amber-400/40 text-amber-200 text-xs text-left">
                ⚠️ 伺服器狀態提示：{serverError}
              </div>
            )}

            <div className="flex items-center bg-slate-900/90 border border-slate-700 focus-within:border-sky-400 rounded-xl px-3.5 py-1 mb-3.5">
              <span className="text-base mr-2.5">🔑</span>
              <input
                type={showPassText ? 'text' : 'password'}
                value={passInput}
                onChange={(e) => setPassInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    attemptUnlockWithKey(passInput);
                  }
                }}
                placeholder="請輸入金庫解鎖密鑰 (Passkey)..."
                className="flex-1 bg-transparent border-none text-white text-sm py-2.5 outline-none placeholder:text-slate-500"
                autoFocus
              />
              <button
                type="button"
                onClick={() => setShowPassText((v) => !v)}
                className="text-slate-400 hover:text-sky-400 p-1 text-base"
                title="顯示/隱藏密碼"
              >
                {showPassText ? '🔒' : '👁️'}
              </button>
            </div>

            {vaultError && (
              <div className="mb-3.5 p-2.5 rounded-xl bg-rose-500/20 border border-rose-500/40 text-rose-200 text-xs text-left">
                {vaultError}
              </div>
            )}

            <button
              type="button"
              disabled={loadingApi}
              onClick={() => attemptUnlockWithKey(passInput)}
              className="w-full py-3 px-4 rounded-xl bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-600 hover:to-blue-700 text-white font-bold text-sm shadow-lg shadow-sky-500/30 transition-all flex items-center justify-center gap-2 disabled:opacity-50"
            >
              <span>
                {loadingApi ? '⏳ 正在載入加密快照...' : '🔓 立即解密並進入系統'}
              </span>
            </button>

            <div className="flex items-center my-4 text-slate-500 text-xs">
              <div className="flex-1 border-b border-slate-800" />
              <span className="px-3">檢視權限申請</span>
              <div className="flex-1 border-b border-slate-800" />
            </div>

            <div className="flex items-center justify-between gap-3 p-3 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 text-left">
              <div className="flex items-center gap-2.5">
                <span className="w-9 h-9 rounded-xl bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-lg">
                  📲
                </span>
                <div>
                  <div className="text-xs font-bold text-white">
                    尚未取得通行密鑰？
                  </div>
                  <div className="text-[11px] text-slate-400">
                    透過資安管理窗口或 LINE 官方機器人取得 1-Click 授權連結
                  </div>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setShowApplyModal(true)}
                className="px-3 py-2 rounded-xl bg-[#06c755] hover:bg-[#05b34c] text-white font-bold text-xs whitespace-nowrap shadow"
              >
                申請密鑰
              </button>
            </div>

            <div className="mt-3.5 p-3 rounded-xl bg-slate-900/60 border border-slate-800 text-left text-[11px] text-slate-400 space-y-1">
              <div className="font-bold text-sky-400">
                💡 1-Click 快捷授權說明
              </div>
              <div>
                • 點擊<strong>專屬核發授權連結（附帶 ?auth= 參數）</strong>時，系統將自動瞬間解密並抹除網址列參數。
                <br />• 授權狀態會在當前工作階段（Session）妥善保存，點擊右上角「🔐 金庫已解鎖」可隨時重新鎖定。
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ==================== PASSKEY APPLICATION MODAL ==================== */}
      {showApplyModal && (
        <div className="modal-backdrop no-print">
          <div className="vault-dialog text-left">
            <div className="flex items-center justify-between mb-3">
              <span className="px-2.5 py-0.5 rounded-full bg-[#06c755] text-white text-[11px] font-bold">
                CTI VAULT ACCESS REQUEST
              </span>
              <button
                type="button"
                onClick={() => setShowApplyModal(false)}
                className="text-slate-400 hover:text-white text-xl leading-none"
              >
                &times;
              </button>
            </div>
            <h3 className="text-lg font-bold text-white mb-1">
              📲 資安情資系統 · 檢視密鑰申請
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              本系統供授權資安與網路維運管理人員檢視與查詢。請透過以下方式聯繫管理員取得通行密鑰或 1-Click 解密連結：
            </p>

            <div className="space-y-2.5 text-xs text-slate-300 mb-4">
              <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
                <div className="font-bold text-white mb-0.5">
                  步驟 1：聯繫資安情資維運窗口
                </div>
                <div className="text-slate-400">
                  可透過 LINE 官方帳號（<code>@208jinte</code>）提交申請。
                </div>
              </div>
              <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
                <div className="font-bold text-white mb-0.5">
                  步驟 2：註明單位與用途
                </div>
                <div className="text-slate-400">
                  傳送：<code>【申請資安情資系統密鑰】姓名 / 單位與用途</code>。
                </div>
              </div>
              <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
                <div className="font-bold text-white mb-0.5">
                  步驟 3：取得 1-Click 解密連結
                </div>
                <div className="text-slate-400">
                  核准後將回傳專屬 Token 連結，點擊即可直接解鎖檢視最新動態資訊與查詢 IP。
                </div>
              </div>
            </div>

            <a
              href="https://line.me/R/ti/p/@208jinte"
              target="_blank"
              rel="noreferrer"
              className="block w-full py-2.5 rounded-xl bg-[#06c755] hover:bg-[#05b34c] text-white font-bold text-center text-sm mb-2"
            >
              💬 透過 LINE 官方帳號申請 (@208jinte)
            </a>
            <button
              type="button"
              onClick={() => setShowApplyModal(false)}
              className="w-full py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 font-semibold text-xs"
            >
              返回密鑰輸入畫面
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
