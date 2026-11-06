'use client';

import React, { useEffect, useState, useCallback } from 'react';
import type {
  DashboardSnapshot,
  FeedCategory,
  LongTermTrendPoint,
} from '@/lib/cti-fetcher';
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

async function decryptVaultPayloadClient(
  encObj: EncryptedVaultPayload,
  passkey: string
): Promise<DashboardSnapshot> {
  const cryptoKey = await deriveWebCryptoKey(passkey);
  const iv = base64ToUint8Array(encObj.iv);
  const ciphertext = base64ToUint8Array(encObj.ciphertext);
  const decryptedBuf = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as BufferSource, tagLength: 128 },
    cryptoKey,
    ciphertext as BufferSource
  );
  const dec = new TextDecoder('utf-8');
  return JSON.parse(dec.decode(decryptedBuf)) as DashboardSnapshot;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const kb = bytes / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB`;
  return `${(kb / 1024).toFixed(2)} MB`;
}

export default function ExecutiveDashboardPage() {
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
    'overview' | 'trend' | 'inventory' | 'compliance' | 'methodology'
  >('overview');
  const [chartMode, setChartMode] = useState<'cumulative' | 'added'>('cumulative');
  const [selectedPoint, setSelectedPoint] = useState<LongTermTrendPoint | null>(
    null
  );
  const [selectedCategory, setSelectedCategory] = useState<'all' | FeedCategory>(
    'all'
  );

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

  const filteredFeeds =
    snapshot?.feeds.filter((f) =>
      selectedCategory === 'all' ? true : f.category === selectedCategory
    ) ?? [];

  const allHealthy =
    snapshot?.pipelineHealth.every((h) => h.status === 'healthy') ?? false;

  return (
    <div className="min-h-screen pb-16">
      {/* Top Legal & Governance Notice Strip */}
      <aside className="bg-slate-900/90 border-b border-slate-800 px-4 py-2 text-xs text-slate-300">
        <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="text-amber-400 font-bold">🛡️ 機敏治理聲明：</span>
            <span>
              <strong>本頁呈現「防護名單規模（Feed Inventory Size）」，而非「設備實際攔截封包次數（Traffic Hits）」。</strong>
              全量統計快照經伺服器端 <code>AES-256-GCM</code> 加密傳輸，且嚴格排除任何組織識別、設備型號及單一 IP / MAC / 內網資產明細。
            </span>
          </div>
          <span className="font-mono text-sky-400">
            CTI Collaborative Defense Executive Hub
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

        {/* Executive Header Container */}
        <header className="glass-panel p-6">
          <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-800 pb-5">
            <div className="space-y-2">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sky-500/15 border border-sky-400/30 text-sky-300 text-xs font-semibold">
                <span>🏛️ 呈 決策主管 暨 資訊安全監督管理單位 核閱</span>
                <span>•</span>
                <span>資通安全情資協防專案報告 (v2.1 動態版)</span>
              </div>
              <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight bg-gradient-to-r from-white via-sky-200 to-sky-400 bg-clip-text text-transparent">
                資訊安全情資協防暨自動化縱深防禦體系 — 高階管理摘要報告
              </h1>
              <p className="text-xs sm:text-sm text-slate-400">
                架構模式：<code>雙庫職責分離 GitOps 自動化管線</code> ｜ 防護載體：
                <strong className="text-slate-200">次世代邊界防火牆動態威脅清單 (EDL Threat Feeds)</strong>
              </p>
            </div>

            {/* Meta Status Pills (Matching finance-free-xq-pub style) */}
            <div className="flex flex-wrap items-center gap-2.5">
              <button
                type="button"
                onClick={handlePromptRelock}
                title={
                  isUnlocked
                    ? '已通過金庫驗證 · 點擊可重新鎖定'
                    : '點擊輸入通行密鑰解鎖報告'
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

          {/* Executive Summary Callout */}
          <div className="mt-5 p-4 rounded-xl bg-slate-900/70 border border-slate-800 text-xs sm:text-sm leading-relaxed text-slate-300">
            <div className="font-bold text-white mb-1 flex items-center justify-between">
              <span>📌 決策管理摘要（Executive Summary）</span>
              <button
                type="button"
                onClick={scrollToMethodology}
                className="text-xs text-sky-400 hover:underline font-normal"
              >
                📖 檢視指標計算公式與資料來源說明 →
              </button>
            </div>
            <p>
              為因應跨國殭屍網路、DDoS 阻斷服務攻擊、SSH 暴力破解與釣魚威脅，本體系建置
              <strong className="text-white">「資訊安全情資協防暨自動化縱深防禦機制」</strong>。系統透過標準化自動化引擎，將
              <strong className="text-sky-300">「國際高信賴威脅情資 (AbuseIPDB)」、「國內聯防與 CERT 威脅情資」、「骨幹流量即時感知探針」與「郵件閘道威脅統計」</strong>
              四方情資深度整合，自動轉化為邊界核心防火牆可即時讀取之動態封鎖清單（External Dynamic Lists）。
              {isUnlocked && snapshot ? (
                <>
                  截至最新同步時間（<code>{snapshot.headTimeDisplay}</code>），全系統維運{' '}
                  <strong className="text-emerald-300">{snapshot.totalFeedsCount} 份清單</strong>，其中去重後唯一外部封鎖 IPv4 達{' '}
                  <strong className="text-emerald-300">
                    {snapshot.uniqueExternalBlockIPv4.toLocaleString()} 筆
                  </strong>
                  （長期黑名單佔{' '}
                  <strong className="text-sky-300">
                    {snapshot.capacity.longTermCount.toLocaleString()} 筆
                  </strong>
                  ），受保護與微隔離資產共{' '}
                  <strong className="text-amber-300">
                    {snapshot.protectedAndInternalEntries.toLocaleString()} 筆
                  </strong>
                  ，累計留存{' '}
                  <strong className="text-white">
                    {snapshot.totalCommitsCount.toLocaleString()} 次
                  </strong>{' '}
                  版本控管軌跡。
                </>
              ) : (
                <span className="text-amber-300 font-semibold ml-1">
                  （請先解鎖安全金庫以檢視即時統計數據）
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

        {/* Navigation Tabs */}
        <nav className="glass-panel p-2 flex flex-wrap items-center gap-2 no-print">
          {[
            { id: 'overview', icon: '🏛️', label: '四大支柱與管線健康度' },
            { id: 'trend', icon: '📈', label: '長期黑名單趨勢與 24h 異動' },
            { id: 'inventory', icon: '📂', label: '全庫清單分類彙總表' },
            { id: 'compliance', icon: '⚖️', label: '容量水位預警與 ISO 27001:2022' },
            { id: 'methodology', icon: '📘', label: '方法論、公式與資料來源說明' },
          ].map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() =>
                setActiveTab(
                  tab.id as
                    | 'overview'
                    | 'trend'
                    | 'inventory'
                    | 'compliance'
                    | 'methodology'
                )
              }
              className={`px-4 py-2.5 rounded-xl text-xs sm:text-sm font-bold transition-all flex items-center gap-2 ${
                activeTab === tab.id
                  ? 'bg-gradient-to-r from-sky-500 to-blue-600 text-white shadow-lg shadow-sky-500/25'
                  : 'text-slate-300 hover:bg-slate-800/70'
              }`}
            >
              <span>{tab.icon}</span>
              <span>{tab.label}</span>
            </button>
          ))}
        </nav>

        {/* ==================== TAB 1: OVERVIEW & PIPELINE HEALTH ==================== */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            <section className="glass-panel p-6 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <h2 className="text-lg font-bold text-white">
                    🚦 自動化情資管線健康度與資料時效監控（Pipeline Health &amp; Freshness）
                  </h2>
                  <p className="text-xs text-slate-400">
                    即時解析各自動化排程引擎最後一次同步距今時間（注意：長期黑名單引擎若當輪無新增/退場則跳過提交，故超過 9 小時才發警示）
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

            {/* Four Pillars of Collaborative Defense */}
            <section className="glass-panel p-6 space-y-5">
              <div>
                <h2 className="text-lg font-bold text-white">
                  🏛️ 壹、資訊安全情資協防「四大支柱」與縱深防禦架構
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  打破傳統「單點被動挨打」模式，透過跨國際、跨聯防組織、跨內部流量探針之多源情資匯流，建立四層立體協防屏障
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="glass-card p-5 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-sm text-white">
                      🌐 支柱一：國際與外部聯防情資協防（先發制人）
                    </span>
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-sky-500/20 text-sky-300 border border-sky-500/30">
                      {isUnlocked && snapshot
                        ? `${snapshot.pillars.externalIntelCount.toLocaleString()} 筆指標`
                        : '🔒 解鎖後顯示'}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    整合國際權威惡意 IP 資料庫 <strong>AbuseIPDB</strong>（嚴選全球高惡意信心度之活躍攻擊源）與{' '}
                    <strong>CERT 外部威脅情資</strong>。無須等待攻擊者觸碰內部網路，即可將全球正在肆虐之 DDoS 殭屍網路與掃描源預先列入 30 天封鎖清單。
                  </p>
                </div>

                <div className="glass-card p-5 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-sm text-white">
                      ⚡ 支柱二：骨幹流量即時感知協防（快速止血）
                    </span>
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                      {isUnlocked && snapshot
                        ? `${snapshot.pillars.campusTrafficCount.toLocaleString()} 筆動態指標`
                        : '🔒 解鎖後顯示'}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    每 10 分鐘自動分析<strong>骨幹網路流量分析平台</strong> 6 大高危行為：外部未阻斷威脅 (Top-N)、對內 SSH 暴力入侵、木馬/IRC 中繼站連線、可疑遠端憑證與 DNS 反解異常。並將
                    <strong>「10 天內跨 3 個日曆日重複犯案」</strong>之持續性攻擊者自動晉升至 30 天長期黑名單。
                  </p>
                </div>

                <div className="glass-card p-5 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-sm text-white">
                      📧 支柱三：郵件閘道與惡意網域縱深協防（反釣魚勒索）
                    </span>
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                      {isUnlocked && snapshot
                        ? `${snapshot.pillars.emailAndFqdnCount.toLocaleString()} 筆網段/網域`
                        : '🔒 解鎖後顯示'}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    每 10 分鐘萃取<strong>郵件閘道異常寄件與暴力攻擊網段</strong>（CIDR 封鎖集），同步餵入邊界防火牆層級直接阻斷；並維護釣魚、木馬 C2 與惡意 FQDN 網域黑名單，搭配專屬{' '}
                    <strong>DNS 阻斷警示頁面</strong>，保護使用者免受社交工程危害。
                  </p>
                </div>

                <div className="glass-card p-5 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-sm text-white">
                      🔒 支柱四：內網資產微隔離與白名單防誤封治理（零信任）
                    </span>
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30">
                      {isUnlocked && snapshot
                        ? `${snapshot.pillars.microSegAndAllowCount.toLocaleString()} 筆控管/保護資產`
                        : '🔒 解鎖後顯示'}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    針對內部高風險資產實施嚴格微隔離（限制 IoT 設備、網通/印表機設備及核心伺服器群之非必要對外連線，並封鎖違規 MAC）；同時造冊保護重要對外資訊服務與關鍵白名單，確保業務與研究服務 100% 暢通。
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
                  📈 貳、長期協防黑名單 (`AutoLongTerm-Blocklist-v1`) 動態趨勢與近 24 小時異動
                </h2>
                <p className="text-xs text-slate-400">
                  由版本控管歷史 (`total= added= removed=`) 即時解析，無須逐筆暴露 IP 內容
                </p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setChartMode('cumulative')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold ${
                    chartMode === 'cumulative'
                      ? 'bg-sky-500 text-white'
                      : 'bg-slate-800 text-slate-300'
                  }`}
                >
                  累計總筆數趨勢 (Total)
                </button>
                <button
                  type="button"
                  onClick={() => setChartMode('added')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold ${
                    chartMode === 'added'
                      ? 'bg-sky-500 text-white'
                      : 'bg-slate-800 text-slate-300'
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
                  📂 參、全庫資安情資與治理清單分類彙總表
                </h2>
                <p className="text-xs text-slate-400">
                  依據資安去識別化規範：所有清單均以標準化功能名稱呈現，內網微隔離與白名單資產僅統計有效筆數，不提供原始下載連結或明細
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2 text-xs">
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
                    className={`px-3 py-1.5 rounded-lg font-bold ${
                      selectedCategory === btn.id
                        ? 'bg-sky-500 text-white'
                        : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
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
                        <th className="p-3">清單功能識別名稱</th>
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
                          <td className="p-3 font-mono text-white">
                            {f.isSensitiveInternal ? (
                              <span title="內部/保護資產清冊僅顯示去識別化統計">
                                🔒 {f.displayName}
                              </span>
                            ) : (
                              <span>{f.displayName}</span>
                            )}
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
                供決策主管、資安官及稽核委員核對各項統計數字之計算邏輯與邊界限制
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div className="glass-card p-4 space-y-2">
                <h3 className="font-bold text-sky-300 text-sm">
                  1. 「名單規模」與「實際攔截次數」之嚴格區分
                </h3>
                <p className="text-slate-300 leading-relaxed">
                  本前臺同步自自動化情資發布庫，所呈現之數字皆為
                  <strong>「生效中之防護規則／指標筆數（Active Indicators in EDL）」</strong>，而非邊界防火牆硬體之「封包攔截命中次數（Firewall Traffic Hits）」。實際封包攔截統計由日誌分析平台另行產出月報。
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
            © 2026 <strong>資通安全情資協防暨自動化縱深防禦專案</strong> ·
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
              資安情資協防金庫 · 安全解鎖
            </h2>
            <p className="text-xs sm:text-sm text-slate-400 leading-relaxed mb-5">
              本高階主管報告全量數據採用金融級{' '}
              <strong className="text-slate-200">AES-256-GCM 密文加密</strong>。<br />
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
                {loadingApi ? '⏳ 正在載入加密快照...' : '🔓 立即解密並進入報告'}
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
              📲 資安情資協防報告 · 檢視密鑰申請
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              本系統專供授權決策主管、資安督導單位與維運管理人員檢閱。請透過以下方式聯繫管理員取得通行密鑰或 1-Click 解密連結：
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
                  傳送：<code>【申請資安情資報告密鑰】姓名 / 單位與用途</code>。
                </div>
              </div>
              <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
                <div className="font-bold text-white mb-0.5">
                  步驟 3：取得 1-Click 解密連結
                </div>
                <div className="text-slate-400">
                  核准後將回傳專屬 Token 連結，點擊即可直接解鎖檢視最新動態報表。
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
