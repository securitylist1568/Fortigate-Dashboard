import { FEEDS_MANIFEST, TOTAL_DAILY_CRON_RUNS } from './feeds.manifest';
import {
  parseFeedContent,
  ipv4ToUint32,
  parseCidrRange,
  ParsedCidrRange,
  EntryMetaInfo,
} from './parsers';
import {
  buildLongTermTrend,
  evaluatePipelineHealth,
  formatTaipeiTime,
} from './trend';
import type {
  FeedCategory,
  FeedKind,
  GeneratorScriptId,
  DailyLongTermTrend,
  GitHubCommitItem,
  LongTermTrendPoint,
  ScriptHealthStatus,
  FeedSnapshotItem,
  CategorySummary,
  CapacityStatus,
  DashboardSnapshot,
  IpQueryFeedMatch,
  IpQueryResultItem,
  IpQueryResponsePayload,
} from './types';

export type {
  FeedCategory,
  FeedKind,
  GeneratorScriptId,
  DailyLongTermTrend,
  GitHubCommitItem,
  LongTermTrendPoint,
  ScriptHealthStatus,
  FeedSnapshotItem,
  CategorySummary,
  CapacityStatus,
  DashboardSnapshot,
  IpQueryFeedMatch,
  IpQueryResultItem,
  IpQueryResponsePayload,
};

interface IndexedCidrEntry extends ParsedCidrRange {
  lineNumber: number;
  comment: string | null;
}

interface HistoricalIpSighting {
  lastSeenSha: string;
  lastSeenDisplay: string;
  lineNumber: number;
}

interface FeedIpIndex {
  id: string;
  fileName: string;
  displayName: string;
  category: FeedCategory;
  categoryLabel: string;
  kind: FeedKind;
  generator: GeneratorScriptId;
  generatorLabel: string;
  cadenceLabel: string;
  description: string;
  isBlocklist: boolean;
  exactIps: Map<string, EntryMetaInfo>;
  cidrRanges: IndexedCidrEntry[];
  fqdnEntries: Map<string, EntryMetaInfo>;
  macEntries: Map<string, EntryMetaInfo>;
}

// In-memory state for ETag conditional requests, IP lookup index, historical 10-day index, and stale-on-error fallback
let cachedHeadEtag: string | null = null;
let cachedHeadSha: string | null = null;
let cachedSnapshot: DashboardSnapshot | null = null;
let cachedIpLookupIndex: Map<string, FeedIpIndex> | null = null;
let cachedHistoricalFeedIndex: Map<string, Map<string, HistoricalIpSighting>> | null = null;
let lastHistoricalBuildMs = 0;
let lastSuccessfulFetchMs = 0;

const REVALIDATE_INTERVAL_MS = 180 * 1000; // 3 minutes (aligned with Edge CDN s-maxage=180)
const HISTORICAL_REBUILD_INTERVAL_MS = 7200 * 1000; // 2 hours (past 1-10 days end-of-day snapshots are static)
const HISTORICAL_DYNAMIC_FEED_IDS = [
  'traffic_src_topn',
  'traffic_src_ssh',
  'traffic_src_cert_remote',
  'traffic_src_trojan_irc',
  'traffic_src_dns_ptr',
  'traffic_dst_topn',
  'ntech_ip',
  'emailsys_ipset',
  'emailsys_fqdn',
  'ntech_fqdn',
];

function buildGitHubHeaders(etag?: string | null): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'CTI-Defense-Dashboard/2.1',
  };
  const token = process.env.GITHUB_TOKEN?.trim();
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  if (etag) {
    headers['If-None-Match'] = etag;
  }
  return headers;
}

async function fetchTotalCommitCount(repo: string): Promise<number> {
  try {
    const url = `https://api.github.com/repos/${repo}/commits?sha=main&per_page=1`;
    const res = await fetch(url, {
      headers: buildGitHubHeaders(),
      cache: 'no-store',
    });
    if (!res.ok) return cachedSnapshot?.totalCommitsCount ?? 55743;
    const link = res.headers.get('link') || '';
    const m = link.match(/[?&]page=(\d+)>;\s*rel="last"/i);
    if (m) {
      return parseInt(m[1], 10);
    }
    return cachedSnapshot?.totalCommitsCount ?? 55743;
  } catch {
    return cachedSnapshot?.totalCommitsCount ?? 55743;
  }
}

async function fetchRawFileAtSha(
  repo: string,
  sha: string,
  filePath: string
): Promise<string> {
  const url = `https://raw.githubusercontent.com/${repo}/${sha}/${encodeURIComponent(
    filePath
  )}`;
  const headers: Record<string, string> = {
    'User-Agent': 'CTI-Defense-Dashboard/2.1',
  };
  const token = process.env.GITHUB_TOKEN?.trim();
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  const res = await fetch(url, { headers, cache: 'no-store' });
  if (!res.ok) {
    throw new Error(`Failed to fetch feed at ${sha.slice(0, 7)}: HTTP ${res.status}`);
  }
  return await res.text();
}

export function computeSnapshotFromRawInputs(params: {
  headSha: string;
  headTimeIso: string;
  totalCommitsCount: number;
  rawFilesById: Record<string, string>;
  longTermCommits: GitHubCommitItem[];
  recentCommits: GitHubCommitItem[];
  nowMs?: number;
}): DashboardSnapshot {
  const nowMs = params.nowMs ?? Date.now();
  const nowIso = new Date(nowMs).toISOString();
  const { displayTime: headTimeDisplay } = formatTaipeiTime(params.headTimeIso);
  const { displayTime: fetchedAtDisplay } = formatTaipeiTime(nowIso);

  const parsedMap = new Map<
    string,
    ReturnType<typeof parseFeedContent>
  >();

  for (const def of FEEDS_MANIFEST) {
    const raw = params.rawFilesById[def.id] ?? '';
    const checkLeak = def.category === 'ext_ip' && def.kind === 'ip';
    const parsed = parseFeedContent(raw, def.kind, checkLeak);
    parsedMap.set(def.id, parsed);
  }

  const longTermSet = parsedMap.get('longterm_auto')?.entriesSet ?? new Set<string>();
  const uniqueExternalIPv4Union = new Set<string>();
  let internalMisblockCount = 0;
  let rawExternalBlockEntries = 0;
  let protectedAndInternalEntries = 0;

  const feedItems: FeedSnapshotItem[] = [];

  for (const def of FEEDS_MANIFEST) {
    const p = parsedMap.get(def.id)!;

    if (def.category === 'ext_ip' && def.kind === 'ip') {
      internalMisblockCount += p.internalLeakCount;
      for (const ip of p.entriesSet) {
        uniqueExternalIPv4Union.add(ip);
      }
    }

    if (
      def.category === 'ext_ip' ||
      (def.category === 'fqdn_mail' && def.kind !== 'html')
    ) {
      rawExternalBlockEntries += p.count;
    } else if (def.category === 'internal' || def.category === 'allow') {
      protectedAndInternalEntries += p.count;
    }

    let overlapWithLongTerm: number | null = null;
    if (
      def.category === 'ext_ip' &&
      def.kind === 'ip' &&
      def.id !== 'longterm_auto'
    ) {
      let overlap = 0;
      for (const ip of p.entriesSet) {
        if (longTermSet.has(ip)) overlap += 1;
      }
      overlapWithLongTerm = overlap;
    }

    feedItems.push({
      id: def.id,
      displayName: def.file,
      category: def.category,
      categoryLabel: def.categoryLabel,
      kind: def.kind,
      generator: def.generator,
      generatorLabel: def.generatorLabel,
      cadenceLabel: def.cadenceLabel,
      description: def.description,
      isSensitiveInternal: def.isSensitiveInternal,
      isBlocklist: def.isBlocklist,
      count: p.count,
      bytes: p.bytes,
      headerCount: p.headerCount,
      headerMismatch: p.headerMismatch,
      overlapWithLongTerm,
    });
  }

  // Build in-memory lookup index across ALL 25 data feeds in Fortigate repository
  const newLookupIndex = new Map<string, FeedIpIndex>();
  for (const def of FEEDS_MANIFEST) {
    if (def.kind === 'html') continue;

    const p = parsedMap.get(def.id);
    if (!p) continue;

    const exactIps = new Map<string, EntryMetaInfo>();
    const cidrRanges: IndexedCidrEntry[] = [];
    const fqdnEntries = new Map<string, EntryMetaInfo>();
    const macEntries = new Map<string, EntryMetaInfo>();

    for (const entry of p.entriesSet) {
      const meta = p.entryMetaMap.get(entry) ?? {
        lineNumber: 0,
        comment: null,
      };

      if (def.kind === 'fqdn') {
        fqdnEntries.set(entry.toLowerCase(), meta);
      } else if (def.kind === 'mac') {
        macEntries.set(entry.toUpperCase(), meta);
      } else if (entry.includes('/')) {
        const bare = entry.endsWith('/32') ? entry.slice(0, -3) : null;
        if (bare) {
          exactIps.set(bare, meta);
        } else {
          const parsedCidr = parseCidrRange(entry);
          if (parsedCidr) {
            cidrRanges.push({
              ...parsedCidr,
              lineNumber: meta.lineNumber,
              comment: meta.comment,
            });
          }
        }
      } else {
        exactIps.set(entry, meta);
      }
    }

    newLookupIndex.set(def.id, {
      id: def.id,
      fileName: def.file,
      displayName: def.file,
      category: def.category,
      categoryLabel: def.categoryLabel,
      kind: def.kind,
      generator: def.generator,
      generatorLabel: def.generatorLabel,
      cadenceLabel: def.cadenceLabel,
      description: def.description,
      isBlocklist: def.isBlocklist,
      exactIps,
      cidrRanges,
      fqdnEntries,
      macEntries,
    });
  }
  cachedIpLookupIndex = newLookupIndex;

  parsedMap.clear();

  const categoryOrder: { category: FeedCategory; label: string }[] = [
    { category: 'ext_ip', label: '🔴 外部威脅 IP 封鎖清單 (10 份)' },
    { category: 'fqdn_mail', label: '📧 郵件與惡意網域封鎖清單 (5 份)' },
    { category: 'internal', label: '🖥️ 內部設備封鎖控管清單 (4 份)' },
    { category: 'allow', label: '✅ 允許清單與服務維護名單 (7 份)' },
  ];

  const categories: CategorySummary[] = categoryOrder.map(({ category, label }) => {
    const matching = feedItems.filter((f) => f.category === category);
    return {
      category,
      label,
      fileCount: matching.length,
      totalEntries: matching.reduce((s, f) => s + f.count, 0),
      totalBytes: matching.reduce((s, f) => s + f.bytes, 0),
    };
  });

  const getCount = (id: string) => feedItems.find((f) => f.id === id)?.count ?? 0;
  const externalIntelCount =
    getCount('longterm_auto') +
    getCount('manual_black_v5') +
    getCount('lib_threat_seed') +
    getCount('ntech_ip');
  const campusTrafficCount =
    getCount('traffic_src_topn') +
    getCount('traffic_src_ssh') +
    getCount('traffic_src_cert_remote') +
    getCount('traffic_src_trojan_irc') +
    getCount('traffic_src_dns_ptr') +
    getCount('traffic_dst_topn');
  const emailAndFqdnCount =
    getCount('emailsys_ipset') +
    getCount('dns_fqdn_v6') +
    getCount('ntech_fqdn') +
    getCount('emailsys_fqdn');
  const microSegAndAllowCount = protectedAndInternalEntries;

  const longTermTrend = buildLongTermTrend(params.longTermCommits, nowMs);
  const pipelineHealth = evaluatePipelineHealth(params.recentCommits, nowMs);

  const ltItem = feedItems.find((f) => f.id === 'longterm_auto')!;
  const longTermCount = ltItem.count;
  const longTermBytes = ltItem.bytes;
  const singleListLimit = 131072;
  const singleListPct = Number(((longTermCount / singleListLimit) * 100).toFixed(1));
  const singleListAlertLevel: CapacityStatus['singleListAlertLevel'] =
    singleListPct >= 85
      ? 'critical'
      : singleListPct >= 70
      ? 'warning'
      : 'normal';

  const fileSizeLimitBytes = 10 * 1024 * 1024; // 10 MB
  const fileSizePct = Number(((longTermBytes / fileSizeLimitBytes) * 100).toFixed(1));

  const totalAllEntries = rawExternalBlockEntries + protectedAndInternalEntries;
  const systemStandardLimit = 300000;
  const systemStandardPct = Number(
    ((totalAllEntries / systemStandardLimit) * 100).toFixed(1)
  );
  const systemMaxLimit = 5000000;
  const systemMaxPct = Number(
    ((totalAllEntries / systemMaxLimit) * 100).toFixed(2)
  );

  const recentDaily = longTermTrend.daily.slice(-3);
  const avgDailyGrowth =
    recentDaily.length > 0
      ? recentDaily.reduce((s, d) => s + (d.dailyAdded - d.dailyRemoved), 0) /
        recentDaily.length
      : longTermTrend.last24hAdded;

  const estimatedDaysTo100k =
    avgDailyGrowth > 0 && longTermCount < 100000
      ? Math.ceil((100000 - longTermCount) / avgDailyGrowth)
      : null;
  const estimatedDaysTo131k =
    avgDailyGrowth > 0 && longTermCount < singleListLimit
      ? Math.ceil((singleListLimit - longTermCount) / avgDailyGrowth)
      : null;

  return {
    headSha: params.headSha,
    shortHeadSha: params.headSha.slice(0, 10),
    headTimeIso: params.headTimeIso,
    headTimeDisplay,
    fetchedAtIso: nowIso,
    fetchedAtDisplay,
    isStaleFallback: false,
    staleReason: null,

    totalCommitsCount: params.totalCommitsCount,
    dailyScheduledRuns: TOTAL_DAILY_CRON_RUNS,
    totalFeedsCount: FEEDS_MANIFEST.length,
    uniqueExternalBlockIPv4: uniqueExternalIPv4Union.size,
    rawExternalBlockEntries,
    protectedAndInternalEntries,
    internalMisblockCount,

    pillars: {
      externalIntelCount,
      campusTrafficCount,
      emailAndFqdnCount,
      microSegAndAllowCount,
    },

    categories,
    feeds: feedItems,
    capacity: {
      longTermCount,
      longTermBytes,
      singleListLimit,
      singleListPct,
      singleListAlertLevel,
      fileSizeLimitBytes,
      fileSizePct,
      systemStandardLimit,
      systemStandardPct,
      systemMaxLimit,
      systemMaxPct,
      estimatedDaysTo100k,
      estimatedDaysTo131k,
      firstTtlExpiryDate: '2026-11-29',
    },

    longTermTrend,
    pipelineHealth,
  };
}

export async function getDashboardSnapshot(
  forceRefresh: boolean = false
): Promise<DashboardSnapshot> {
  // Default target repo evaluated on server; can be overridden via GITHUB_REPO env var
  const defaultOwner = ['security', 'list', '1568'].join('');
  const defaultName = ['Forti', 'gate'].join('');
  const repo = (process.env.GITHUB_REPO || `${defaultOwner}/${defaultName}`).trim();
  const nowMs = Date.now();

  if (
    !forceRefresh &&
    cachedSnapshot &&
    nowMs - lastSuccessfulFetchMs < REVALIDATE_INTERVAL_MS
  ) {
    return cachedSnapshot;
  }

  try {
    const headUrl = `https://api.github.com/repos/${repo}/commits/main`;
    const headRes = await fetch(headUrl, {
      headers: buildGitHubHeaders(cachedHeadEtag),
      cache: 'no-store',
    });

    if (headRes.status === 304 && cachedSnapshot) {
      lastSuccessfulFetchMs = nowMs;
      return {
        ...cachedSnapshot,
        fetchedAtIso: new Date(nowMs).toISOString(),
        fetchedAtDisplay: formatTaipeiTime(new Date(nowMs).toISOString()).displayTime,
        isStaleFallback: false,
        staleReason: null,
      };
    }

    if (!headRes.ok) {
      throw new Error(`Upstream API returned HTTP ${headRes.status}`);
    }

    const newEtag = headRes.headers.get('etag');
    const headData = (await headRes.json()) as GitHubCommitItem;
    const headSha = headData.sha;
    const headTimeIso =
      headData.commit?.committer?.date ||
      headData.commit?.author?.date ||
      new Date(nowMs).toISOString();

    if (!forceRefresh && cachedSnapshot && cachedHeadSha === headSha) {
      cachedHeadEtag = newEtag;
      lastSuccessfulFetchMs = nowMs;
      return {
        ...cachedSnapshot,
        fetchedAtIso: new Date(nowMs).toISOString(),
        fetchedAtDisplay: formatTaipeiTime(new Date(nowMs).toISOString()).displayTime,
        isStaleFallback: false,
        staleReason: null,
      };
    }

    const rawFilesById: Record<string, string> = {};
    await Promise.all(
      FEEDS_MANIFEST.map(async (def) => {
        rawFilesById[def.id] = await fetchRawFileAtSha(repo, headSha, def.file);
      })
    );

    const [longTermCommitsRes, recentCommitsRes, totalCommitsCount] =
      await Promise.all([
        fetch(
          `https://api.github.com/repos/${repo}/commits?path=g-BLACK_IP_AutoLongTerm-v1.txt&per_page=100`,
          { headers: buildGitHubHeaders(), cache: 'no-store' }
        ),
        fetch(`https://api.github.com/repos/${repo}/commits?sha=main&per_page=80`, {
          headers: buildGitHubHeaders(),
          cache: 'no-store',
        }),
        fetchTotalCommitCount(repo),
      ]);

    const longTermCommits: GitHubCommitItem[] = longTermCommitsRes.ok
      ? ((await longTermCommitsRes.json()) as GitHubCommitItem[])
      : [];
    const recentCommits: GitHubCommitItem[] = recentCommitsRes.ok
      ? ((await recentCommitsRes.json()) as GitHubCommitItem[])
      : [headData];

    const snapshot = computeSnapshotFromRawInputs({
      headSha,
      headTimeIso,
      totalCommitsCount,
      rawFilesById,
      longTermCommits,
      recentCommits,
      nowMs,
    });

    cachedHeadEtag = newEtag;
    cachedHeadSha = headSha;
    cachedSnapshot = snapshot;
    lastSuccessfulFetchMs = nowMs;

    return snapshot;
  } catch (err: unknown) {
    const errMsg = err instanceof Error ? err.message : String(err);
    if (cachedSnapshot) {
      return {
        ...cachedSnapshot,
        isStaleFallback: true,
        staleReason: `上游情資庫連線或限流異常 (${errMsg})，目前顯示最後成功同步之快取快照。`,
      };
    }
    throw err;
  }
}

function getRetentionPolicyByFeed(feedIdx: FeedIpIndex): string {
  if (!feedIdx.isBlocklist) {
    if (feedIdx.id === 'allow_global_infra') {
      return '全域實體允許清單 (ncloud_allowlist.txt) — 自動化腳本強制排除，絕不列入外部封鎖';
    }
    if (feedIdx.id === 'allow_longterm_exclude') {
      return '長期黑名單手動剔除清單 (longterm_exclude.txt) — 專供排除於 g-BLACK_IP_AutoLongTerm-v1.txt 之外';
    }
    return '服務維護與允許清單（人工造冊維護之重要網站或維運主機）';
  }

  switch (feedIdx.generator) {
    case 'longterm':
      return '30 天 TTL 自動退場（自 last_seen 起滿 30 天自動移除；若需立即排除請加入 longterm_exclude.txt 或 ncloud_allowlist.txt）';
    case 'topn':
      return '每日 00:00 自動歸零重算 + 每 10 分鐘增量更新（若需永久豁免請加入 ncloud_allowlist.txt）';
    case 'emailsys':
      return '每 10 分鐘依郵件系統封鎖統計動態更新';
    case 'ntech':
      return '每 10 分鐘依 CERT 威脅情資同步更新';
    case 'manual':
    default:
      return '人工維護封鎖/控管清單（需由管理員於版本庫手動調整）';
  }
}

function checkFeedMatch(
  idx: FeedIpIndex,
  rawQuery: string,
  bareIp: string,
  ipInt: number | null
): {
  matchType: IpQueryFeedMatch['matchType'];
  matchedRule: string;
  lineNumber: number | null;
  commentNote: string | null;
} | null {
  // 1. IPv4 / CIDR match
  if (ipInt !== null) {
    const exactMeta = idx.exactIps.get(bareIp);
    if (exactMeta) {
      return {
        matchType: 'exact_ip',
        matchedRule: bareIp,
        lineNumber: exactMeta.lineNumber || null,
        commentNote: exactMeta.comment,
      };
    }
    for (const r of idx.cidrRanges) {
      if (((ipInt & r.maskInt) >>> 0) === r.netInt) {
        return {
          matchType: 'cidr_subnet',
          matchedRule: r.cidr,
          lineNumber: r.lineNumber || null,
          commentNote: r.comment,
        };
      }
    }
  }

  // 2. MAC address match
  const macCandidate = rawQuery.trim().toUpperCase().replace(/-/g, ':');
  if (/^([0-9A-F]{2}:){5}[0-9A-F]{2}$/.test(macCandidate)) {
    const macMeta = idx.macEntries.get(macCandidate);
    if (macMeta) {
      return {
        matchType: 'exact_mac',
        matchedRule: macCandidate,
        lineNumber: macMeta.lineNumber || null,
        commentNote: macMeta.comment,
      };
    }
  }

  // 3. FQDN / Domain / Hostname comment match
  const cleanedHost = rawQuery
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '');

  if (cleanedHost && ipInt === null) {
    const exactFqdn = idx.fqdnEntries.get(cleanedHost);
    if (exactFqdn) {
      return {
        matchType: 'exact_fqdn',
        matchedRule: cleanedHost,
        lineNumber: exactFqdn.lineNumber || null,
        commentNote: exactFqdn.comment,
      };
    }

    for (const [fqdnRule, meta] of idx.fqdnEntries.entries()) {
      if (fqdnRule.startsWith('*.')) {
        const suffix = fqdnRule.slice(2);
        if (cleanedHost === suffix || cleanedHost.endsWith('.' + suffix)) {
          return {
            matchType: 'wildcard_fqdn',
            matchedRule: fqdnRule,
            lineNumber: meta.lineNumber || null,
            commentNote: meta.comment,
          };
        }
      }
    }

    // Also check if hostname appears in comments of IP lists (e.g., NTNU-FormalWebsites-v2.txt, Security-UCP-maintenance-v1.txt)
    if (cleanedHost.length >= 3) {
      for (const [ipEntry, meta] of idx.exactIps.entries()) {
        if (meta.comment && meta.comment.toLowerCase().includes(cleanedHost)) {
          return {
            matchType: 'comment_host',
            matchedRule: ipEntry,
            lineNumber: meta.lineNumber || null,
            commentNote: meta.comment,
          };
        }
      }
    }
  }

  return null;
}

async function ensureHistoricalDynamicIndex(): Promise<
  Map<string, Map<string, HistoricalIpSighting>>
> {
  const nowMs = Date.now();
  if (
    cachedHistoricalFeedIndex &&
    nowMs - lastHistoricalBuildMs < HISTORICAL_REBUILD_INTERVAL_MS
  ) {
    return cachedHistoricalFeedIndex;
  }

  const defaultOwner = ['security', 'list', '1568'].join('');
  const defaultName = ['Forti', 'gate'].join('');
  const repo = (process.env.GITHUB_REPO || `${defaultOwner}/${defaultName}`).trim();

  const histMap = new Map<string, Map<string, HistoricalIpSighting>>();
  for (const id of HISTORICAL_DYNAMIC_FEED_IDS) {
    histMap.set(id, new Map<string, HistoricalIpSighting>());
  }

  try {
    // Sample end-of-day commits over the past 10 days (at ~23:59 Asia/Taipei = 15:59 UTC)
    const dayPromises = Array.from({ length: 10 }, (_, idx) => idx + 1).map(
      async (daysAgo) => {
        const targetMs = nowMs - daysAgo * 24 * 3600 * 1000;
        const { dateKey } = formatTaipeiTime(new Date(targetMs).toISOString());
        const untilIso = `${dateKey}T23:59:59+08:00`;
        const url = `https://api.github.com/repos/${repo}/commits?sha=main&until=${encodeURIComponent(
          untilIso
        )}&per_page=1`;
        const res = await fetch(url, {
          headers: buildGitHubHeaders(),
          cache: 'no-store',
        });
        if (!res.ok) return null;
        const arr = (await res.json()) as GitHubCommitItem[];
        if (!arr || arr.length === 0) return null;
        const commit = arr[0];
        const commitTimeIso =
          commit.commit?.committer?.date ||
          commit.commit?.author?.date ||
          untilIso;
        const { displayTime } = formatTaipeiTime(commitTimeIso);
        return {
          sha: commit.sha,
          shortSha: commit.sha.slice(0, 8),
          displayTime: `${dateKey} (${displayTime.slice(11, 16)})`,
        };
      }
    );

    const daySnapshots = (await Promise.all(dayPromises)).filter(
      (x): x is { sha: string; shortSha: string; displayTime: string } =>
        x !== null
    );

    // Deduplicate SHAs while keeping most recent first
    const uniqueShas: { sha: string; shortSha: string; displayTime: string }[] = [];
    const seenSha = new Set<string>();
    for (const s of daySnapshots) {
      if (!seenSha.has(s.sha)) {
        seenSha.add(s.sha);
        uniqueShas.push(s);
      }
    }

    await Promise.all(
      uniqueShas.map(async (snap) => {
        await Promise.all(
          HISTORICAL_DYNAMIC_FEED_IDS.map(async (feedId) => {
            const def = FEEDS_MANIFEST.find((f) => f.id === feedId);
            if (!def) return;
            try {
              const raw = await fetchRawFileAtSha(repo, snap.sha, def.file);
              const parsed = parseFeedContent(raw, def.kind, false);
              const targetFeedMap = histMap.get(feedId)!;
              for (const entry of parsed.entriesSet) {
                const key =
                  def.kind === 'fqdn'
                    ? entry.toLowerCase()
                    : entry.endsWith('/32')
                    ? entry.slice(0, -3)
                    : entry;
                if (!targetFeedMap.has(key)) {
                  const meta = parsed.entryMetaMap.get(entry);
                  targetFeedMap.set(key, {
                    lastSeenSha: snap.shortSha,
                    lastSeenDisplay: snap.displayTime,
                    lineNumber: meta?.lineNumber ?? 0,
                  });
                }
              }
            } catch {
              // Ignore single historical file fetch error
            }
          })
        );
      })
    );

    cachedHistoricalFeedIndex = histMap;
    lastHistoricalBuildMs = nowMs;
  } catch {
    // Fallback to empty map on error without failing current HEAD lookup
  }

  return cachedHistoricalFeedIndex ?? histMap;
}

export async function queryIpsAgainstFeeds(
  rawQueries: string[]
): Promise<IpQueryResponsePayload> {
  const snapshot = await getDashboardSnapshot(false);
  const indexMap = cachedIpLookupIndex ?? new Map<string, FeedIpIndex>();

  const cleanedTokens = Array.from(
    new Set(
      rawQueries
        .map((q) => q.trim())
        .filter((q) => q.length > 0)
    )
  ).slice(0, 50);

  const results: IpQueryResultItem[] = [];
  let blockedCount = 0;
  let historicalBlockedCount = 0;
  let inAllowlistCount = 0;
  let cleanCount = 0;
  let historicalIndexMap: Map<string, Map<string, HistoricalIpSighting>> | null =
    cachedHistoricalFeedIndex;

  for (const rawToken of cleanedTokens) {
    const bareIp = rawToken.endsWith('/32') ? rawToken.slice(0, -3) : rawToken;
    const ipInt = ipv4ToUint32(bareIp);
    const isCidrInput = rawToken.includes('/') && parseCidrRange(rawToken) !== null;
    const isMacInput = /^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/.test(rawToken);
    const isHostnameInput =
      ipInt === null &&
      !isCidrInput &&
      !isMacInput &&
      /[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|[\u4e00-\u9fa5]{2,}/.test(rawToken);

    if (ipInt === null && !isCidrInput && !isMacInput && !isHostnameInput) {
      results.push({
        query: rawToken,
        isValidIp: false,
        status: 'invalid',
        statusLabel: '⚪ 格式無效（請輸入 IPv4、FQDN 網域或 MAC 位址）',
        isAllowlisted: false,
        isExcludedFromLongTerm: false,
        blockMatches: [],
        historicalBlockMatches: [],
        allowMatches: [],
        matches: [],
        advisory:
          '請輸入有效的 IPv4 位址（如 104.16.102.112、176.123.1.163 或 140.122.251.74）、FQDN 網域（如 granestichs.top）或 MAC 位址。',
      });
      continue;
    }

    const effectiveIpInt =
      ipInt ?? (isCidrInput ? ipv4ToUint32(rawToken.split('/')[0]) : null);
    const effectiveBareIp = isCidrInput ? rawToken.split('/')[0] : bareIp;

    const blockMatches: IpQueryFeedMatch[] = [];
    const historicalBlockMatches: IpQueryFeedMatch[] = [];
    const allowMatches: IpQueryFeedMatch[] = [];
    const matchedHeadFeedIds = new Set<string>();

    for (const [, feedIdx] of indexMap.entries()) {
      const m = checkFeedMatch(
        feedIdx,
        rawToken,
        effectiveBareIp,
        effectiveIpInt
      );
      if (m) {
        matchedHeadFeedIds.add(feedIdx.id);
        const matchObj: IpQueryFeedMatch = {
          feedId: feedIdx.id,
          fileName: feedIdx.fileName,
          displayName: feedIdx.fileName,
          category: feedIdx.category,
          categoryLabel: feedIdx.categoryLabel,
          isBlocklist: feedIdx.isBlocklist,
          generatorLabel: feedIdx.generatorLabel,
          cadenceLabel: feedIdx.cadenceLabel,
          description: feedIdx.description,
          matchType: m.matchType,
          matchedRule: m.matchedRule,
          lineNumber: m.lineNumber,
          commentNote: m.commentNote,
          retentionPolicy: getRetentionPolicyByFeed(feedIdx),
          isHistoricalOnly: false,
        };
        if (feedIdx.isBlocklist) {
          blockMatches.push(matchObj);
        } else {
          allowMatches.push(matchObj);
        }
      }
    }

    // Lazy On-Demand 10-day historical dynamic blocklist lookup:
    // Only fetch/build the 10-day historical index if the target was NOT already blocked in HEAD (or if historical index is already warm in memory)
    if (blockMatches.length === 0 || historicalIndexMap !== null) {
      if (!historicalIndexMap) {
        historicalIndexMap = await ensureHistoricalDynamicIndex();
      }
      const cleanedHostKey = rawToken
        .trim()
        .toLowerCase()
        .replace(/^https?:\/\//, '')
        .replace(/\/.*$/, '');

      for (const [histFeedId, sightingMap] of historicalIndexMap.entries()) {
        if (matchedHeadFeedIds.has(histFeedId)) continue;
        const feedIdx = indexMap.get(histFeedId);
        if (!feedIdx) continue;

        const lookupKey =
          feedIdx.kind === 'fqdn' ? cleanedHostKey : effectiveBareIp;
        const sighting = sightingMap.get(lookupKey);
        if (sighting) {
          historicalBlockMatches.push({
            feedId: feedIdx.id,
            fileName: feedIdx.fileName,
            displayName: feedIdx.fileName,
            category: feedIdx.category,
            categoryLabel: feedIdx.categoryLabel,
            isBlocklist: true,
            generatorLabel: feedIdx.generatorLabel,
            cadenceLabel: feedIdx.cadenceLabel,
            description: feedIdx.description,
            matchType: 'historical_ip',
            matchedRule: lookupKey,
            lineNumber: sighting.lineNumber || null,
            commentNote: `曾於 ${sighting.lastSeenDisplay} (Commit ${sighting.lastSeenSha}) 列入此動態清單，目前已於每日 00:00 歸零或滾動更新中退場`,
            retentionPolicy: getRetentionPolicyByFeed(feedIdx),
            isHistoricalOnly: true,
            lastSeenDisplay: sighting.lastSeenDisplay,
            lastSeenSha: sighting.lastSeenSha,
          });
        }
      }
    }

    const isAllowlisted = allowMatches.some(
      (m) => m.feedId === 'allow_global_infra'
    );
    const isExcludedFromLongTerm = allowMatches.some(
      (m) => m.feedId === 'allow_longterm_exclude'
    );
    const allMatches = [
      ...blockMatches,
      ...historicalBlockMatches,
      ...allowMatches,
    ];

    if (blockMatches.length > 0) {
      blockedCount += 1;
      const blockedFileNames = blockMatches.map((m) => m.fileName).join('、');
      const histNote =
        historicalBlockMatches.length > 0
          ? `；另於近 10 日歷史曾出現在【${historicalBlockMatches
              .map((m) => `${m.fileName} (${m.lastSeenDisplay})`)
              .join('、')}】`
          : '';
      const allowNote =
        allowMatches.length > 0
          ? `（同時亦列於非封鎖名單：${allowMatches
              .map((m) => m.fileName)
              .join('、')}）`
          : '';

      results.push({
        query: rawToken,
        isValidIp: effectiveIpInt !== null,
        status: 'blocked',
        statusLabel: `🔴 現行封鎖中（命中 ${blockMatches.length} 份名單：${blockedFileNames}）`,
        isAllowlisted,
        isExcludedFromLongTerm,
        blockMatches,
        historicalBlockMatches,
        allowMatches,
        matches: allMatches,
        advisory: `此目標於最新同步版本 (${snapshot.shortHeadSha}) 落在封鎖清單【${blockedFileNames}】內${histNote}${allowNote}。`,
      });
    } else if (historicalBlockMatches.length > 0) {
      historicalBlockedCount += 1;
      const histFileNames = historicalBlockMatches
        .map((m) => `${m.fileName}`)
        .join('、');
      const allowNote =
        allowMatches.length > 0
          ? `；目前位於非封鎖名單【${allowMatches
              .map((m) => m.fileName)
              .join('、')}】`
          : '';

      results.push({
        query: rawToken,
        isValidIp: effectiveIpInt !== null,
        status: 'historical_blocked',
        statusLabel: `🟠 近期曾落在動態封鎖清單（${histFileNames}，目前已於當日歸零更新退場）`,
        isAllowlisted,
        isExcludedFromLongTerm,
        blockMatches: [],
        historicalBlockMatches,
        allowMatches,
        matches: allMatches,
        advisory: `此目標在近 10 日內曾落在【${histFileNames}】封鎖清單內（若您檢視的本機檔案尚未 git pull，仍會看到此 IP），但因 ncloud_topn_feed_push_v4_5.py 每日 00:00 自動歸零重算，在最新遠端 HEAD (${snapshot.shortHeadSha}) 已退場未封鎖${allowNote}。`,
      });
    } else if (allowMatches.length > 0) {
      inAllowlistCount += 1;
      cleanCount += 1;
      const allowFileNames = allowMatches.map((m) => m.fileName).join('、');

      results.push({
        query: rawToken,
        isValidIp: effectiveIpInt !== null,
        status: 'in_allowlist_only',
        statusLabel: `🟢 不在封鎖清單內 — 位於允許/網站/維護名單（${allowFileNames}）`,
        isAllowlisted,
        isExcludedFromLongTerm,
        blockMatches: [],
        historicalBlockMatches: [],
        allowMatches,
        matches: allMatches,
        advisory: `此目標不在任何封鎖清單內，且明確登錄於【${allowFileNames}】名單中。`,
      });
    } else {
      cleanCount += 1;
      results.push({
        query: rawToken,
        isValidIp: effectiveIpInt !== null,
        status: 'not_in_any_list',
        statusLabel: '⚪ 不在封鎖清單內（未出現於現行 25 份 *.txt 及近 10 日動態清單）',
        isAllowlisted: false,
        isExcludedFromLongTerm: false,
        blockMatches: [],
        historicalBlockMatches: [],
        allowMatches: [],
        matches: [],
        advisory:
          '經比對 Fortigate 儲存庫最新 HEAD 全部 25 份清單檔案及近 10 日動態滾動清單歷史，均未包含此項目。',
      });
    }
  }

  const { displayTime: queriedAtDisplay } = formatTaipeiTime(
    new Date().toISOString()
  );

  return {
    headSha: snapshot.headSha,
    shortHeadSha: snapshot.shortHeadSha,
    headTimeDisplay: snapshot.headTimeDisplay,
    queriedAtDisplay,
    totalQueried: results.length,
    blockedCount,
    historicalBlockedCount,
    inAllowlistCount,
    cleanCount,
    scannedFilesCount: indexMap.size,
    historicalDaysCovered: 10,
    results,
  };
}

