import {
  FEEDS_MANIFEST,
  FeedCategory,
  FeedKind,
  GeneratorScriptId,
  TOTAL_DAILY_CRON_RUNS,
} from './feeds.manifest';
import { parseFeedContent } from './parsers';
import {
  buildLongTermTrend,
  DailyLongTermTrend,
  evaluatePipelineHealth,
  formatTaipeiTime,
  GitHubCommitItem,
  LongTermTrendPoint,
  ScriptHealthStatus,
} from './trend';

export type {
  FeedCategory,
  FeedKind,
  GeneratorScriptId,
  DailyLongTermTrend,
  GitHubCommitItem,
  LongTermTrendPoint,
  ScriptHealthStatus,
};

export interface FeedSnapshotItem {
  id: string;
  file: string;
  category: FeedCategory;
  categoryLabel: string;
  kind: FeedKind;
  generator: GeneratorScriptId;
  generatorLabel: string;
  cadenceLabel: string;
  description: string;
  isSensitiveInternal: boolean;
  isBlocklist: boolean;
  count: number;
  bytes: number;
  headerCount: number | null;
  headerMismatch: boolean;
  overlapWithLongTerm: number | null;
}

export interface CategorySummary {
  category: FeedCategory;
  label: string;
  fileCount: number;
  totalEntries: number;
  totalBytes: number;
}

export interface CapacityStatus {
  longTermCount: number;
  longTermBytes: number;
  fortiOs72Limit: number;       // 131,072
  fortiOs72Pct: number;
  fortiOs72AlertLevel: 'normal' | 'warning' | 'critical'; // >=70% warning, >=85% critical
  fileSizeLimitBytes: number;   // 10 MB (10,485,760 bytes)
  fileSizePct: number;
  fortiOs74TotalLimit: number;  // 300,000
  fortiOs74TotalPct: number;
  fortiOs76FlagshipLimit: number; // 5,000,000
  fortiOs76FlagshipPct: number;
  estimatedDaysTo100k: number | null;
  estimatedDaysTo131k: number | null;
  firstTtlExpiryDate: string;   // 2026-11-29 (30d from 2026-10-30)
}

export interface DashboardSnapshot {
  repo: string;
  headSha: string;
  shortHeadSha: string;
  headTimeIso: string;
  headTimeDisplay: string;
  fetchedAtIso: string;
  fetchedAtDisplay: string;
  isStaleFallback: boolean;
  staleReason: string | null;

  // Top-level Governance KPIs (strictly separated per v2.1 audit)
  totalCommitsCount: number;
  dailyScheduledRuns: number;      // 440 runs/day (derived from crontab config)
  totalFeedsCount: number;         // Derived from FEEDS_MANIFEST.length
  uniqueExternalBlockIPv4: number; // Deduplicated union of external IPv4 blocklists
  rawExternalBlockEntries: number; // Sum of all external blocklist entries (IP + CIDR + FQDN)
  protectedAndInternalEntries: number; // Sum of allowlist + campus micro-segmentation entries
  internalMisblockCount: number;   // Verified count of 140.122.x.x / RFC1918 leaked into external IP blocklists (0)

  // Pillar summaries
  pillars: {
    externalIntelCount: number;    // LongTerm + ntech + Lib-ThreatSeed + Manual
    campusNcloudCount: number;     // 6 Ncloud dynamic feeds
    emailAndFqdnCount: number;     // EmailSys CIDR/FQDN + DNS-FQDN + ntech FQDN
    microSegAndAllowCount: number; // Internal micro-seg + Allowlists
  };

  categories: CategorySummary[];
  feeds: FeedSnapshotItem[];
  capacity: CapacityStatus;

  longTermTrend: {
    points: LongTermTrendPoint[];
    daily: DailyLongTermTrend[];
    last24hAdded: number;
    last24hRemoved: number;
    last24hCommits: number;
  };

  pipelineHealth: ScriptHealthStatus[];
}

// In-memory state for ETag conditional requests and stale-on-error fallback
let cachedHeadEtag: string | null = null;
let cachedHeadSha: string | null = null;
let cachedSnapshot: DashboardSnapshot | null = null;
let lastSuccessfulFetchMs = 0;

const REVALIDATE_INTERVAL_MS = 300 * 1000; // 5 minutes

function buildGitHubHeaders(etag?: string | null): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'NTNU-Fortigate-Dashboard/2.1',
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

/**
 * Extracts total commit count from GitHub's `Link` header when requesting `per_page=1`.
 */
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

/**
 * Fetches immutable raw file content pinned to a specific commit SHA (`raw.githubusercontent.com/<repo>/<sha>/<file>`)
 * so CDN branch caching never serves stale data.
 */
async function fetchRawFileAtSha(
  repo: string,
  sha: string,
  filePath: string
): Promise<string> {
  const url = `https://raw.githubusercontent.com/${repo}/${sha}/${encodeURIComponent(
    filePath
  )}`;
  const headers: Record<string, string> = {
    'User-Agent': 'NTNU-Fortigate-Dashboard/2.1',
  };
  const token = process.env.GITHUB_TOKEN?.trim();
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  const res = await fetch(url, { headers, cache: 'no-store' });
  if (!res.ok) {
    throw new Error(`Failed to fetch ${filePath} at ${sha.slice(0, 7)}: HTTP ${res.status}`);
  }
  return await res.text();
}

/**
 * Pure aggregation function that computes a complete DashboardSnapshot from raw feed contents
 * and commit histories. Strictly strips all IP/MAC/FQDN strings from the output.
 */
export function computeSnapshotFromRawInputs(params: {
  repo: string;
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

  // First pass: parse all feeds in memory
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

    if (def.isBlocklist) {
      rawExternalBlockEntries += p.count;
    } else if (def.category === 'internal' || def.category === 'allow') {
      protectedAndInternalEntries += p.count;
    }

    // Compute overlap with LongTerm for external IP blocklists (other than LongTerm itself)
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
      file: def.file,
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

  // Clear in-memory sets immediately after union/overlap calculation
  parsedMap.clear();

  // Category summaries
  const categoryOrder: { category: FeedCategory; label: string }[] = [
    { category: 'ext_ip', label: '🔴 封鎖 — 外部威脅 IP 清單' },
    { category: 'fqdn_mail', label: '📧 封鎖 — 郵件網段與惡意網域清單' },
    { category: 'internal', label: '🖥️ 內網設備微隔離控管清單（僅顯示筆數）' },
    { category: 'allow', label: '✅ 白名單與校務網站資產清冊（僅顯示筆數）' },
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

  // Four pillars breakdown
  const getCount = (id: string) => feedItems.find((f) => f.id === id)?.count ?? 0;
  const externalIntelCount =
    getCount('longterm_auto') +
    getCount('manual_black_v5') +
    getCount('lib_threat_seed') +
    getCount('ntech_ip');
  const campusNcloudCount =
    getCount('ncloud_src_topn') +
    getCount('ncloud_src_ssh') +
    getCount('ncloud_src_cert_remote') +
    getCount('ncloud_src_trojan_irc') +
    getCount('ncloud_src_dns_ptr') +
    getCount('ncloud_dst_topn');
  const emailAndFqdnCount =
    getCount('emailsys_ipset') +
    getCount('dns_fqdn_v6') +
    getCount('ntech_fqdn') +
    getCount('emailsys_fqdn');
  const microSegAndAllowCount = protectedAndInternalEntries;

  // Trend & Pipeline Health
  const longTermTrend = buildLongTermTrend(params.longTermCommits, nowMs);
  const pipelineHealth = evaluatePipelineHealth(params.recentCommits, nowMs);

  // Capacity & Watermark Calculation
  const ltItem = feedItems.find((f) => f.id === 'longterm_auto')!;
  const longTermCount = ltItem.count;
  const longTermBytes = ltItem.bytes;
  const fortiOs72Limit = 131072;
  const fortiOs72Pct = Number(((longTermCount / fortiOs72Limit) * 100).toFixed(1));
  const fortiOs72AlertLevel: CapacityStatus['fortiOs72AlertLevel'] =
    fortiOs72Pct >= 85
      ? 'critical'
      : fortiOs72Pct >= 70
      ? 'warning'
      : 'normal';

  const fileSizeLimitBytes = 10 * 1024 * 1024; // 10 MB
  const fileSizePct = Number(((longTermBytes / fileSizeLimitBytes) * 100).toFixed(1));

  const totalAllEntries = rawExternalBlockEntries + protectedAndInternalEntries;
  const fortiOs74TotalLimit = 300000;
  const fortiOs74TotalPct = Number(
    ((totalAllEntries / fortiOs74TotalLimit) * 100).toFixed(1)
  );
  const fortiOs76FlagshipLimit = 5000000;
  const fortiOs76FlagshipPct = Number(
    ((totalAllEntries / fortiOs76FlagshipLimit) * 100).toFixed(2)
  );

  // Estimate days to 100k / 131k using recent 3-day average growth (or last24hAdded)
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
    avgDailyGrowth > 0 && longTermCount < fortiOs72Limit
      ? Math.ceil((fortiOs72Limit - longTermCount) / avgDailyGrowth)
      : null;

  return {
    repo: params.repo,
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
      campusNcloudCount,
      emailAndFqdnCount,
      microSegAndAllowCount,
    },

    categories,
    feeds: feedItems,
    capacity: {
      longTermCount,
      longTermBytes,
      fortiOs72Limit,
      fortiOs72Pct,
      fortiOs72AlertLevel,
      fileSizeLimitBytes,
      fileSizePct,
      fortiOs74TotalLimit,
      fortiOs74TotalPct,
      fortiOs76FlagshipLimit,
      fortiOs76FlagshipPct,
      estimatedDaysTo100k,
      estimatedDaysTo131k,
      firstTtlExpiryDate: '2026-11-29',
    },

    longTermTrend,
    pipelineHealth,
  };
}

/**
 * Main entry point to obtain the latest DashboardSnapshot.
 * Implements:
 * 1. 5-minute TTL check (`revalidate = 300s`).
 * 2. `GET /repos/<repo>/commits/main` with `If-None-Match: <ETag>`.
 * 3. If HTTP 304 Not Modified or SHA unchanged, reuses cached derived Snapshot (< 50 KB).
 * 4. If SHA changed, fetches immutable raw files at `raw.githubusercontent.com/<repo>/<SHA>/<file>`,
 *    computes derived summary JSON, discards raw text, and caches only the summary Snapshot.
 * 5. Graceful degradation: if GitHub fails or rate-limits, returns the last known Snapshot with `isStaleFallback = true`.
 */
export async function getDashboardSnapshot(
  forceRefresh: boolean = false
): Promise<DashboardSnapshot> {
  const repo = (process.env.GITHUB_REPO || 'securitylist1568/Fortigate').trim();
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
      throw new Error(`GitHub commits/main returned HTTP ${headRes.status}`);
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

    // Fetch all raw feeds pinned to headSha + commit histories in parallel
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
      repo,
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
        staleReason: `GitHub API 連線或限流異常 (${errMsg})，目前顯示最後成功同步之快取快照。`,
      };
    }
    throw err;
  }
}

