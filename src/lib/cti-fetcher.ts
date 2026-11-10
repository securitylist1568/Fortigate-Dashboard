import { FEEDS_MANIFEST, TOTAL_DAILY_CRON_RUNS } from './feeds.manifest';
import {
  parseFeedContent,
  ipv4ToUint32,
  parseCidrRange,
  isCampusOrPrivateIPv4,
  ParsedCidrRange,
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

interface FeedIpIndex {
  id: string;
  displayName: string;
  categoryLabel: string;
  generator: GeneratorScriptId;
  generatorLabel: string;
  cadenceLabel: string;
  isBlocklist: boolean;
  exactIps: Set<string>;
  cidrRanges: ParsedCidrRange[];
}

// In-memory state for ETag conditional requests, IP lookup index, and stale-on-error fallback
let cachedHeadEtag: string | null = null;
let cachedHeadSha: string | null = null;
let cachedSnapshot: DashboardSnapshot | null = null;
let cachedIpLookupIndex: Map<string, FeedIpIndex> | null = null;
let lastSuccessfulFetchMs = 0;

const REVALIDATE_INTERVAL_MS = 300 * 1000; // 5 minutes

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

    if (def.isBlocklist) {
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
      displayName: def.displayName,
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

  // Build in-memory IP/CIDR lookup index for external blocklists + global allowlist/exclude
  const newLookupIndex = new Map<string, FeedIpIndex>();
  for (const def of FEEDS_MANIFEST) {
    const isLookupTarget =
      (def.isBlocklist && (def.kind === 'ip' || def.kind === 'cidr')) ||
      def.id === 'allow_global' ||
      def.id === 'longterm_exclude';
    if (!isLookupTarget) continue;

    const p = parsedMap.get(def.id);
    if (!p) continue;

    const exactIps = new Set<string>();
    const cidrRanges: ParsedCidrRange[] = [];

    for (const entry of p.entriesSet) {
      if (entry.includes('/')) {
        const bare = entry.endsWith('/32') ? entry.slice(0, -3) : null;
        if (bare) {
          exactIps.add(bare);
        } else {
          const parsedCidr = parseCidrRange(entry);
          if (parsedCidr) {
            cidrRanges.push(parsedCidr);
          }
        }
      } else {
        exactIps.add(entry);
      }
    }

    newLookupIndex.set(def.id, {
      id: def.id,
      displayName: def.displayName,
      categoryLabel: def.categoryLabel,
      generator: def.generator,
      generatorLabel: def.generatorLabel,
      cadenceLabel: def.cadenceLabel,
      isBlocklist: def.isBlocklist,
      exactIps,
      cidrRanges,
    });
  }
  cachedIpLookupIndex = newLookupIndex;

  parsedMap.clear();

  const categoryOrder: { category: FeedCategory; label: string }[] = [
    { category: 'ext_ip', label: '🔴 封鎖 — 外部威脅 IP 清單' },
    { category: 'fqdn_mail', label: '📧 封鎖 — 郵件網段與惡意網域清單' },
    { category: 'internal', label: '🖥️ 內網設備微隔離控管清單（僅顯示筆數）' },
    { category: 'allow', label: '✅ 白名單與重要服務資產清冊（僅顯示筆數）' },
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

function getRetentionPolicyByGenerator(generator: GeneratorScriptId): string {
  switch (generator) {
    case 'longterm':
      return '30 天 TTL 自動退場（自 last_seen 起滿 30 天自動移除；若需立即排除請加入 longterm_exclude.txt 或 ncloud_allowlist.txt）';
    case 'topn':
      return '每日 00:00 自動歸零重算 + 每 10 分鐘增量更新（若需永久豁免請加入 ncloud_allowlist.txt）';
    case 'emailsys':
      return '每 10 分鐘依郵件閘道統計動態更新 CIDR 封鎖集';
    case 'ntech':
      return '每 10 分鐘依外部聯防 / CERT 情資同步更新';
    case 'manual':
    default:
      return '人工維護黑名單（需由維運人員於版本庫手動移除）';
  }
}

function checkIndexMatch(
  idx: FeedIpIndex,
  bareIp: string,
  ipInt: number
): { matchType: 'exact_ip' | 'cidr_subnet'; matchedRule: string } | null {
  if (idx.exactIps.has(bareIp)) {
    return { matchType: 'exact_ip', matchedRule: bareIp };
  }
  for (const r of idx.cidrRanges) {
    if (((ipInt & r.maskInt) >>> 0) === r.netInt) {
      return { matchType: 'cidr_subnet', matchedRule: r.cidr };
    }
  }
  return null;
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

  const allowGlobalIdx = indexMap.get('allow_global');
  const longtermExcludeIdx = indexMap.get('longterm_exclude');

  const results: IpQueryResultItem[] = [];
  let blockedCount = 0;
  let cleanCount = 0;

  for (const rawToken of cleanedTokens) {
    const bareIp = rawToken.endsWith('/32') ? rawToken.slice(0, -3) : rawToken;
    const ipInt = ipv4ToUint32(bareIp);

    if (ipInt === null) {
      results.push({
        query: rawToken,
        isValidIp: false,
        status: 'invalid',
        statusLabel: '⚪ 格式無效 (請輸入標準 IPv4 位址)',
        isAllowlisted: false,
        isExcludedFromLongTerm: false,
        matches: [],
        advisory: '請輸入有效的 IPv4 點分十進位位址（例如：60.251.148.94）。',
      });
      continue;
    }

    if (isCampusOrPrivateIPv4(bareIp)) {
      cleanCount += 1;
      results.push({
        query: bareIp,
        isValidIp: true,
        status: 'internal_protected',
        statusLabel: '🛡️ 內部/私網保留網段 (系統預設保護)',
        isAllowlisted: true,
        isExcludedFromLongTerm: true,
        matches: [],
        advisory:
          '此 IP 屬於受保護內部網段或 RFC1918 私網保留位址。所有自動化腳本均已強制內建排除規則，絕不會列入外部黑名單。',
      });
      continue;
    }

    const isAllowlisted = allowGlobalIdx
      ? checkIndexMatch(allowGlobalIdx, bareIp, ipInt) !== null
      : false;
    const isExcludedFromLongTerm = longtermExcludeIdx
      ? checkIndexMatch(longtermExcludeIdx, bareIp, ipInt) !== null
      : false;

    const matches: IpQueryFeedMatch[] = [];
    for (const [, feedIdx] of indexMap.entries()) {
      if (!feedIdx.isBlocklist) continue;
      const m = checkIndexMatch(feedIdx, bareIp, ipInt);
      if (m) {
        matches.push({
          feedId: feedIdx.id,
          displayName: feedIdx.displayName,
          categoryLabel: feedIdx.categoryLabel,
          generatorLabel: feedIdx.generatorLabel,
          cadenceLabel: feedIdx.cadenceLabel,
          matchType: m.matchType,
          matchedRule: m.matchedRule,
          retentionPolicy: getRetentionPolicyByGenerator(feedIdx.generator),
        });
      }
    }

    if (matches.length > 0) {
      blockedCount += 1;
      const hasLongTerm = matches.some((m) => m.feedId === 'longterm_auto');
      const hasTopN = matches.some((m) => m.feedId.startsWith('traffic_'));
      const hasCidr = matches.some((m) => m.matchType === 'cidr_subnet');

      const notes: string[] = [];
      if (hasLongTerm) {
        notes.push(
          '已列入「自動化長期黑名單 (AutoLongTerm-Blocklist-v1)」，預設自最後觀測日起算 30 天 TTL 後自動退場；若確認為正常業務 IP 需立即解封，請將其加入 longterm_exclude.txt 或 ncloud_allowlist.txt。'
        );
      }
      if (hasTopN) {
        notes.push(
          '已列入「當日流量威脅清單 (TopN)」，將於每日 00:00 自動歸零重算；若跨 3 個日曆日重複出現將晉升至長期黑名單。'
        );
      }
      if (hasCidr) {
        notes.push(
          '命中郵件閘道 CIDR 網段封鎖（非單點 IP 規則，而是落入被封鎖之子網段範圍內）。'
        );
      }
      if (notes.length === 0) {
        notes.push(
          '目前存在於外部封鎖清單中，邊界防火牆將依據 EDL 同步機制予以阻斷。'
        );
      }

      results.push({
        query: bareIp,
        isValidIp: true,
        status: 'blocked',
        statusLabel: `🔴 處於封鎖中 (命中 ${matches.length} 份清單)`,
        isAllowlisted,
        isExcludedFromLongTerm,
        matches,
        advisory: notes.join(' '),
      });
    } else if (isAllowlisted || isExcludedFromLongTerm) {
      cleanCount += 1;
      results.push({
        query: bareIp,
        isValidIp: true,
        status: 'allowlisted',
        statusLabel: '🛡️ 白名單/剔除清單保護中 (未封鎖)',
        isAllowlisted,
        isExcludedFromLongTerm,
        matches: [],
        advisory: `此 IP 目前未在任何黑名單中，且已受 ${
          isAllowlisted ? '全域允許清單 (ncloud_allowlist.txt)' : ''
        }${isAllowlisted && isExcludedFromLongTerm ? ' 與 ' : ''}${
          isExcludedFromLongTerm ? '長期黑名單手動剔除清單 (longterm_exclude.txt)' : ''
        } 保護。`,
      });
    } else {
      cleanCount += 1;
      results.push({
        query: bareIp,
        isValidIp: true,
        status: 'clean',
        statusLabel: '🟢 未在最新黑名單中 (0 次封鎖)',
        isAllowlisted: false,
        isExcludedFromLongTerm: false,
        matches: [],
        advisory:
          '此 IP 目前未出現在任何現行外部威脅 IP 封鎖清單或郵件 CIDR 封鎖網段中。',
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
    cleanCount,
    results,
  };
}

