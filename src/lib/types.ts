export type FeedCategory =
  | 'ext_ip'      // 封鎖-外部威脅IP
  | 'fqdn_mail'   // 封鎖-郵件/惡意網域
  | 'internal'    // 內網微隔離 (不暴露連結與內容)
  | 'allow';      // 白名單/服務資產清冊 (不暴露連結與內容)

export type FeedKind = 'ip' | 'cidr' | 'fqdn' | 'mac' | 'html';

export type GeneratorScriptId =
  | 'longterm'
  | 'topn'
  | 'ntech'
  | 'emailsys'
  | 'manual';

export interface FeedDefinition {
  id: string;
  file: string;
  displayName: string;
  category: FeedCategory;
  categoryLabel: string;
  kind: FeedKind;
  generator: GeneratorScriptId;
  generatorLabel: string;
  cadenceMinutes: number | null;
  cadenceLabel: string;
  description: string;
  isSensitiveInternal: boolean;
  isBlocklist: boolean;
}

export interface ScriptScheduleConfig {
  id: Exclude<GeneratorScriptId, 'manual'>;
  name: string;
  version: string;
  cronExpression: string;
  runsPerDay: number;
  intervalMinutes: number;
  warnThresholdMinutes: number;
  note: string;
}

export interface GitHubCommitItem {
  sha: string;
  commit: {
    message: string;
    committer?: { date?: string };
    author?: { date?: string };
  };
}

export interface LongTermTrendPoint {
  sha: string;
  shortSha: string;
  timestampIso: string;
  displayTime: string;
  shortTime: string;
  dateKey: string;
  total: number;
  added: number;
  removed: number;
  sourceType: 'global_or_batch' | 'traffic_incremental';
}

export interface DailyLongTermTrend {
  date: string;
  shortDate: string;
  closingTotal: number;
  dailyAdded: number;
  dailyRemoved: number;
  commitCount: number;
}

export interface ScriptHealthStatus {
  id: ScriptScheduleConfig['id'];
  name: string;
  version: string;
  cronExpression: string;
  runsPerDay: number;
  warnThresholdMinutes: number;
  lastCommitSha: string | null;
  lastCommitTimeIso: string | null;
  lastCommitDisplay: string | null;
  minutesAgo: number | null;
  status: 'healthy' | 'warning' | 'unknown';
  note: string;
}

export interface FeedSnapshotItem {
  id: string;
  displayName: string;
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
  singleListLimit: number;
  singleListPct: number;
  singleListAlertLevel: 'normal' | 'warning' | 'critical';
  fileSizeLimitBytes: number;
  fileSizePct: number;
  systemStandardLimit: number;
  systemStandardPct: number;
  systemMaxLimit: number;
  systemMaxPct: number;
  estimatedDaysTo100k: number | null;
  estimatedDaysTo131k: number | null;
  firstTtlExpiryDate: string;
}

export interface DashboardSnapshot {
  headSha: string;
  shortHeadSha: string;
  headTimeIso: string;
  headTimeDisplay: string;
  fetchedAtIso: string;
  fetchedAtDisplay: string;
  isStaleFallback: boolean;
  staleReason: string | null;

  totalCommitsCount: number;
  dailyScheduledRuns: number;
  totalFeedsCount: number;
  uniqueExternalBlockIPv4: number;
  rawExternalBlockEntries: number;
  protectedAndInternalEntries: number;
  internalMisblockCount: number;

  pillars: {
    externalIntelCount: number;
    campusTrafficCount: number;
    emailAndFqdnCount: number;
    microSegAndAllowCount: number;
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

export interface IpQueryFeedMatch {
  feedId: string;
  fileName: string;
  displayName: string;
  category: FeedCategory;
  categoryLabel: string;
  isBlocklist: boolean;
  generatorLabel: string;
  cadenceLabel: string;
  description: string;
  matchType:
    | 'exact_ip'
    | 'cidr_subnet'
    | 'exact_fqdn'
    | 'wildcard_fqdn'
    | 'comment_host'
    | 'exact_mac'
    | 'historical_ip';
  matchedRule: string;
  lineNumber: number | null;
  commentNote: string | null;
  retentionPolicy: string;
  isHistoricalOnly?: boolean;
  lastSeenDisplay?: string | null;
  lastSeenSha?: string | null;
}

export interface IpQueryResultItem {
  query: string;
  isValidIp: boolean;
  status:
    | 'blocked'
    | 'historical_blocked'
    | 'in_allowlist_only'
    | 'not_in_any_list'
    | 'invalid';
  statusLabel: string;
  isAllowlisted: boolean;
  isExcludedFromLongTerm: boolean;
  blockMatches: IpQueryFeedMatch[];
  historicalBlockMatches: IpQueryFeedMatch[];
  allowMatches: IpQueryFeedMatch[];
  matches: IpQueryFeedMatch[];
  advisory: string;
}

export interface IpQueryResponsePayload {
  headSha: string;
  shortHeadSha: string;
  headTimeDisplay: string;
  queriedAtDisplay: string;
  totalQueried: number;
  blockedCount: number;
  historicalBlockedCount: number;
  inAllowlistCount: number;
  cleanCount: number;
  scannedFilesCount: number;
  historicalDaysCovered: number;
  results: IpQueryResultItem[];
}


