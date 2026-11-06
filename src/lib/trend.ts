import { SCRIPT_SCHEDULES, ScriptScheduleConfig } from './feeds.manifest';

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
  displayTime: string; // Asia/Taipei YYYY-MM-DD HH:mm
  shortTime: string;   // MM/DD HH:mm
  dateKey: string;     // YYYY-MM-DD (Asia/Taipei)
  total: number;
  added: number;
  removed: number;
  sourceType: 'abuse_or_batch' | 'ncloud_incremental';
}

export interface DailyLongTermTrend {
  date: string;        // YYYY-MM-DD
  shortDate: string;   // MM/DD
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

// Accepts both `feed(longterm v1.0)` and `feed(longterm v1.0.1)` (or future v1.x.x)
// Strictly ignores non-data commits like `fix:`, `feat:`, `docs:`, etc.
const LONGTERM_COMMIT_REGEX =
  /^feed\(longterm\s+v[\d.]+\):\s*update\s+g-BLACK_IP_AutoLongTerm-v1\.txt\s*\(total=(\d+)\s+added=(\d+)\s+removed=(\d+)\)/i;

const SCRIPT_PREFIX_REGEX: Record<ScriptScheduleConfig['id'], RegExp> = {
  longterm: /^feed\(longterm\s+v[\d.]+\):/i,
  topn: /^feed\(py\s+v[\d.]+\):/i,
  ntech: /^feed\(ntech\s+v[\d.]+\):/i,
  emailsys: /^feed\(emailsys\s+v[\d.]+\):/i,
};

/**
 * Formats an ISO timestamp string into Asia/Taipei `YYYY-MM-DD HH:mm` and `MM/DD HH:mm`.
 */
export function formatTaipeiTime(isoString: string): {
  displayTime: string;
  shortTime: string;
  dateKey: string;
} {
  const d = new Date(isoString);
  if (Number.isNaN(d.getTime())) {
    return { displayTime: isoString, shortTime: isoString, dateKey: 'unknown' };
  }
  // Convert to UTC+8 (Asia/Taipei has no DST)
  const taipeiMs = d.getTime() + 8 * 3600 * 1000;
  const td = new Date(taipeiMs);
  const yyyy = td.getUTCFullYear();
  const mm = String(td.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(td.getUTCDate()).padStart(2, '0');
  const hh = String(td.getUTCHours()).padStart(2, '0');
  const min = String(td.getUTCMinutes()).padStart(2, '0');

  return {
    displayTime: `${yyyy}-${mm}-${dd} ${hh}:${min}`,
    shortTime: `${mm}/${dd} ${hh}:${min}`,
    dateKey: `${yyyy}-${mm}-${dd}`,
  };
}

/**
 * Parses a single LongTerm commit title. Returns null if it is not a data feed commit.
 */
export function parseLongTermCommitTitle(message: string): {
  total: number;
  added: number;
  removed: number;
} | null {
  const firstLine = message.split(/\r?\n/)[0].trim();
  const m = firstLine.match(LONGTERM_COMMIT_REGEX);
  if (!m) return null;
  return {
    total: parseInt(m[1], 10),
    added: parseInt(m[2], 10),
    removed: parseInt(m[3], 10),
  };
}

/**
 * Extracts chronological LongTerm trend points, daily summaries, and 24-hour added/removed totals.
 */
export function buildLongTermTrend(
  commits: GitHubCommitItem[],
  nowMs: number = Date.now()
): {
  points: LongTermTrendPoint[];
  daily: DailyLongTermTrend[];
  last24hAdded: number;
  last24hRemoved: number;
  last24hCommits: number;
} {
  const parsedPoints: LongTermTrendPoint[] = [];

  for (const c of commits) {
    const firstLine = (c.commit?.message || '').split(/\r?\n/)[0].trim();
    const parsed = parseLongTermCommitTitle(firstLine);
    if (!parsed) continue;

    const iso =
      c.commit?.committer?.date ||
      c.commit?.author?.date ||
      new Date(nowMs).toISOString();
    const { displayTime, shortTime, dateKey } = formatTaipeiTime(iso);

    parsedPoints.push({
      sha: c.sha,
      shortSha: c.sha.slice(0, 10),
      timestampIso: iso,
      displayTime,
      shortTime,
      dateKey,
      total: parsed.total,
      added: parsed.added,
      removed: parsed.removed,
      sourceType: parsed.added >= 100 ? 'abuse_or_batch' : 'ncloud_incremental',
    });
  }

  // Sort ascending by time
  parsedPoints.sort(
    (a, b) =>
      new Date(a.timestampIso).getTime() - new Date(b.timestampIso).getTime()
  );

  // Compute last 24h metrics
  const cutoff24h = nowMs - 24 * 3600 * 1000;
  let last24hAdded = 0;
  let last24hRemoved = 0;
  let last24hCommits = 0;

  for (const pt of parsedPoints) {
    const t = new Date(pt.timestampIso).getTime();
    if (t >= cutoff24h) {
      last24hAdded += pt.added;
      last24hRemoved += pt.removed;
      last24hCommits += 1;
    }
  }

  // Group by Asia/Taipei dateKey
  const byDate = new Map<string, DailyLongTermTrend>();
  for (const pt of parsedPoints) {
    const existing = byDate.get(pt.dateKey);
    if (!existing) {
      byDate.set(pt.dateKey, {
        date: pt.dateKey,
        shortDate: pt.dateKey.slice(5).replace('-', '/'),
        closingTotal: pt.total,
        dailyAdded: pt.added,
        dailyRemoved: pt.removed,
        commitCount: 1,
      });
    } else {
      existing.closingTotal = pt.total;
      existing.dailyAdded += pt.added;
      existing.dailyRemoved += pt.removed;
      existing.commitCount += 1;
    }
  }

  return {
    points: parsedPoints,
    daily: Array.from(byDate.values()),
    last24hAdded,
    last24hRemoved,
    last24hCommits,
  };
}

/**
 * Evaluates pipeline health across the 4 scheduled scripts based on recent commit history.
 */
export function evaluatePipelineHealth(
  recentCommits: GitHubCommitItem[],
  nowMs: number = Date.now()
): ScriptHealthStatus[] {
  return SCRIPT_SCHEDULES.map((sched) => {
    const regex = SCRIPT_PREFIX_REGEX[sched.id];
    const matchCommit = recentCommits.find((c) => {
      const firstLine = (c.commit?.message || '').split(/\r?\n/)[0].trim();
      return regex.test(firstLine);
    });

    if (!matchCommit) {
      return {
        id: sched.id,
        name: sched.name,
        version: sched.version,
        cronExpression: sched.cronExpression,
        runsPerDay: sched.runsPerDay,
        warnThresholdMinutes: sched.warnThresholdMinutes,
        lastCommitSha: null,
        lastCommitTimeIso: null,
        lastCommitDisplay: null,
        minutesAgo: null,
        status: 'unknown',
        note: sched.note,
      };
    }

    const iso =
      matchCommit.commit?.committer?.date ||
      matchCommit.commit?.author?.date ||
      new Date(nowMs).toISOString();
    const { displayTime } = formatTaipeiTime(iso);
    const diffMinutes = Math.max(
      0,
      Math.round((nowMs - new Date(iso).getTime()) / 60000)
    );

    const status: ScriptHealthStatus['status'] =
      diffMinutes <= sched.warnThresholdMinutes ? 'healthy' : 'warning';

    return {
      id: sched.id,
      name: sched.name,
      version: sched.version,
      cronExpression: sched.cronExpression,
      runsPerDay: sched.runsPerDay,
      warnThresholdMinutes: sched.warnThresholdMinutes,
      lastCommitSha: matchCommit.sha.slice(0, 10),
      lastCommitTimeIso: iso,
      lastCommitDisplay: displayTime,
      minutesAgo: diffMinutes,
      status,
      note: sched.note,
    };
  });
}
