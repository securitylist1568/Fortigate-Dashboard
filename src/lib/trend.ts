import { SCRIPT_SCHEDULES } from './feeds.manifest';
import type {
  ScriptScheduleConfig,
  GitHubCommitItem,
  LongTermTrendPoint,
  DailyLongTermTrend,
  ScriptHealthStatus,
} from './types';

export type {
  ScriptScheduleConfig,
  GitHubCommitItem,
  LongTermTrendPoint,
  DailyLongTermTrend,
  ScriptHealthStatus,
};

const LONGTERM_COMMIT_REGEX =
  /^feed\(longterm\s+v[\d.]+\):\s*update\s+g-BLACK_IP_AutoLongTerm-v1\.txt\s*\(total=(\d+)\s+added=(\d+)\s+removed=(\d+)\)/i;

const SCRIPT_PREFIX_REGEX: Record<ScriptScheduleConfig['id'], RegExp> = {
  longterm: /^feed\(longterm\s+v[\d.]+\):/i,
  topn: /^feed\(py\s+v[\d.]+\):/i,
  ntech: /^feed\(ntech\s+v[\d.]+\):/i,
  emailsys: /^feed\(emailsys\s+v[\d.]+\):/i,
};

export function formatTaipeiTime(isoString: string): {
  displayTime: string;
  shortTime: string;
  dateKey: string;
} {
  const d = new Date(isoString);
  if (Number.isNaN(d.getTime())) {
    return { displayTime: isoString, shortTime: isoString, dateKey: 'unknown' };
  }
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
      sha: c.sha.slice(0, 10),
      shortSha: c.sha.slice(0, 10),
      timestampIso: iso,
      displayTime,
      shortTime,
      dateKey,
      total: parsed.total,
      added: parsed.added,
      removed: parsed.removed,
      sourceType: parsed.added >= 100 ? 'global_or_batch' : 'traffic_incremental',
    });
  }

  parsedPoints.sort(
    (a, b) =>
      new Date(a.timestampIso).getTime() - new Date(b.timestampIso).getTime()
  );

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
    points: parsedPoints.slice(-60),
    daily: Array.from(byDate.values()),
    last24hAdded,
    last24hRemoved,
    last24hCommits,
  };
}

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
