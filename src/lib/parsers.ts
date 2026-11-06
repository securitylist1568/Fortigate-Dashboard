import { FeedKind } from './feeds.manifest';

export interface ParsedFeedStats {
  count: number;
  bytes: number;
  headerCount: number | null;
  headerMismatch: boolean;
  internalLeakCount: number; // Count of internal/private IPs leaked into external blocklists
  entriesSet: Set<string>;   // Used strictly in-memory on server for deduplication, never serialized!
}

const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

/**
 * Checks whether an IPv4 string belongs to internal protected /16 subnet or RFC1918 private/loopback ranges
 * to verify that external blocklists have zero internal mis-blocks.
 */
export function isCampusOrPrivateIPv4(ip: string): boolean {
  if (!IPV4_REGEX.test(ip)) return false;
  const parts = ip.split('.').map(Number);
  const [a, b] = parts;
  if (a === 140 && b === 122) return true;
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  return false;
}

/**
 * Parses a raw feed file content into summary statistics.
 * Handles CRLF/LF normalization, strips # comments (including inline comments),
 * extracts `# Count: <num>` header if present, and checks for header mismatches.
 */
export function parseFeedContent(
  rawText: string,
  kind: FeedKind,
  checkInternalLeak: boolean = false
): ParsedFeedStats {
  const bytes = Buffer.byteLength(rawText, 'utf8');

  if (kind === 'html') {
    const trimmed = rawText.trim();
    return {
      count: trimmed.length > 0 ? 1 : 0,
      bytes,
      headerCount: null,
      headerMismatch: false,
      internalLeakCount: 0,
      entriesSet: new Set<string>(),
    };
  }

  const normalized = rawText.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  const lines = normalized.split('\n');

  let headerCount: number | null = null;
  const entriesSet = new Set<string>();
  let validLineCount = 0;
  let internalLeakCount = 0;

  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (!trimmed) continue;

    if (trimmed.startsWith('#')) {
      const m = trimmed.match(/^#\s*Count\s*:\s*(\d+)/i);
      if (m) {
        headerCount = parseInt(m[1], 10);
      }
      continue;
    }

    // Strip inline comments or trailing descriptions
    const token = trimmed.split(/\s+#|\s+/)[0].trim();
    if (!token) continue;

    validLineCount += 1;
    entriesSet.add(token);

    if (checkInternalLeak && kind === 'ip') {
      const bareIp = token.split('/')[0];
      if (isCampusOrPrivateIPv4(bareIp)) {
        internalLeakCount += 1;
      }
    }
  }

  const headerMismatch = headerCount !== null && headerCount !== validLineCount;

  return {
    count: validLineCount,
    bytes,
    headerCount,
    headerMismatch,
    internalLeakCount,
    entriesSet,
  };
}
