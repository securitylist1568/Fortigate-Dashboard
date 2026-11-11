import { NextResponse } from 'next/server';
import { getDashboardSnapshot } from '@/lib/cti-fetcher';
import {
  encryptSnapshotPayload,
  EncryptedVaultPayload,
} from '@/lib/vault-crypto';

export const runtime = 'nodejs';

// In-memory encrypted payload cache so identical headSha +fetchedAtDisplay reuses ciphertext
let cachedEncryptedSnapshot: {
  cacheKey: string;
  payload: EncryptedVaultPayload;
} | null = null;

export async function GET() {
  try {
    const passkey = process.env.VAULT_PASSKEY?.trim();
    if (!passkey) {
      return NextResponse.json(
        {
          error:
            '伺服器尚未設定 VAULT_PASSKEY 環境變數，請於 Vercel Project Settings -> Environment Variables 配置。',
        },
        {
          status: 503,
          headers: {
            'Cache-Control': 'no-store, must-revalidate',
            'X-Robots-Tag': 'noindex, nofollow, noarchive',
          },
        }
      );
    }

    const snapshot = await getDashboardSnapshot(false);
    const cacheKey = `${snapshot.headSha}:${snapshot.fetchedAtDisplay}:${passkey.slice(0, 4)}`;

    let encryptedPayload: EncryptedVaultPayload;
    if (cachedEncryptedSnapshot && cachedEncryptedSnapshot.cacheKey === cacheKey) {
      encryptedPayload = cachedEncryptedSnapshot.payload;
    } else {
      encryptedPayload = encryptSnapshotPayload(snapshot, passkey);
      cachedEncryptedSnapshot = { cacheKey, payload: encryptedPayload };
    }

    // Safe to cache on Vercel Edge CDN because payload is AES-256-GCM ciphertext (zero plaintext exposure).
    // Converts 99% of requests from Fast Origin Transfer (10GB quota) to Fast Data Transfer (100GB quota).
    const cacheHeader =
      'public, max-age=60, s-maxage=180, stale-while-revalidate=600';

    return NextResponse.json(encryptedPayload, {
      status: 200,
      headers: {
        'Cache-Control': cacheHeader,
        'CDN-Cache-Control': 'public, s-maxage=180, stale-while-revalidate=600',
        'Vercel-CDN-Cache-Control':
          'public, s-maxage=180, stale-while-revalidate=600',
        'X-Robots-Tag': 'noindex, nofollow, noarchive',
      },
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Unknown server error';
    return NextResponse.json(
      { error: `無法取得資安情資快照：${message}` },
      {
        status: 500,
        headers: {
          'Cache-Control': 'no-store',
          'X-Robots-Tag': 'noindex, nofollow, noarchive',
        },
      }
    );
  }
}

