import { NextResponse } from 'next/server';
import { getDashboardSnapshot } from '@/lib/cti-fetcher';
import { encryptSnapshotPayload } from '@/lib/vault-crypto';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

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
    const encryptedPayload = encryptSnapshotPayload(snapshot, passkey);

    return NextResponse.json(encryptedPayload, {
      status: 200,
      headers: {
        'Cache-Control': 'private, no-store, must-revalidate',
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

