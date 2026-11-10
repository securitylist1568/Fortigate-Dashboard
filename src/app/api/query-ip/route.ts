import { NextRequest, NextResponse } from 'next/server';
import { queryIpsAgainstFeeds } from '@/lib/cti-fetcher';
import { encryptSnapshotPayload } from '@/lib/vault-crypto';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
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

    const body = await req.json().catch(() => ({}));
    const rawInput: string =
      typeof body?.queryText === 'string' ? body.queryText : '';

    const tokens = rawInput
      .split(/[\s,;，；\n\r]+/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);

    if (tokens.length === 0) {
      return NextResponse.json(
        { error: '請至少輸入一個要查詢的 IPv4 位址。' },
        { status: 400 }
      );
    }

    const queryResult = await queryIpsAgainstFeeds(tokens);
    const encryptedPayload = encryptSnapshotPayload(queryResult, passkey);

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
      { error: `IP 查詢失敗：${message}` },
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
