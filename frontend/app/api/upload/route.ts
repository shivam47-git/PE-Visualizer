import { NextRequest, NextResponse } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// Stream multipart form data directly to C++ backend — no buffering
export async function POST(req: NextRequest) {
  try {
    const contentType = req.headers.get('content-type') || '';
    const contentLength = req.headers.get('content-length') || '';

    console.log('[upload] content-type:', contentType);
    console.log('[upload] content-length:', contentLength);

    // Stream body directly to backend without buffering
    const response = await fetch('http://127.0.0.1:9000/api/upload', {
      method: 'POST',
      headers: {
        'content-type': contentType,
        ...(contentLength ? { 'content-length': contentLength } : {}),
      },
      // @ts-ignore — duplex needed for streaming in Node 18+
      duplex: 'half',
      body: req.body,
    });

    console.log('[upload] backend status:', response.status);
    const data = await response.text();
    return new NextResponse(data, {
      status: response.status,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (e: any) {
    console.error('[upload] error:', e.message);
    return NextResponse.json({ error: e.message }, { status: 500 });
  }
}
