import { NextResponse } from 'next/server';
export const dynamic = 'force-dynamic';
import { threatRegistry } from '@/lib/store';

/**
 * Endpoint for extensions to sync their local threat database with the global network.
 * Returns new threat hashes since a given timestamp.
 */
export async function GET(req: Request) {
    try {
        const { searchParams } = new URL(req.url);
        const sinceStr = searchParams.get('since') || '0';
        const since = parseInt(sinceStr);

        const allThreats = Array.from(threatRegistry.values() as IterableIterator<any>);

        // Filter threats created after the 'since' timestamp
        // If 'since' is 0, it returns everything
        const newThreats = allThreats.filter(t => {
            const createdAt = new Date(t.createdAt).getTime();
            return createdAt > since;
        });

        const hashes = newThreats.map(t => t.hash);

        console.log(`[Sync API] Sending ${hashes.length} hashes to client since ${new Date(since).toISOString()}`);

        return NextResponse.json({
            hashes,
            timestamp: Date.now(),
            count: hashes.length
        });
    } catch (e: any) {
        console.error('Vault sync error:', e);
        return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
    }
}
