import { NextResponse } from 'next/server';
export const dynamic = 'force-dynamic';
import { getVaultStats } from '@/lib/store';

export async function GET() {
    try {
        const stats = getVaultStats();
        return NextResponse.json(stats);
    } catch (e: any) {
        console.error('Blockchain vault stats error:', e);
        return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
    }
}
