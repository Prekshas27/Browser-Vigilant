import { NextResponse } from 'next/server';
export const dynamic = 'force-dynamic';
import { threatRegistry, syncLogs } from '@/lib/store';

export async function POST(req: Request) {
    try {
        const body = await req.json();
        const { hash, source, confidence, threatType, clientId } = body;

        if (!hash || typeof hash !== 'string' || hash.length !== 64) {
            return NextResponse.json({ error: "Invalid SHA-256 hash" }, { status: 400 });
        }

        // Blockchain-style threat registration
        const existingThreat = threatRegistry.get(hash);

        if (existingThreat) {
            // Update existing threat with higher confidence
            existingThreat.confidence = Math.max(confidence || 0, existingThreat.confidence);
            existingThreat.threatType = threatType || existingThreat.threatType;
            existingThreat.updatedAt = new Date().toISOString();
            existingThreat.sources = [...new Set([...(existingThreat.sources || []), source || 'extension'])];
        } else {
            // Register new threat
            threatRegistry.set(hash, {
                hash,
                source: source || 'extension-ml',
                confidence: confidence || 1.0,
                threatType: threatType || null,
                sources: [source || 'extension'],
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString(),
                status: 'pending' // Will be verified through consensus
            });
        }

        // Log the sync event
        const syncId = `sync_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        syncLogs.set(syncId, {
            id: syncId,
            clientId: clientId || 'anonymous',
            syncedAt: new Date().toISOString(),
            hashCount: 1,
            threatHash: hash
        });

        const threat = threatRegistry.get(hash);
        return NextResponse.json({
            success: true,
            threat,
            syncId
        }, { status: 201 });

    } catch (e: any) {
        console.error("Blockchain vault submit error:", e);
        return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });
    }
}

// Get threat by hash
export async function GET(req: Request) {
    try {
        const { searchParams } = new URL(req.url);
        const hash = searchParams.get('hash');

        if (!hash) {
            return NextResponse.json({ error: "Hash parameter required" }, { status: 400 });
        }

        const threat = threatRegistry.get(hash);
        if (!threat) {
            return NextResponse.json({ error: "Threat not found" }, { status: 404 });
        }

        return NextResponse.json({ threat });
    } catch (e: any) {
        console.error("Vault get error:", e);
        return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });
    }
}
