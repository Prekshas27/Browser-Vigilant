// Persistent in-memory store for development (avoids reset on hot-reload)
const globalStore = global as any;

if (!globalStore.threatRegistry) {
    globalStore.threatRegistry = new Map<string, any>();
}
if (!globalStore.syncLogs) {
    globalStore.syncLogs = new Map<string, any>();
}

export const threatRegistry = globalStore.threatRegistry;
export const syncLogs = globalStore.syncLogs;

/**
 * Ensures a consistent hostname for hashing.
 * Removes protocol, port, 'www.', and trailing slashes.
 */
export function cleanHostname(domainOrUrl: string): string {
    try {
        let hostname = domainOrUrl.trim().toLowerCase();
        if (hostname.includes('://')) {
            hostname = new URL(hostname).hostname;
        } else if (hostname.includes('/')) {
            hostname = hostname.split('/')[0];
        }
        // Remove 'www.' for consistency
        if (hostname.startsWith('www.')) {
            hostname = hostname.slice(4);
        }
        // Remove port if present
        if (hostname.includes(':')) {
            hostname = hostname.split(':')[0];
        }
        return hostname;
    } catch (e) {
        return domainOrUrl.toLowerCase().trim().replace(/^www\./, '');
    }
}

// Helper to get formatted stats
export function getVaultStats() {
    const allThreats = Array.from(threatRegistry.values() as IterableIterator<any>);
    const verifiedThreats = allThreats.filter(t => t.status === 'verified' || t.confidence > 0.8);

    const recentThreats = allThreats
        .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
        .slice(0, 10);

    const sourceMap = new Map<string, number>();
    allThreats.forEach(threat => {
        const source = (threat.source || 'extension').toLowerCase();
        sourceMap.set(source, (sourceMap.get(source) || 0) + 1);
    });

    const sourceBreakdown = Array.from(sourceMap.entries())
        .map(([source, count]) => ({ source, count }))
        .sort((a, b) => b.count - a.count);

    return {
        totalThreats: allThreats.length,
        verifiedThreats: verifiedThreats.length,
        recentThreats,
        totalSyncs: syncLogs.size,
        sourceBreakdown,
        lastUpdated: new Date().toISOString()
    };
}
