import { UnifiedFinding } from '../core/unified-finding-schema';
import { AxiosInstance } from 'axios';
export interface SIEMConfig {
    type: 'splunk' | 'qradar' | 'sentinel' | 'custom';
    enabled: boolean;
    endpoint: string;
    authentication: {
        type: 'basic' | 'bearer' | 'api-key' | 'oauth2';
        credentials: Record<string, string>;
    };
    options?: Record<string, any>;
}
export interface SIEMEvent {
    timestamp: string;
    source: string;
    severity: string;
    category: string;
    title: string;
    description: string;
    raw: any;
}
export interface SIEMQueryResult {
    events: SIEMEvent[];
    total: number;
    query: string;
}
export declare abstract class BaseSIEMAdapter {
    protected config: SIEMConfig;
    protected client: AxiosInstance;
    constructor(config: SIEMConfig);
    protected setupAuthentication(): void;
    abstract sendFinding(finding: UnifiedFinding): Promise<boolean>;
    abstract queryEvents(query: string, timeRange?: {
        start: Date;
        end: Date;
    }): Promise<SIEMQueryResult>;
    abstract testConnection(): Promise<boolean>;
}
export declare class SplunkAdapter extends BaseSIEMAdapter {
    private sessionKey?;
    testConnection(): Promise<boolean>;
    sendFinding(finding: UnifiedFinding): Promise<boolean>;
    queryEvents(query: string, timeRange?: {
        start: Date;
        end: Date;
    }): Promise<SIEMQueryResult>;
    private convertFindingToSplunkEvent;
    private buildSplunkQuery;
    private parseSplunkEvent;
}
export declare class QRadarAdapter extends BaseSIEMAdapter {
    testConnection(): Promise<boolean>;
    sendFinding(finding: UnifiedFinding): Promise<boolean>;
    queryEvents(query: string, timeRange?: {
        start: Date;
        end: Date;
    }): Promise<SIEMQueryResult>;
    private convertFindingToQRadarEvent;
    private buildQRadarQuery;
    private parseQRadarEvent;
    private mapQRadarSeverity;
}
export declare class SentinelAdapter extends BaseSIEMAdapter {
    private accessToken?;
    testConnection(): Promise<boolean>;
    private authenticate;
    sendFinding(finding: UnifiedFinding): Promise<boolean>;
    queryEvents(query: string, timeRange?: {
        start: Date;
        end: Date;
    }): Promise<SIEMQueryResult>;
    private convertFindingToSentinelEvent;
    private buildSentinelQuery;
    private parseSentinelEvent;
}
export declare class SIEMIntegration {
    private adapters;
    registerAdapter(id: string, adapter: BaseSIEMAdapter): void;
    createAdapter(config: SIEMConfig): BaseSIEMAdapter;
    sendFindingToAll(finding: UnifiedFinding): Promise<Map<string, boolean>>;
    querySIEM(siemId: string, query: string, timeRange?: {
        start: Date;
        end: Date;
    }): Promise<SIEMQueryResult>;
    testSIEMConnection(siemId: string): Promise<boolean>;
}
