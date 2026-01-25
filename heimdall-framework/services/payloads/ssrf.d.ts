export interface SSRFPayload {
    url: string;
    description: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    target: 'localhost' | 'internal' | 'cloud' | 'external';
}
export declare const SSRF_PAYLOADS: SSRFPayload[];
export declare function getSSRFPayloads(target?: string): SSRFPayload[];
export declare function getSSRFPayloadsBySeverity(severity: 'critical' | 'high' | 'medium' | 'low'): SSRFPayload[];
