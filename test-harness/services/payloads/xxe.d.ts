export interface XXEPayload {
    payload: string;
    description: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    attackType: 'file-read' | 'ssrf' | 'dos' | 'blind';
}
export declare const XXE_PAYLOADS: XXEPayload[];
export declare function getXXEPayloads(attackType?: string): XXEPayload[];
