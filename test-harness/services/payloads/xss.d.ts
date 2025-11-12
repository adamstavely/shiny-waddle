export interface XSSPayload {
    payload: string;
    description: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    type: 'reflected' | 'stored' | 'dom-based' | 'universal';
    context?: 'html' | 'attribute' | 'javascript' | 'css' | 'url';
}
export declare const XSS_PAYLOADS: XSSPayload[];
export declare function getXSSPayloads(type?: string): XSSPayload[];
export declare function getXSSPayloadsByContext(context?: string): XSSPayload[];
