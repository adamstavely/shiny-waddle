export interface SQLInjectionPayload {
    payload: string;
    description: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    database?: string;
}
export declare const SQL_INJECTION_PAYLOADS: SQLInjectionPayload[];
export declare function getSQLInjectionPayloads(database?: string): SQLInjectionPayload[];
export declare function getSQLInjectionPayloadsBySeverity(severity: 'critical' | 'high' | 'medium' | 'low'): SQLInjectionPayload[];
