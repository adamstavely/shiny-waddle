export interface NoSQLInjectionPayload {
    payload: any;
    description: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    database?: 'mongodb' | 'couchdb' | 'cassandra' | 'dynamodb';
}
export declare const NOSQL_INJECTION_PAYLOADS: NoSQLInjectionPayload[];
export declare function nosqlPayloadToString(payload: any): string;
export declare function getNoSQLInjectionPayloads(database?: string): NoSQLInjectionPayload[];
