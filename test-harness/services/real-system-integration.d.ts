import { TestQuery, User } from '../core/types';
export interface DatabaseConnection {
    type: 'postgresql' | 'mysql' | 'sqlite' | 'mssql' | 'oracle';
    connectionString: string;
    options?: Record<string, any>;
}
export interface APIConnection {
    baseUrl: string;
    authentication?: {
        type: 'bearer' | 'basic' | 'oauth2' | 'api-key';
        credentials: Record<string, string>;
    };
    headers?: Record<string, string>;
}
export interface IdentityProviderConnection {
    type: 'ldap' | 'oauth2' | 'saml' | 'active-directory' | 'okta' | 'auth0';
    endpoint: string;
    credentials: Record<string, string>;
    options?: Record<string, any>;
}
export interface QueryExecutionResult {
    success: boolean;
    rows?: any[];
    rowCount?: number;
    executionTime?: number;
    error?: string;
    queryPlan?: any;
}
export interface APIResponse {
    status: number;
    headers: Record<string, string>;
    body: any;
    executionTime?: number;
}
export declare class RealSystemIntegration {
    executeDatabaseQuery(connection: DatabaseConnection, query: TestQuery): Promise<QueryExecutionResult>;
    private executePostgreSQLQuery;
    private executePostgreSQLViaAPI;
    private executeMySQLQuery;
    private executeSQLiteQuery;
    executeAPIRequest(connection: APIConnection, query: TestQuery, user?: User): Promise<APIResponse>;
    private getAuthHeader;
    authenticateUser(idp: IdentityProviderConnection, username: string, password: string): Promise<{
        success: boolean;
        user?: User;
        error?: string;
    }>;
    private authenticateLDAP;
    private mapLDAPGroupsToRole;
    private authenticateOAuth2;
    private mapOAuth2RolesToRole;
    private authenticateSAML;
    private authenticateSAMLViaHTTP;
    private parseSAMLAssertion;
    private mapSAMLAttributesToRole;
    getUserAttributes(idp: IdentityProviderConnection, userId: string): Promise<Record<string, any>>;
    private getLDAPAttributes;
    private getOAuth2Attributes;
    private getSAMLAttributes;
    validateAPIResponse(response: APIResponse, expectedFields?: string[], piiFields?: string[]): {
        compliant: boolean;
        violations: string[];
    };
    private detectPIIInResponse;
    private findUnexpectedFields;
}
