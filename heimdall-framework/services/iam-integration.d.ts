export interface SSOConfig {
    type: 'saml' | 'oidc';
    enabled: boolean;
    endpoint: string;
    entityId?: string;
    certificate?: string;
    privateKey?: string;
    clientId?: string;
    clientSecret?: string;
    redirectUri?: string;
    scopes?: string[];
    options?: Record<string, any>;
}
export interface RBACConfig {
    provider: 'okta' | 'auth0' | 'azure-ad' | 'aws-iam' | 'gcp-iam' | 'custom';
    enabled: boolean;
    endpoint: string;
    apiKey?: string;
    options?: Record<string, any>;
}
export interface PAMConfig {
    provider: 'cyberark' | 'hashicorp-vault' | 'aws-secrets-manager' | 'azure-key-vault' | 'custom';
    enabled: boolean;
    endpoint: string;
    authentication: {
        type: 'basic' | 'bearer' | 'api-key' | 'oauth2';
        credentials: Record<string, string>;
    };
    options?: Record<string, any>;
}
export interface IdPConfig {
    type: 'ldap' | 'active-directory' | 'okta' | 'auth0' | 'azure-ad' | 'google-workspace' | 'custom';
    enabled: boolean;
    endpoint: string;
    authentication: {
        type: 'basic' | 'bearer' | 'api-key' | 'oauth2';
        credentials: Record<string, string>;
    };
    options?: Record<string, any>;
}
export interface User {
    id: string;
    email: string;
    name: string;
    roles: string[];
    groups: string[];
    attributes: Record<string, any>;
}
export interface Role {
    id: string;
    name: string;
    permissions: string[];
    description?: string;
}
export interface Permission {
    id: string;
    name: string;
    resource: string;
    action: string;
    conditions?: Record<string, any>;
}
export declare class SSOIntegration {
    private config;
    private client;
    constructor(config: SSOConfig);
    generateSAMLAuthUrl(relayState?: string): string;
    generateOIDCAuthUrl(state?: string, nonce?: string): string;
    exchangeOIDCCode(code: string): Promise<{
        accessToken: string;
        idToken: string;
        refreshToken?: string;
    }>;
    validateSAMLAssertion(assertion: string): Promise<{
        valid: boolean;
        user?: User;
        error?: string;
    }>;
    private generateSAMLRequest;
    private generateID;
    private parseSAMLUser;
}
export declare class RBACIntegration {
    private config;
    private client;
    constructor(config: RBACConfig);
    getUserRoles(userId: string): Promise<Role[]>;
    getRolePermissions(roleId: string): Promise<Permission[]>;
    hasPermission(userId: string, resource: string, action: string): Promise<boolean>;
    assignRole(userId: string, roleId: string): Promise<boolean>;
    removeRole(userId: string, roleId: string): Promise<boolean>;
}
export declare class PAMIntegration {
    private config;
    private client;
    constructor(config: PAMConfig);
    private setupAuthentication;
    getSecret(secretPath: string): Promise<{
        value: string;
        metadata?: Record<string, any>;
    }>;
    storeSecret(secretPath: string, value: string, metadata?: Record<string, any>): Promise<boolean>;
    deleteSecret(secretPath: string): Promise<boolean>;
    listSecrets(path: string): Promise<string[]>;
    rotateSecret(secretPath: string): Promise<boolean>;
}
export declare class IdPIntegration {
    private config;
    private client;
    constructor(config: IdPConfig);
    private setupAuthentication;
    authenticateUser(username: string, password: string): Promise<{
        success: boolean;
        user?: User;
        error?: string;
    }>;
    getUser(userId: string): Promise<User | null>;
    searchUsers(query: string): Promise<User[]>;
    getUserGroups(userId: string): Promise<string[]>;
    private authenticateLDAP;
    private authenticateOAuth2;
    private parseUser;
}
export declare class IAMIntegration {
    private sso;
    private rbac;
    private pam;
    private idp;
    registerSSO(id: string, config: SSOConfig): void;
    registerRBAC(id: string, config: RBACConfig): void;
    registerPAM(id: string, config: PAMConfig): void;
    registerIdP(id: string, config: IdPConfig): void;
    getSSO(id: string): SSOIntegration | undefined;
    getRBAC(id: string): RBACIntegration | undefined;
    getPAM(id: string): PAMIntegration | undefined;
    getIdP(id: string): IdPIntegration | undefined;
}
