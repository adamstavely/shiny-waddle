"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.IAMIntegration = exports.IdPIntegration = exports.PAMIntegration = exports.RBACIntegration = exports.SSOIntegration = void 0;
const axios_1 = require("axios");
class SSOIntegration {
    constructor(config) {
        this.config = config;
        this.client = axios_1.default.create({
            baseURL: config.endpoint,
            timeout: 30000,
        });
    }
    generateSAMLAuthUrl(relayState) {
        if (this.config.type !== 'saml') {
            throw new Error('SSO type must be SAML');
        }
        const params = new URLSearchParams({
            SAMLRequest: this.generateSAMLRequest(),
            ...(relayState && { RelayState: relayState }),
        });
        return `${this.config.endpoint}?${params.toString()}`;
    }
    generateOIDCAuthUrl(state, nonce) {
        if (this.config.type !== 'oidc') {
            throw new Error('SSO type must be OIDC');
        }
        const params = new URLSearchParams({
            client_id: this.config.clientId || '',
            redirect_uri: this.config.redirectUri || '',
            response_type: 'code',
            scope: (this.config.scopes || ['openid', 'profile', 'email']).join(' '),
            ...(state && { state }),
            ...(nonce && { nonce }),
        });
        return `${this.config.endpoint}/authorize?${params.toString()}`;
    }
    async exchangeOIDCCode(code) {
        if (this.config.type !== 'oidc') {
            throw new Error('SSO type must be OIDC');
        }
        const response = await this.client.post('/token', new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            redirect_uri: this.config.redirectUri || '',
            client_id: this.config.clientId || '',
            client_secret: this.config.clientSecret || '',
        }), {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
        });
        return {
            accessToken: response.data.access_token,
            idToken: response.data.id_token,
            refreshToken: response.data.refresh_token,
        };
    }
    async validateSAMLAssertion(assertion) {
        if (this.config.type !== 'saml') {
            throw new Error('SSO type must be SAML');
        }
        try {
            const response = await this.client.post('/saml/validate', {
                assertion,
                entityId: this.config.entityId,
            });
            if (response.data.valid) {
                return {
                    valid: true,
                    user: this.parseSAMLUser(response.data.attributes),
                };
            }
            return {
                valid: false,
                error: response.data.error || 'Invalid SAML assertion',
            };
        }
        catch (error) {
            return {
                valid: false,
                error: error.message,
            };
        }
    }
    generateSAMLRequest() {
        const request = `<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    ID="${this.generateID()}"
                    Version="2.0"
                    IssueInstant="${new Date().toISOString()}"
                    Destination="${this.config.endpoint}">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${this.config.entityId}</saml:Issuer>
</samlp:AuthnRequest>`;
        return Buffer.from(request).toString('base64');
    }
    generateID() {
        return `_${Math.random().toString(36).substr(2, 9)}`;
    }
    parseSAMLUser(attributes) {
        return {
            id: attributes.nameID || attributes.uid || attributes.email || '',
            email: attributes.email || attributes.mail || '',
            name: attributes.name || attributes.cn || attributes.displayName || '',
            roles: attributes.roles || attributes.groups || [],
            groups: attributes.groups || [],
            attributes,
        };
    }
}
exports.SSOIntegration = SSOIntegration;
class RBACIntegration {
    constructor(config) {
        this.config = config;
        this.client = axios_1.default.create({
            baseURL: config.endpoint,
            timeout: 30000,
            headers: {
                ...(config.apiKey && { 'Authorization': `Bearer ${config.apiKey}` }),
            },
        });
    }
    async getUserRoles(userId) {
        try {
            const response = await this.client.get(`/users/${userId}/roles`);
            return response.data.roles || [];
        }
        catch (error) {
            console.error('Failed to get user roles:', error.message);
            return [];
        }
    }
    async getRolePermissions(roleId) {
        try {
            const response = await this.client.get(`/roles/${roleId}/permissions`);
            return response.data.permissions || [];
        }
        catch (error) {
            console.error('Failed to get role permissions:', error.message);
            return [];
        }
    }
    async hasPermission(userId, resource, action) {
        try {
            const roles = await this.getUserRoles(userId);
            for (const role of roles) {
                const permissions = await this.getRolePermissions(role.id);
                const hasPermission = permissions.some(p => p.resource === resource && p.action === action);
                if (hasPermission)
                    return true;
            }
            return false;
        }
        catch (error) {
            console.error('Failed to check permission:', error.message);
            return false;
        }
    }
    async assignRole(userId, roleId) {
        try {
            const response = await this.client.post(`/users/${userId}/roles`, {
                roleId,
            });
            return response.status === 200 || response.status === 201;
        }
        catch (error) {
            console.error('Failed to assign role:', error.message);
            return false;
        }
    }
    async removeRole(userId, roleId) {
        try {
            const response = await this.client.delete(`/users/${userId}/roles/${roleId}`);
            return response.status === 200 || response.status === 204;
        }
        catch (error) {
            console.error('Failed to remove role:', error.message);
            return false;
        }
    }
}
exports.RBACIntegration = RBACIntegration;
class PAMIntegration {
    constructor(config) {
        this.config = config;
        this.client = axios_1.default.create({
            baseURL: config.endpoint,
            timeout: 30000,
        });
        this.setupAuthentication();
    }
    setupAuthentication() {
        const { authentication } = this.config;
        switch (authentication.type) {
            case 'basic':
                this.client.defaults.auth = {
                    username: authentication.credentials.username || '',
                    password: authentication.credentials.password || '',
                };
                break;
            case 'bearer':
                this.client.defaults.headers.common['Authorization'] =
                    `Bearer ${authentication.credentials.token}`;
                break;
            case 'api-key':
                const apiKeyHeader = authentication.credentials.headerName || 'X-API-Key';
                this.client.defaults.headers.common[apiKeyHeader] =
                    authentication.credentials.apiKey || '';
                break;
        }
    }
    async getSecret(secretPath) {
        try {
            const response = await this.client.get(`/secrets/${secretPath}`);
            return {
                value: response.data.value || response.data.data?.value || '',
                metadata: response.data.metadata,
            };
        }
        catch (error) {
            console.error('Failed to get secret:', error.message);
            throw error;
        }
    }
    async storeSecret(secretPath, value, metadata) {
        try {
            const response = await this.client.post(`/secrets/${secretPath}`, {
                value,
                metadata,
            });
            return response.status === 200 || response.status === 201;
        }
        catch (error) {
            console.error('Failed to store secret:', error.message);
            return false;
        }
    }
    async deleteSecret(secretPath) {
        try {
            const response = await this.client.delete(`/secrets/${secretPath}`);
            return response.status === 200 || response.status === 204;
        }
        catch (error) {
            console.error('Failed to delete secret:', error.message);
            return false;
        }
    }
    async listSecrets(path) {
        try {
            const response = await this.client.get(`/secrets/${path}`, {
                params: { list: true },
            });
            return response.data.keys || response.data.data?.keys || [];
        }
        catch (error) {
            console.error('Failed to list secrets:', error.message);
            return [];
        }
    }
    async rotateSecret(secretPath) {
        try {
            const response = await this.client.post(`/secrets/${secretPath}/rotate`);
            return response.status === 200 || response.status === 201;
        }
        catch (error) {
            console.error('Failed to rotate secret:', error.message);
            return false;
        }
    }
}
exports.PAMIntegration = PAMIntegration;
class IdPIntegration {
    constructor(config) {
        this.config = config;
        this.client = axios_1.default.create({
            baseURL: config.endpoint,
            timeout: 30000,
        });
        this.setupAuthentication();
    }
    setupAuthentication() {
        const { authentication } = this.config;
        switch (authentication.type) {
            case 'basic':
                this.client.defaults.auth = {
                    username: authentication.credentials.username || '',
                    password: authentication.credentials.password || '',
                };
                break;
            case 'bearer':
                this.client.defaults.headers.common['Authorization'] =
                    `Bearer ${authentication.credentials.token}`;
                break;
            case 'api-key':
                const apiKeyHeader = authentication.credentials.headerName || 'X-API-Key';
                this.client.defaults.headers.common[apiKeyHeader] =
                    authentication.credentials.apiKey || '';
                break;
        }
    }
    async authenticateUser(username, password) {
        try {
            switch (this.config.type) {
                case 'ldap':
                case 'active-directory':
                    return await this.authenticateLDAP(username, password);
                case 'okta':
                case 'auth0':
                case 'azure-ad':
                case 'google-workspace':
                    return await this.authenticateOAuth2(username, password);
                default:
                    throw new Error(`Unsupported IdP type: ${this.config.type}`);
            }
        }
        catch (error) {
            return {
                success: false,
                error: error.message,
            };
        }
    }
    async getUser(userId) {
        try {
            const response = await this.client.get(`/users/${userId}`);
            return this.parseUser(response.data);
        }
        catch (error) {
            console.error('Failed to get user:', error.message);
            return null;
        }
    }
    async searchUsers(query) {
        try {
            const response = await this.client.get('/users', {
                params: { q: query },
            });
            return (response.data.users || response.data || []).map((u) => this.parseUser(u));
        }
        catch (error) {
            console.error('Failed to search users:', error.message);
            return [];
        }
    }
    async getUserGroups(userId) {
        try {
            const response = await this.client.get(`/users/${userId}/groups`);
            return response.data.groups || [];
        }
        catch (error) {
            console.error('Failed to get user groups:', error.message);
            return [];
        }
    }
    async authenticateLDAP(username, password) {
        try {
            const response = await this.client.post('/auth/ldap', {
                username,
                password,
            });
            if (response.data.success) {
                return {
                    success: true,
                    user: this.parseUser(response.data.user),
                };
            }
            return {
                success: false,
                error: response.data.error || 'Authentication failed',
            };
        }
        catch (error) {
            return {
                success: false,
                error: error.message,
            };
        }
    }
    async authenticateOAuth2(username, password) {
        try {
            const response = await this.client.post('/auth/oauth2', {
                grant_type: 'password',
                username,
                password,
                client_id: this.config.authentication.credentials.clientId,
                client_secret: this.config.authentication.credentials.clientSecret,
            });
            if (response.data.access_token) {
                const userInfoResponse = await this.client.get('/userinfo', {
                    headers: {
                        Authorization: `Bearer ${response.data.access_token}`,
                    },
                });
                return {
                    success: true,
                    user: this.parseUser(userInfoResponse.data),
                };
            }
            return {
                success: false,
                error: 'Failed to obtain access token',
            };
        }
        catch (error) {
            return {
                success: false,
                error: error.message,
            };
        }
    }
    parseUser(data) {
        return {
            id: data.id || data.sub || data.userId || '',
            email: data.email || data.mail || '',
            name: data.name || data.displayName || data.cn || '',
            roles: data.roles || [],
            groups: data.groups || data.memberOf || [],
            attributes: data,
        };
    }
}
exports.IdPIntegration = IdPIntegration;
class IAMIntegration {
    constructor() {
        this.sso = new Map();
        this.rbac = new Map();
        this.pam = new Map();
        this.idp = new Map();
    }
    registerSSO(id, config) {
        if (config.enabled) {
            this.sso.set(id, new SSOIntegration(config));
        }
    }
    registerRBAC(id, config) {
        if (config.enabled) {
            this.rbac.set(id, new RBACIntegration(config));
        }
    }
    registerPAM(id, config) {
        if (config.enabled) {
            this.pam.set(id, new PAMIntegration(config));
        }
    }
    registerIdP(id, config) {
        if (config.enabled) {
            this.idp.set(id, new IdPIntegration(config));
        }
    }
    getSSO(id) {
        return this.sso.get(id);
    }
    getRBAC(id) {
        return this.rbac.get(id);
    }
    getPAM(id) {
        return this.pam.get(id);
    }
    getIdP(id) {
        return this.idp.get(id);
    }
}
exports.IAMIntegration = IAMIntegration;
//# sourceMappingURL=iam-integration.js.map