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

