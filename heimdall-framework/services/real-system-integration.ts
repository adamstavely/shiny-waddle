/**
 * Real System Integration Service
 * 
 * Integrates with actual databases, APIs, and identity providers
 */

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

export class RealSystemIntegration {
  /**
   * Execute query against real database
   */
  async executeDatabaseQuery(
    connection: DatabaseConnection,
    query: TestQuery
  ): Promise<QueryExecutionResult> {
    const startTime = Date.now();

    try {
      // This would use actual database drivers
      // For now, return a placeholder structure
      
      switch (connection.type) {
        case 'postgresql':
          return await this.executePostgreSQLQuery(connection, query);
        case 'mysql':
          return await this.executeMySQLQuery(connection, query);
        case 'sqlite':
          return await this.executeSQLiteQuery(connection, query);
        default:
          throw new Error(`Unsupported database type: ${connection.type}`);
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
        executionTime: Date.now() - startTime,
      };
    }
  }

  /**
   * Execute PostgreSQL query
   */
  private async executePostgreSQLQuery(
    connection: DatabaseConnection,
    query: TestQuery
  ): Promise<QueryExecutionResult> {
    const startTime = Date.now();
    
    try {
      // Try to use pg library if available
      let pg: any;
      try {
        pg = require('pg');
      } catch (e) {
        // Fallback to fetch-based approach for testing
        return await this.executePostgreSQLViaAPI(connection, query, startTime);
      }

      const { Client } = pg;
      const client = new Client({
        connectionString: connection.connectionString,
        ...connection.options,
      });

      await client.connect();
      
      try {
        const result = await client.query(query.sql || '');
        
        // Get query plan if EXPLAIN is used
        let queryPlan;
        if (query.sql?.toUpperCase().startsWith('EXPLAIN')) {
          queryPlan = result.rows;
        } else {
          // Get actual query plan
          try {
            const explainResult = await client.query(`EXPLAIN (FORMAT JSON) ${query.sql}`);
            queryPlan = explainResult.rows[0]?.['QUERY PLAN'];
          } catch {
            // Ignore if EXPLAIN fails
          }
        }

        return {
          success: true,
          rows: result.rows,
          rowCount: result.rowCount,
          executionTime: Date.now() - startTime,
          queryPlan,
        };
      } finally {
        await client.end();
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
        executionTime: Date.now() - startTime,
      };
    }
  }

  /**
   * Execute PostgreSQL via API (fallback)
   */
  private async executePostgreSQLViaAPI(
    connection: DatabaseConnection,
    query: TestQuery,
    startTime: number
  ): Promise<QueryExecutionResult> {
    // Fallback: Use HTTP API if pg library not available
    // This assumes a PostgreSQL HTTP API endpoint
    try {
      const apiUrl = connection.connectionString.replace(/^postgresql:\/\//, 'http://');
      const response = await fetch(`${apiUrl}/query`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: query.sql }),
      });

      if (!response.ok) {
        throw new Error(`API request failed: ${response.statusText}`);
      }

      const data = await response.json();
      return {
        success: true,
        rows: data.rows || [],
        rowCount: data.rowCount || 0,
        executionTime: Date.now() - startTime,
        queryPlan: data.queryPlan,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
        executionTime: Date.now() - startTime,
      };
    }
  }

  /**
   * Execute MySQL query
   */
  private async executeMySQLQuery(
    connection: DatabaseConnection,
    query: TestQuery
  ): Promise<QueryExecutionResult> {
    const startTime = Date.now();
    
    try {
      // Try to use mysql2 library if available
      let mysql: any;
      try {
        mysql = require('mysql2/promise');
      } catch (e) {
        return {
          success: false,
          error: 'mysql2 library not installed. Install with: npm install mysql2',
          executionTime: Date.now() - startTime,
        };
      }

      // Parse connection string
      const url = new URL(connection.connectionString.replace(/^mysql:\/\//, 'http://'));
      const dbConfig = {
        host: url.hostname,
        port: parseInt(url.port) || 3306,
        user: url.username,
        password: url.password,
        database: url.pathname.slice(1),
        ...connection.options,
      };

      const conn = await mysql.createConnection(dbConfig);
      
      try {
        const [rows, fields] = await conn.execute(query.sql || '');
        
        // Get query plan if EXPLAIN is used
        let queryPlan;
        if (query.sql?.toUpperCase().startsWith('EXPLAIN')) {
          queryPlan = rows;
        } else {
          try {
            const [explainRows] = await conn.execute(`EXPLAIN ${query.sql}`);
            queryPlan = explainRows;
          } catch {
            // Ignore if EXPLAIN fails
          }
        }

        return {
          success: true,
          rows: Array.isArray(rows) ? rows : [],
          rowCount: Array.isArray(rows) ? rows.length : 0,
          executionTime: Date.now() - startTime,
          queryPlan,
        };
      } finally {
        await conn.end();
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
        executionTime: Date.now() - startTime,
      };
    }
  }

  /**
   * Execute SQLite query
   */
  private async executeSQLiteQuery(
    connection: DatabaseConnection,
    query: TestQuery
  ): Promise<QueryExecutionResult> {
    const startTime = Date.now();
    
    try {
      // Try to use better-sqlite3 library if available
      let Database: any;
      try {
        Database = require('better-sqlite3');
      } catch (e) {
        return {
          success: false,
          error: 'better-sqlite3 library not installed. Install with: npm install better-sqlite3',
          executionTime: Date.now() - startTime,
        };
      }

      // Extract database path from connection string
      const dbPath = connection.connectionString.replace(/^sqlite:\/\//, '').replace(/^sqlite3:\/\//, '');
      const db = new Database(dbPath, { readonly: true });
      
      try {
        // Check if it's an EXPLAIN query
        if (query.sql?.toUpperCase().startsWith('EXPLAIN')) {
          const stmt = db.prepare(query.sql);
          const rows = stmt.all();
          return {
            success: true,
            rows,
            rowCount: rows.length,
            executionTime: Date.now() - startTime,
            queryPlan: rows,
          };
        }

        // Regular query
        const stmt = db.prepare(query.sql || '');
        const rows = stmt.all();

        // Get query plan
        let queryPlan;
        try {
          const explainStmt = db.prepare(`EXPLAIN QUERY PLAN ${query.sql}`);
          queryPlan = explainStmt.all();
        } catch {
          // Ignore if EXPLAIN fails
        }

        return {
          success: true,
          rows,
          rowCount: rows.length,
          executionTime: Date.now() - startTime,
          queryPlan,
        };
      } finally {
        db.close();
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
        executionTime: Date.now() - startTime,
      };
    }
  }

  /**
   * Execute API request
   */
  async executeAPIRequest(
    connection: APIConnection,
    query: TestQuery,
    user?: User
  ): Promise<APIResponse> {
    const startTime = Date.now();

    try {
      const url = `${connection.baseUrl}${query.apiEndpoint}`;
      const headers: Record<string, string> = {
        ...connection.headers,
        'Content-Type': 'application/json',
      };

      // Add authentication
      if (connection.authentication) {
        headers['Authorization'] = this.getAuthHeader(
          connection.authentication,
          user
        );
      }

      // Make request
      const response = await fetch(url, {
        method: query.httpMethod || 'GET',
        headers,
        body: query.requestBody ? JSON.stringify(query.requestBody) : undefined,
      });

      const body = await response.json();

      return {
        status: response.status,
        headers: Object.fromEntries(response.headers.entries()),
        body,
        executionTime: Date.now() - startTime,
      };
    } catch (error: any) {
      return {
        status: 500,
        headers: {},
        body: { error: error.message },
        executionTime: Date.now() - startTime,
      };
    }
  }

  /**
   * Get authentication header
   */
  private getAuthHeader(
    auth: APIConnection['authentication'],
    user?: User
  ): string {
    if (!auth) return '';

    switch (auth.type) {
      case 'bearer':
        return `Bearer ${auth.credentials.token}`;
      case 'basic':
        const credentials = Buffer.from(
          `${auth.credentials.username}:${auth.credentials.password}`
        ).toString('base64');
        return `Basic ${credentials}`;
      case 'api-key':
        return auth.credentials.apiKey || '';
      case 'oauth2':
        return `Bearer ${auth.credentials.accessToken}`;
      default:
        return '';
    }
  }

  /**
   * Authenticate user with identity provider
   */
  async authenticateUser(
    idp: IdentityProviderConnection,
    username: string,
    password: string
  ): Promise<{ success: boolean; user?: User; error?: string }> {
    try {
      switch (idp.type) {
        case 'ldap':
          return await this.authenticateLDAP(idp, username, password);
        case 'oauth2':
          return await this.authenticateOAuth2(idp, username, password);
        case 'saml':
          return await this.authenticateSAML(idp, username, password);
        default:
          throw new Error(`Unsupported identity provider: ${idp.type}`);
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Authenticate with LDAP
   */
  private async authenticateLDAP(
    idp: IdentityProviderConnection,
    username: string,
    password: string
  ): Promise<{ success: boolean; user?: User; error?: string }> {
    try {
      // Try to use ldapjs library if available
      let ldap: any;
      try {
        ldap = require('ldapjs');
      } catch (e) {
        return {
          success: false,
          error: 'ldapjs library not installed. Install with: npm install ldapjs',
        };
      }

      const client = ldap.createClient({
        url: idp.endpoint,
        ...idp.options,
      });

      return new Promise((resolve) => {
        // Bind (authenticate) with user credentials
        const userDN = idp.credentials.userDNTemplate?.replace('{username}', username) || 
                       `cn=${username},${idp.credentials.baseDN || ''}`;

        client.bind(userDN, password, (err: any) => {
          if (err) {
            client.unbind();
            resolve({
              success: false,
              error: `LDAP authentication failed: ${err.message}`,
            });
            return;
          }

          // Search for user attributes
          const searchOptions = {
            filter: `(cn=${username})`,
            scope: 'sub',
            attributes: ['cn', 'mail', 'memberOf', 'department', 'title'],
          };

          client.search(idp.credentials.baseDN || '', searchOptions, (searchErr: any, res: any) => {
            if (searchErr) {
              client.unbind();
              resolve({
                success: false,
                error: `LDAP search failed: ${searchErr.message}`,
              });
              return;
            }

            let userAttributes: Record<string, any> = {};

            res.on('searchEntry', (entry: any) => {
              userAttributes = {
                email: entry.object.mail || entry.object.mail || `${username}@example.com`,
                name: entry.object.cn || username,
                department: entry.object.department || '',
                groups: entry.object.memberOf || [],
                title: entry.object.title || '',
              };
            });

            res.on('end', () => {
              client.unbind();
              
              if (Object.keys(userAttributes).length === 0) {
                resolve({
                  success: false,
                  error: 'User not found in LDAP directory',
                });
                return;
              }

              // Map to User object
              const user: User = {
                id: username,
                email: userAttributes.email,
                role: this.mapLDAPGroupsToRole(userAttributes.groups),
                attributes: userAttributes,
              };

              resolve({
                success: true,
                user,
              });
            });

            res.on('error', (searchErr: any) => {
              client.unbind();
              resolve({
                success: false,
                error: `LDAP search error: ${searchErr.message}`,
              });
            });
          });
        });
      });
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Map LDAP groups to user role
   */
  private mapLDAPGroupsToRole(groups: string[]): User['role'] {
    const groupMap: Record<string, User['role']> = {
      'admin': 'admin',
      'administrators': 'admin',
      'researchers': 'researcher',
      'analysts': 'analyst',
      'viewers': 'viewer',
    };

    for (const group of groups) {
      const lowerGroup = group.toLowerCase();
      for (const [key, role] of Object.entries(groupMap)) {
        if (lowerGroup.includes(key)) {
          return role;
        }
      }
    }

    return 'viewer'; // Default role
  }

  /**
   * Authenticate with OAuth2
   */
  private async authenticateOAuth2(
    idp: IdentityProviderConnection,
    username: string,
    password: string
  ): Promise<{ success: boolean; user?: User; error?: string }> {
    try {
      // OAuth2 Resource Owner Password Credentials flow
      const tokenEndpoint = idp.endpoint.endsWith('/token') 
        ? idp.endpoint 
        : `${idp.endpoint}/token`;

      const params = new URLSearchParams({
        grant_type: 'password',
        username,
        password,
        client_id: idp.credentials.clientId || '',
        client_secret: idp.credentials.clientSecret || '',
        ...idp.options?.additionalParams,
      });

      const response = await fetch(tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          ...idp.options?.headers,
        },
        body: params.toString(),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        return {
          success: false,
          error: `OAuth2 authentication failed: ${response.statusText} - ${errorData.error_description || errorData.error || 'Unknown error'}`,
        };
      }

      const tokenData = await response.json();
      const accessToken = tokenData.access_token;

      if (!accessToken) {
        return {
          success: false,
          error: 'OAuth2 token response missing access_token',
        };
      }

      // Get user info from userinfo endpoint
      const userInfoEndpoint = idp.options?.userInfoEndpoint || 
                               idp.endpoint.replace('/token', '/userinfo');
      
      const userInfoResponse = await fetch(userInfoEndpoint, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          ...idp.options?.headers,
        },
      });

      let userAttributes: Record<string, any> = {
        email: username,
        name: username,
      };

      if (userInfoResponse.ok) {
        const userInfo = await userInfoResponse.json();
        userAttributes = {
          email: userInfo.email || userInfo.preferred_username || username,
          name: userInfo.name || userInfo.preferred_username || username,
          sub: userInfo.sub || username,
          roles: userInfo.roles || userInfo.groups || [],
          ...userInfo,
        };
      }

      // Map to User object
      const user: User = {
        id: userAttributes.sub || username,
        email: userAttributes.email,
        role: this.mapOAuth2RolesToRole(userAttributes.roles || []),
        attributes: userAttributes,
      };

      return {
        success: true,
        user,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Map OAuth2 roles to user role
   */
  private mapOAuth2RolesToRole(roles: string[]): User['role'] {
    const roleMap: Record<string, User['role']> = {
      'admin': 'admin',
      'administrator': 'admin',
      'researcher': 'researcher',
      'analyst': 'analyst',
      'viewer': 'viewer',
      'user': 'viewer',
    };

    for (const role of roles) {
      const lowerRole = role.toLowerCase();
      if (roleMap[lowerRole]) {
        return roleMap[lowerRole];
      }
    }

    return 'viewer'; // Default role
  }

  /**
   * Authenticate with SAML
   */
  private async authenticateSAML(
    idp: IdentityProviderConnection,
    username: string,
    password: string
  ): Promise<{ success: boolean; user?: User; error?: string }> {
    try {
      // SAML authentication typically requires a browser-based flow
      // For programmatic access, we'll use SAML assertion or token endpoint
      
      // Try to use saml2-js or passport-saml if available
      let saml: any;
      try {
        saml = require('saml2-js');
      } catch (e) {
        // Fallback: Use HTTP-based SAML assertion endpoint
        return await this.authenticateSAMLViaHTTP(idp, username, password);
      }

      // SAML2.0 authentication flow
      const spOptions = {
        entity_id: idp.credentials.entityId || idp.endpoint,
        private_key: idp.credentials.privateKey,
        certificate: idp.credentials.certificate,
        assert_endpoint: idp.endpoint,
        ...idp.options,
      };

      const idpOptions = {
        sso_login_url: idp.endpoint,
        sso_logout_url: idp.endpoint.replace('/sso', '/slo'),
        certificates: [idp.credentials.certificate],
        ...idp.options?.idpOptions,
      };

      const sp = new saml.ServiceProvider(spOptions);
      const idpEntity = new saml.IdentityProvider(idpOptions);

      // For programmatic access, we need to get a SAML assertion
      // This is typically done via a browser redirect, but we can simulate
      // by calling an assertion endpoint if available
      return await this.authenticateSAMLViaHTTP(idp, username, password);
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Authenticate SAML via HTTP assertion endpoint
   */
  private async authenticateSAMLViaHTTP(
    idp: IdentityProviderConnection,
    username: string,
    password: string
  ): Promise<{ success: boolean; user?: User; error?: string }> {
    try {
      // Some SAML providers support HTTP-based authentication
      const assertionEndpoint = idp.options?.assertionEndpoint || 
                                `${idp.endpoint}/assertion`;

      const response = await fetch(assertionEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          ...idp.options?.headers,
        },
        body: new URLSearchParams({
          username,
          password,
          ...idp.options?.additionalParams,
        }).toString(),
      });

      if (!response.ok) {
        return {
          success: false,
          error: `SAML authentication failed: ${response.statusText}`,
        };
      }

      // Parse SAML assertion or token response
      const contentType = response.headers.get('content-type') || '';
      let assertionData: any;

      if (contentType.includes('application/json')) {
        assertionData = await response.json();
      } else {
        // Parse XML SAML assertion
        const xmlText = await response.text();
        assertionData = this.parseSAMLAssertion(xmlText);
      }

      // Extract user attributes from SAML assertion
      const userAttributes: Record<string, any> = {
        email: assertionData.email || assertionData['urn:oid:0.9.2342.19200300.100.1.3'] || username,
        name: assertionData.name || assertionData['urn:oid:2.5.4.3'] || username,
        roles: assertionData.roles || assertionData['urn:oid:1.3.6.1.4.1.5923.1.1.1.1'] || [],
        ...assertionData,
      };

      const user: User = {
        id: assertionData.nameID || assertionData.sub || username,
        email: userAttributes.email,
        role: this.mapSAMLAttributesToRole(userAttributes),
        attributes: userAttributes,
      };

      return {
        success: true,
        user,
      };
    } catch (error: any) {
      return {
        success: false,
        error: `SAML authentication error: ${error.message}`,
      };
    }
  }

  /**
   * Parse SAML assertion XML
   */
  private parseSAMLAssertion(xmlText: string): Record<string, any> {
    // Simplified XML parsing - in production, use a proper XML parser
    const attributes: Record<string, any> = {};
    
    // Extract NameID
    const nameIdMatch = xmlText.match(/<saml:NameID[^>]*>([^<]+)<\/saml:NameID>/);
    if (nameIdMatch) {
      attributes.nameID = nameIdMatch[1];
    }

    // Extract AttributeValue elements
    const attributeMatches = xmlText.matchAll(/<saml:AttributeValue[^>]*>([^<]+)<\/saml:AttributeValue>/g);
    for (const match of attributeMatches) {
      const value = match[1];
      // Try to identify attribute type from context
      if (value.includes('@')) {
        attributes.email = value;
      } else if (!attributes.name) {
        attributes.name = value;
      }
    }

    return attributes;
  }

  /**
   * Map SAML attributes to user role
   */
  private mapSAMLAttributesToRole(attributes: Record<string, any>): User['role'] {
    const roles = attributes.roles || attributes.groups || [];
    return this.mapOAuth2RolesToRole(Array.isArray(roles) ? roles : [roles]);
  }

  /**
   * Get user attributes from identity provider
   */
  async getUserAttributes(
    idp: IdentityProviderConnection,
    userId: string
  ): Promise<Record<string, any>> {
    try {
      switch (idp.type) {
        case 'ldap':
          return await this.getLDAPAttributes(idp, userId);
        case 'oauth2':
          return await this.getOAuth2Attributes(idp, userId);
        case 'saml':
          return await this.getSAMLAttributes(idp, userId);
        default:
          return {};
      }
    } catch (error: any) {
      return { error: error.message };
    }
  }

  /**
   * Get attributes from LDAP
   */
  private async getLDAPAttributes(
    idp: IdentityProviderConnection,
    userId: string
  ): Promise<Record<string, any>> {
    try {
      const ldap = require('ldapjs');
      const client = ldap.createClient({
        url: idp.endpoint,
        ...idp.options,
      });

      return new Promise((resolve) => {
        const searchOptions = {
          filter: `(cn=${userId})`,
          scope: 'sub',
          attributes: ['*'], // Get all attributes
        };

        client.search(idp.credentials.baseDN || '', searchOptions, (err: any, res: any) => {
          if (err) {
            client.unbind();
            resolve({});
            return;
          }

          let attributes: Record<string, any> = {};

          res.on('searchEntry', (entry: any) => {
            attributes = entry.object;
          });

          res.on('end', () => {
            client.unbind();
            resolve(attributes);
          });

          res.on('error', () => {
            client.unbind();
            resolve({});
          });
        });
      });
    } catch {
      return {};
    }
  }

  /**
   * Get attributes from OAuth2 provider
   */
  private async getOAuth2Attributes(
    idp: IdentityProviderConnection,
    userId: string
  ): Promise<Record<string, any>> {
    try {
      const userInfoEndpoint = idp.options?.userInfoEndpoint || 
                               idp.endpoint.replace('/token', '/userinfo');
      
      const response = await fetch(`${userInfoEndpoint}/${userId}`, {
        headers: {
          'Authorization': `Bearer ${idp.credentials.accessToken || ''}`,
          ...idp.options?.headers,
        },
      });

      if (response.ok) {
        return await response.json();
      }
    } catch {
      // Ignore errors
    }
    return {};
  }

  /**
   * Get attributes from SAML provider
   */
  private async getSAMLAttributes(
    idp: IdentityProviderConnection,
    userId: string
  ): Promise<Record<string, any>> {
    try {
      const attributesEndpoint = idp.options?.attributesEndpoint || 
                                  `${idp.endpoint}/attributes`;
      
      const response = await fetch(`${attributesEndpoint}?userId=${userId}`, {
        headers: {
          ...idp.options?.headers,
        },
      });

      if (response.ok) {
        const contentType = response.headers.get('content-type') || '';
        if (contentType.includes('application/json')) {
          return await response.json();
        } else {
          const xmlText = await response.text();
          return this.parseSAMLAssertion(xmlText);
        }
      }
    } catch {
      // Ignore errors
    }
    return {};
  }

  /**
   * Validate API response for compliance
   */
  validateAPIResponse(
    response: APIResponse,
    expectedFields?: string[],
    piiFields?: string[]
  ): {
    compliant: boolean;
    violations: string[];
  } {
    const violations: string[] = [];

    // Check status code
    if (response.status >= 400) {
      violations.push(`API returned error status: ${response.status}`);
    }

    // Check for PII in response
    if (piiFields && response.body) {
      const foundPII = this.detectPIIInResponse(response.body, piiFields);
      if (foundPII.length > 0) {
        violations.push(`PII fields found in response: ${foundPII.join(', ')}`);
      }
    }

    // Check for unexpected fields
    if (expectedFields && response.body) {
      const unexpectedFields = this.findUnexpectedFields(
        response.body,
        expectedFields
      );
      if (unexpectedFields.length > 0) {
        violations.push(
          `Unexpected fields in response: ${unexpectedFields.join(', ')}`
        );
      }
    }

    return {
      compliant: violations.length === 0,
      violations,
    };
  }

  /**
   * Detect PII in API response
   */
  private detectPIIInResponse(
    body: any,
    piiFields: string[]
  ): string[] {
    const found: string[] = [];

    const checkObject = (obj: any, path: string = ''): void => {
      for (const key in obj) {
        const currentPath = path ? `${path}.${key}` : key;
        const value = obj[key];

        if (piiFields.some(field => currentPath.includes(field))) {
          if (value && typeof value === 'string' && value.length > 0) {
            found.push(currentPath);
          }
        }

        if (value && typeof value === 'object' && !Array.isArray(value)) {
          checkObject(value, currentPath);
        } else if (Array.isArray(value)) {
          value.forEach((item, index) => {
            if (item && typeof item === 'object') {
              checkObject(item, `${currentPath}[${index}]`);
            }
          });
        }
      }
    };

    if (body && typeof body === 'object') {
      checkObject(body);
    }

    return found;
  }

  /**
   * Find unexpected fields in response
   */
  private findUnexpectedFields(
    body: any,
    expectedFields: string[]
  ): string[] {
    const unexpected: string[] = [];
    const expectedSet = new Set(expectedFields);

    const checkObject = (obj: any, path: string = ''): void => {
      for (const key in obj) {
        const currentPath = path ? `${path}.${key}` : key;

        if (!expectedSet.has('*') && !expectedSet.has(currentPath)) {
          // Check if any expected field is a prefix
          const isExpected = Array.from(expectedSet).some(expected =>
            currentPath.startsWith(expected + '.') || expected.startsWith(currentPath + '.')
          );

          if (!isExpected) {
            unexpected.push(currentPath);
          }
        }

        const value = obj[key];
        if (value && typeof value === 'object' && !Array.isArray(value)) {
          checkObject(value, currentPath);
        } else if (Array.isArray(value)) {
          value.forEach((item, index) => {
            if (item && typeof item === 'object') {
              checkObject(item, `${currentPath}[${index}]`);
            }
          });
        }
      }
    };

    if (body && typeof body === 'object') {
      checkObject(body);
    }

    return unexpected;
  }
}

