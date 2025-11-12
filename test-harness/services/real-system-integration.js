"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RealSystemIntegration = void 0;
class RealSystemIntegration {
    async executeDatabaseQuery(connection, query) {
        const startTime = Date.now();
        try {
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
        }
        catch (error) {
            return {
                success: false,
                error: error.message,
                executionTime: Date.now() - startTime,
            };
        }
    }
    async executePostgreSQLQuery(connection, query) {
        const startTime = Date.now();
        try {
            let pg;
            try {
                pg = require('pg');
            }
            catch (e) {
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
                let queryPlan;
                if (query.sql?.toUpperCase().startsWith('EXPLAIN')) {
                    queryPlan = result.rows;
                }
                else {
                    try {
                        const explainResult = await client.query(`EXPLAIN (FORMAT JSON) ${query.sql}`);
                        queryPlan = explainResult.rows[0]?.['QUERY PLAN'];
                    }
                    catch {
                    }
                }
                return {
                    success: true,
                    rows: result.rows,
                    rowCount: result.rowCount,
                    executionTime: Date.now() - startTime,
                    queryPlan,
                };
            }
            finally {
                await client.end();
            }
        }
        catch (error) {
            return {
                success: false,
                error: error.message,
                executionTime: Date.now() - startTime,
            };
        }
    }
    async executePostgreSQLViaAPI(connection, query, startTime) {
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
        }
        catch (error) {
            return {
                success: false,
                error: error.message,
                executionTime: Date.now() - startTime,
            };
        }
    }
    async executeMySQLQuery(connection, query) {
        const startTime = Date.now();
        try {
            let mysql;
            try {
                mysql = require('mysql2/promise');
            }
            catch (e) {
                return {
                    success: false,
                    error: 'mysql2 library not installed. Install with: npm install mysql2',
                    executionTime: Date.now() - startTime,
                };
            }
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
                let queryPlan;
                if (query.sql?.toUpperCase().startsWith('EXPLAIN')) {
                    queryPlan = rows;
                }
                else {
                    try {
                        const [explainRows] = await conn.execute(`EXPLAIN ${query.sql}`);
                        queryPlan = explainRows;
                    }
                    catch {
                    }
                }
                return {
                    success: true,
                    rows: Array.isArray(rows) ? rows : [],
                    rowCount: Array.isArray(rows) ? rows.length : 0,
                    executionTime: Date.now() - startTime,
                    queryPlan,
                };
            }
            finally {
                await conn.end();
            }
        }
        catch (error) {
            return {
                success: false,
                error: error.message,
                executionTime: Date.now() - startTime,
            };
        }
    }
    async executeSQLiteQuery(connection, query) {
        const startTime = Date.now();
        try {
            let Database;
            try {
                Database = require('better-sqlite3');
            }
            catch (e) {
                return {
                    success: false,
                    error: 'better-sqlite3 library not installed. Install with: npm install better-sqlite3',
                    executionTime: Date.now() - startTime,
                };
            }
            const dbPath = connection.connectionString.replace(/^sqlite:\/\//, '').replace(/^sqlite3:\/\//, '');
            const db = new Database(dbPath, { readonly: true });
            try {
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
                const stmt = db.prepare(query.sql || '');
                const rows = stmt.all();
                let queryPlan;
                try {
                    const explainStmt = db.prepare(`EXPLAIN QUERY PLAN ${query.sql}`);
                    queryPlan = explainStmt.all();
                }
                catch {
                }
                return {
                    success: true,
                    rows,
                    rowCount: rows.length,
                    executionTime: Date.now() - startTime,
                    queryPlan,
                };
            }
            finally {
                db.close();
            }
        }
        catch (error) {
            return {
                success: false,
                error: error.message,
                executionTime: Date.now() - startTime,
            };
        }
    }
    async executeAPIRequest(connection, query, user) {
        const startTime = Date.now();
        try {
            const url = `${connection.baseUrl}${query.apiEndpoint}`;
            const headers = {
                ...connection.headers,
                'Content-Type': 'application/json',
            };
            if (connection.authentication) {
                headers['Authorization'] = this.getAuthHeader(connection.authentication, user);
            }
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
        }
        catch (error) {
            return {
                status: 500,
                headers: {},
                body: { error: error.message },
                executionTime: Date.now() - startTime,
            };
        }
    }
    getAuthHeader(auth, user) {
        if (!auth)
            return '';
        switch (auth.type) {
            case 'bearer':
                return `Bearer ${auth.credentials.token}`;
            case 'basic':
                const credentials = Buffer.from(`${auth.credentials.username}:${auth.credentials.password}`).toString('base64');
                return `Basic ${credentials}`;
            case 'api-key':
                return auth.credentials.apiKey || '';
            case 'oauth2':
                return `Bearer ${auth.credentials.accessToken}`;
            default:
                return '';
        }
    }
    async authenticateUser(idp, username, password) {
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
        }
        catch (error) {
            return {
                success: false,
                error: error.message,
            };
        }
    }
    async authenticateLDAP(idp, username, password) {
        try {
            let ldap;
            try {
                ldap = require('ldapjs');
            }
            catch (e) {
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
                const userDN = idp.credentials.userDNTemplate?.replace('{username}', username) ||
                    `cn=${username},${idp.credentials.baseDN || ''}`;
                client.bind(userDN, password, (err) => {
                    if (err) {
                        client.unbind();
                        resolve({
                            success: false,
                            error: `LDAP authentication failed: ${err.message}`,
                        });
                        return;
                    }
                    const searchOptions = {
                        filter: `(cn=${username})`,
                        scope: 'sub',
                        attributes: ['cn', 'mail', 'memberOf', 'department', 'title'],
                    };
                    client.search(idp.credentials.baseDN || '', searchOptions, (searchErr, res) => {
                        if (searchErr) {
                            client.unbind();
                            resolve({
                                success: false,
                                error: `LDAP search failed: ${searchErr.message}`,
                            });
                            return;
                        }
                        let userAttributes = {};
                        res.on('searchEntry', (entry) => {
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
                            const user = {
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
                        res.on('error', (searchErr) => {
                            client.unbind();
                            resolve({
                                success: false,
                                error: `LDAP search error: ${searchErr.message}`,
                            });
                        });
                    });
                });
            });
        }
        catch (error) {
            return {
                success: false,
                error: error.message,
            };
        }
    }
    mapLDAPGroupsToRole(groups) {
        const groupMap = {
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
        return 'viewer';
    }
    async authenticateOAuth2(idp, username, password) {
        try {
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
            const userInfoEndpoint = idp.options?.userInfoEndpoint ||
                idp.endpoint.replace('/token', '/userinfo');
            const userInfoResponse = await fetch(userInfoEndpoint, {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    ...idp.options?.headers,
                },
            });
            let userAttributes = {
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
            const user = {
                id: userAttributes.sub || username,
                email: userAttributes.email,
                role: this.mapOAuth2RolesToRole(userAttributes.roles || []),
                attributes: userAttributes,
            };
            return {
                success: true,
                user,
            };
        }
        catch (error) {
            return {
                success: false,
                error: error.message,
            };
        }
    }
    mapOAuth2RolesToRole(roles) {
        const roleMap = {
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
        return 'viewer';
    }
    async authenticateSAML(idp, username, password) {
        try {
            let saml;
            try {
                saml = require('saml2-js');
            }
            catch (e) {
                return await this.authenticateSAMLViaHTTP(idp, username, password);
            }
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
            return await this.authenticateSAMLViaHTTP(idp, username, password);
        }
        catch (error) {
            return {
                success: false,
                error: error.message,
            };
        }
    }
    async authenticateSAMLViaHTTP(idp, username, password) {
        try {
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
            const contentType = response.headers.get('content-type') || '';
            let assertionData;
            if (contentType.includes('application/json')) {
                assertionData = await response.json();
            }
            else {
                const xmlText = await response.text();
                assertionData = this.parseSAMLAssertion(xmlText);
            }
            const userAttributes = {
                email: assertionData.email || assertionData['urn:oid:0.9.2342.19200300.100.1.3'] || username,
                name: assertionData.name || assertionData['urn:oid:2.5.4.3'] || username,
                roles: assertionData.roles || assertionData['urn:oid:1.3.6.1.4.1.5923.1.1.1.1'] || [],
                ...assertionData,
            };
            const user = {
                id: assertionData.nameID || assertionData.sub || username,
                email: userAttributes.email,
                role: this.mapSAMLAttributesToRole(userAttributes),
                attributes: userAttributes,
            };
            return {
                success: true,
                user,
            };
        }
        catch (error) {
            return {
                success: false,
                error: `SAML authentication error: ${error.message}`,
            };
        }
    }
    parseSAMLAssertion(xmlText) {
        const attributes = {};
        const nameIdMatch = xmlText.match(/<saml:NameID[^>]*>([^<]+)<\/saml:NameID>/);
        if (nameIdMatch) {
            attributes.nameID = nameIdMatch[1];
        }
        const attributeMatches = xmlText.matchAll(/<saml:AttributeValue[^>]*>([^<]+)<\/saml:AttributeValue>/g);
        for (const match of attributeMatches) {
            const value = match[1];
            if (value.includes('@')) {
                attributes.email = value;
            }
            else if (!attributes.name) {
                attributes.name = value;
            }
        }
        return attributes;
    }
    mapSAMLAttributesToRole(attributes) {
        const roles = attributes.roles || attributes.groups || [];
        return this.mapOAuth2RolesToRole(Array.isArray(roles) ? roles : [roles]);
    }
    async getUserAttributes(idp, userId) {
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
        }
        catch (error) {
            return { error: error.message };
        }
    }
    async getLDAPAttributes(idp, userId) {
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
                    attributes: ['*'],
                };
                client.search(idp.credentials.baseDN || '', searchOptions, (err, res) => {
                    if (err) {
                        client.unbind();
                        resolve({});
                        return;
                    }
                    let attributes = {};
                    res.on('searchEntry', (entry) => {
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
        }
        catch {
            return {};
        }
    }
    async getOAuth2Attributes(idp, userId) {
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
        }
        catch {
        }
        return {};
    }
    async getSAMLAttributes(idp, userId) {
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
                }
                else {
                    const xmlText = await response.text();
                    return this.parseSAMLAssertion(xmlText);
                }
            }
        }
        catch {
        }
        return {};
    }
    validateAPIResponse(response, expectedFields, piiFields) {
        const violations = [];
        if (response.status >= 400) {
            violations.push(`API returned error status: ${response.status}`);
        }
        if (piiFields && response.body) {
            const foundPII = this.detectPIIInResponse(response.body, piiFields);
            if (foundPII.length > 0) {
                violations.push(`PII fields found in response: ${foundPII.join(', ')}`);
            }
        }
        if (expectedFields && response.body) {
            const unexpectedFields = this.findUnexpectedFields(response.body, expectedFields);
            if (unexpectedFields.length > 0) {
                violations.push(`Unexpected fields in response: ${unexpectedFields.join(', ')}`);
            }
        }
        return {
            compliant: violations.length === 0,
            violations,
        };
    }
    detectPIIInResponse(body, piiFields) {
        const found = [];
        const checkObject = (obj, path = '') => {
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
                }
                else if (Array.isArray(value)) {
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
    findUnexpectedFields(body, expectedFields) {
        const unexpected = [];
        const expectedSet = new Set(expectedFields);
        const checkObject = (obj, path = '') => {
            for (const key in obj) {
                const currentPath = path ? `${path}.${key}` : key;
                if (!expectedSet.has('*') && !expectedSet.has(currentPath)) {
                    const isExpected = Array.from(expectedSet).some(expected => currentPath.startsWith(expected + '.') || expected.startsWith(currentPath + '.'));
                    if (!isExpected) {
                        unexpected.push(currentPath);
                    }
                }
                const value = obj[key];
                if (value && typeof value === 'object' && !Array.isArray(value)) {
                    checkObject(value, currentPath);
                }
                else if (Array.isArray(value)) {
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
exports.RealSystemIntegration = RealSystemIntegration;
//# sourceMappingURL=real-system-integration.js.map