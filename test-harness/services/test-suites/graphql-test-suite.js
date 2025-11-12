"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GraphQLTestSuite = void 0;
const base_test_suite_1 = require("./base-test-suite");
class GraphQLTestSuite extends base_test_suite_1.BaseTestSuite {
    async runAllTests(endpoint, method, test) {
        const results = [];
        results.push(await this.testGraphQLIntrospection(endpoint, method, test));
        results.push(await this.testGraphQLQueryDepth(endpoint, method, test));
        results.push(await this.testGraphQLFieldAuthorization(endpoint, method, test));
        results.push(await this.testGraphQLBatchQueries(endpoint, method, test));
        results.push(await this.testGraphQLQueryCost(endpoint, method, test));
        results.push(await this.testGraphQLMutationAuthorization(endpoint, method, test));
        results.push(await this.testGraphQLQueryComplexity(endpoint, method, test));
        return results;
    }
    async testGraphQLIntrospection(endpoint, method, test) {
        const result = this.createBaseResult('GraphQL Introspection Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            headers['Content-Type'] = 'application/json';
            const introspectionQuery = {
                query: '{ __schema { types { name } } }',
            };
            const response = await this.makeRequest(url, method, headers, introspectionQuery);
            const body = await response.json().catch(() => ({}));
            result.statusCode = response.status;
            result.responseTime = Date.now() - startTime;
            result.passed = !body.data?.__schema;
            result.securityIssues = body.data?.__schema ? ['GraphQL introspection is enabled'] : undefined;
            result.details = {
                introspectionEnabled: !!body.data?.__schema,
            };
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testGraphQLQueryDepth(endpoint, method, test) {
        const result = this.createBaseResult('GraphQL Query Depth Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            headers['Content-Type'] = 'application/json';
            let deepQuery = 'query { user {';
            for (let i = 0; i < 20; i++) {
                deepQuery += ' friends {';
            }
            for (let i = 0; i < 20; i++) {
                deepQuery += ' }';
            }
            deepQuery += ' } }';
            const query = { query: deepQuery };
            const response = await this.makeRequest(url, method, headers, query);
            const body = await response.json().catch(() => ({}));
            result.statusCode = response.status;
            result.responseTime = Date.now() - startTime;
            result.passed = !!body.errors || response.status !== 200;
            result.securityIssues = !body.errors && response.status === 200 ? ['GraphQL query depth limit not enforced'] : undefined;
            result.details = {
                depth: 20,
                errors: body.errors,
            };
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testGraphQLFieldAuthorization(endpoint, method, test) {
        const result = this.createBaseResult('GraphQL Field Authorization Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            headers['Content-Type'] = 'application/json';
            const sensitiveFields = ['password', 'creditCard', 'ssn', 'apiKey', 'secret'];
            const securityIssues = [];
            for (const field of sensitiveFields) {
                const query = {
                    query: `{ user { ${field} } }`,
                };
                const response = await this.makeRequest(url, method, headers, query);
                const body = await response.json().catch(() => ({}));
                if (body.data?.user?.[field]) {
                    securityIssues.push(`Sensitive field ${field} accessible without authorization`);
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                fieldsTested: sensitiveFields.length,
                issuesFound: securityIssues.length,
            };
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testGraphQLBatchQueries(endpoint, method, test) {
        const result = this.createBaseResult('GraphQL Batch Queries Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            headers['Content-Type'] = 'application/json';
            const batchQuery = {
                query: '{ users { id posts { id comments { id } } } }',
            };
            const response = await this.makeRequest(url, method, headers, batchQuery);
            const body = await response.json().catch(() => ({}));
            result.statusCode = response.status;
            result.responseTime = Date.now() - startTime;
            const hasData = !!body.data;
            result.passed = !hasData || response.status !== 200;
            result.securityIssues = hasData && response.status === 200 ? ['GraphQL batch queries may cause N+1 problem'] : undefined;
            result.details = {
                batchQueryExecuted: hasData,
            };
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testGraphQLQueryCost(endpoint, method, test) {
        const result = this.createBaseResult('GraphQL Query Cost Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            headers['Content-Type'] = 'application/json';
            const expensiveQuery = {
                query: '{ users { id name email posts { id title comments { id text } } } }',
            };
            const response = await this.makeRequest(url, method, headers, expensiveQuery);
            const body = await response.json().catch(() => ({}));
            result.statusCode = response.status;
            result.responseTime = Date.now() - startTime;
            result.passed = !!body.errors || response.status !== 200;
            result.securityIssues = !body.errors && response.status === 200 ? ['GraphQL query cost limit not enforced'] : undefined;
            result.details = {
                queryExecuted: !!body.data,
                errors: body.errors,
            };
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testGraphQLMutationAuthorization(endpoint, method, test) {
        const result = this.createBaseResult('GraphQL Mutation Authorization Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            headers['Content-Type'] = 'application/json';
            const mutation = {
                query: 'mutation { deleteUser(id: "1") { id } }',
            };
            const response = await this.makeRequest(url, method, headers, mutation);
            const body = await response.json().catch(() => ({}));
            result.statusCode = response.status;
            result.responseTime = Date.now() - startTime;
            result.passed = !!body.errors || response.status === 403;
            result.securityIssues = !body.errors && response.status === 200 ? ['GraphQL mutation authorization not enforced'] : undefined;
            result.details = {
                mutationExecuted: !!body.data,
                errors: body.errors,
            };
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
    async testGraphQLQueryComplexity(endpoint, method, test) {
        const result = this.createBaseResult('GraphQL Query Complexity Test', endpoint, method);
        const startTime = Date.now();
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            headers['Content-Type'] = 'application/json';
            const complexQuery = {
                query: '{ users { id name email posts { id title comments { id text author { id name } } } } }',
            };
            const response = await this.makeRequest(url, method, headers, complexQuery);
            const body = await response.json().catch(() => ({}));
            result.statusCode = response.status;
            result.responseTime = Date.now() - startTime;
            const complexity = (complexQuery.query.match(/\{/g) || []).length;
            result.passed = !!body.errors || response.status !== 200;
            result.securityIssues = !body.errors && response.status === 200 && complexity > 10 ? ['GraphQL query complexity limit not enforced'] : undefined;
            result.details = {
                complexity,
                queryExecuted: !!body.data,
            };
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            result.details = { error: error.message };
        }
        return result;
    }
}
exports.GraphQLTestSuite = GraphQLTestSuite;
//# sourceMappingURL=graphql-test-suite.js.map