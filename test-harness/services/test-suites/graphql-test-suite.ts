/**
 * GraphQL Test Suite
 * Tests for GraphQL-specific security issues
 */

import { BaseTestSuite } from './base-test-suite';
import { APISecurityTest, APISecurityTestResult } from '../api-security-tester';

export class GraphQLTestSuite extends BaseTestSuite {
  /**
   * Run all GraphQL tests
   */
  async runAllTests(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult[]> {
    const results: APISecurityTestResult[] = [];

    results.push(await this.testGraphQLIntrospection(endpoint, method, test));
    results.push(await this.testGraphQLQueryDepth(endpoint, method, test));
    results.push(await this.testGraphQLFieldAuthorization(endpoint, method, test));
    results.push(await this.testGraphQLBatchQueries(endpoint, method, test));
    results.push(await this.testGraphQLQueryCost(endpoint, method, test));
    results.push(await this.testGraphQLMutationAuthorization(endpoint, method, test));
    results.push(await this.testGraphQLQueryComplexity(endpoint, method, test));

    return results;
  }

  /**
   * Test 1: GraphQL Introspection
   */
  async testGraphQLIntrospection(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
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
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 2: GraphQL Query Depth
   */
  async testGraphQLQueryDepth(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('GraphQL Query Depth Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      headers['Content-Type'] = 'application/json';

      // Create deeply nested query
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
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 3: GraphQL Field Authorization
   */
  async testGraphQLFieldAuthorization(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('GraphQL Field Authorization Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      headers['Content-Type'] = 'application/json';

      // Try to access sensitive fields
      const sensitiveFields = ['password', 'creditCard', 'ssn', 'apiKey', 'secret'];
      const securityIssues: string[] = [];

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
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 4: GraphQL Batch Queries
   */
  async testGraphQLBatchQueries(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('GraphQL Batch Queries Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      headers['Content-Type'] = 'application/json';

      // Create batch query (N+1 problem)
      const batchQuery = {
        query: '{ users { id posts { id comments { id } } } }',
      };

      const response = await this.makeRequest(url, method, headers, batchQuery);
      const body = await response.json().catch(() => ({}));

      result.statusCode = response.status;
      result.responseTime = Date.now() - startTime;
      
      // Check if query executed (potential N+1 problem)
      const hasData = !!body.data;
      result.passed = !hasData || response.status !== 200;
      result.securityIssues = hasData && response.status === 200 ? ['GraphQL batch queries may cause N+1 problem'] : undefined;
      result.details = {
        batchQueryExecuted: hasData,
      };
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 5: GraphQL Query Cost
   */
  async testGraphQLQueryCost(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('GraphQL Query Cost Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      headers['Content-Type'] = 'application/json';

      // Create expensive query
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
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 6: GraphQL Mutation Authorization
   */
  async testGraphQLMutationAuthorization(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('GraphQL Mutation Authorization Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      headers['Content-Type'] = 'application/json';

      // Try unauthorized mutation
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
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }

  /**
   * Test 7: GraphQL Query Complexity
   */
  async testGraphQLQueryComplexity(
    endpoint: string,
    method: string,
    test?: Partial<APISecurityTest>
  ): Promise<APISecurityTestResult> {
    const result = this.createBaseResult('GraphQL Query Complexity Test', endpoint, method);
    const startTime = Date.now();

    try {
      const url = `${this.config.baseUrl}${endpoint}`;
      const headers = this.buildHeaders(test);
      headers['Content-Type'] = 'application/json';

      // Create complex query
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
    } catch (error: any) {
      result.passed = false;
      result.error = error.message;
      result.details = { error: error.message };
    }

    return result;
  }
}

