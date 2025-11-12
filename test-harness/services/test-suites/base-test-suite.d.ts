import { APISecurityTestConfig, APISecurityTest, APISecurityTestResult } from '../api-security-tester';
export declare abstract class BaseTestSuite {
    protected config: APISecurityTestConfig;
    constructor(config: APISecurityTestConfig);
    protected buildHeaders(test?: Partial<APISecurityTest>): Record<string, string>;
    protected getAuthHeader(auth: APISecurityTestConfig['authentication'], user?: any): string;
    protected makeRequest(url: string, method: string, headers: Record<string, string>, body?: any): Promise<Response>;
    protected createBaseResult(testName: string, endpoint: string, method: string): APISecurityTestResult;
    protected evaluateResult(result: APISecurityTestResult, expectedStatus?: number, expectedAuthRequired?: boolean): boolean;
    abstract runAllTests(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult[]>;
}
