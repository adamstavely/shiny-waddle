"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ContainerSecurityScanner = void 0;
class ContainerSecurityScanner {
    async scanImage(image) {
        const vulnerabilities = [
            {
                id: 'CVE-2023-12345',
                severity: 'high',
                package: 'openssl',
                version: '1.1.1',
                description: 'OpenSSL vulnerability',
            },
            {
                id: 'CVE-2023-67890',
                severity: 'medium',
                package: 'curl',
                version: '7.68.0',
                description: 'Curl vulnerability',
            },
        ];
        const criticalOrHigh = vulnerabilities.filter(v => v.severity === 'critical' || v.severity === 'high').length;
        return {
            image,
            vulnerabilities,
            passed: criticalOrHigh === 0,
        };
    }
    async scanImages(images) {
        const results = [];
        for (const image of images) {
            results.push(await this.scanImage(image));
        }
        return results;
    }
}
exports.ContainerSecurityScanner = ContainerSecurityScanner;
//# sourceMappingURL=container-security-scanner.js.map