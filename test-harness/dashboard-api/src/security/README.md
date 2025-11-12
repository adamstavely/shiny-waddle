# Security Module

This module implements comprehensive security features for the ASPM platform, including encryption, secrets management, audit logging, and access controls.

## Features

### 1. Encryption Service

Provides encryption at rest and in transit for sensitive data.

**Usage:**
```typescript
import { EncryptionService } from './security/encryption.service';

// Encrypt data at rest
const encrypted = encryptionService.encryptAtRest('sensitive data');
const decrypted = encryptionService.decryptAtRest(encrypted);

// Encrypt data for transmission
const encryptedString = encryptionService.encryptInTransit('data to transmit');
const decrypted = encryptionService.decryptInTransit(encryptedString);

// Hash passwords
const { hash, salt } = encryptionService.hash('password');
const isValid = encryptionService.verifyHash('password', hash, salt);
```

**Configuration:**
- Set `ENCRYPTION_KEY` environment variable (hex-encoded 32-byte key for AES-256)
- Default algorithm: `aes-256-gcm`

### 2. Secrets Management Service

Secure storage and retrieval of platform secrets.

**API Endpoints:**
- `POST /api/security/secrets` - Create a secret
- `GET /api/security/secrets` - List all secrets (metadata only)
- `GET /api/security/secrets/:key` - Get a secret by key (decrypted)
- `PUT /api/security/secrets/:id` - Update a secret
- `DELETE /api/security/secrets/:id` - Delete a secret
- `POST /api/security/secrets/:id/rotate` - Rotate a secret

**Usage:**
```typescript
import { SecretsService } from './security/secrets.service';

// Create a secret
const secret = await secretsService.createSecret({
  key: 'database-password',
  value: 'my-secret-password',
  description: 'Database connection password',
  tags: ['database', 'production'],
  createdBy: 'user-id',
});

// Retrieve a secret (decrypted)
const secret = await secretsService.getSecretByKey('database-password');
console.log(secret.value); // 'my-secret-password'

// Rotate a secret
await secretsService.rotateSecret(secret.id, 'new-password', 'user-id');
```

**Storage:**
- Secrets are stored encrypted in `data/platform-secrets.json`
- File permissions are set to 600 (owner read/write only)

### 3. Security Audit Logging Service

Comprehensive audit logging for security events.

**Event Types:**
- Authentication & Authorization: login, logout, access granted/denied
- Data Access: read, write, delete, export, import
- Configuration Changes: policy changes, config updates
- Secrets Management: secret created, accessed, updated, deleted, rotated
- System Events: startup, shutdown, backups, encryption key rotation
- Security Events: alerts, suspicious activity, brute force attempts

**Usage:**
```typescript
import { SecurityAuditLogService, SecurityAuditEventType } from './security/audit-log.service';

// Log an event
await auditLogService.log({
  type: SecurityAuditEventType.SECRET_ACCESSED,
  action: 'secret-accessed',
  description: 'User accessed database password',
  userId: 'user-123',
  username: 'john.doe',
  ipAddress: '192.168.1.1',
  resourceType: 'secret',
  resourceId: 'secret-456',
  success: true,
});

// Query logs
const logs = await auditLogService.queryLogs({
  type: SecurityAuditEventType.SECRET_ACCESSED,
  startDate: new Date('2024-01-01'),
  endDate: new Date('2024-12-31'),
  limit: 100,
});
```

**API Endpoints:**
- `GET /api/security/audit-logs` - Query audit logs
- `GET /api/security/audit-logs/:id` - Get specific audit log

### 4. Access Control Guards

Role-based and permission-based access control for API endpoints.

**Roles:**
- `ADMIN` - Full access to all resources
- `EDITOR` - Read and write access to most resources
- `VIEWER` - Read-only access
- `AUDITOR` - Read access including audit logs

**Permissions:**
- `read:*` - Read permissions for various resources
- `write:*` - Write permissions for various resources
- `delete:*` - Delete permissions for various resources
- `manage:*` - Administrative permissions

**Usage:**
```typescript
import { Controller, Get, UseGuards } from '@nestjs/common';
import { AccessControlGuard, RequirePermission, Permission, RequireRole, UserRole } from './security/guards/access-control.guard';

@Controller('api/policies')
@UseGuards(AccessControlGuard)
export class PoliciesController {
  @Get()
  @RequirePermission(Permission.READ_POLICIES)
  async listPolicies() {
    // Only users with READ_POLICIES permission can access
  }

  @Post()
  @RequirePermission(Permission.WRITE_POLICIES)
  async createPolicy() {
    // Only users with WRITE_POLICIES permission can access
  }

  @Delete(':id')
  @RequireRole(UserRole.ADMIN)
  async deletePolicy() {
    // Only admin users can access
  }
}
```

**Note:** The guard expects a `user` object on the request with `role`, `id`, and `username` properties. This should be set by your authentication middleware.

### 5. Audit Logging Middleware

Automatically logs all HTTP requests for audit purposes.

**Features:**
- Logs all write operations (POST, PUT, PATCH, DELETE)
- Logs read operations on sensitive endpoints
- Captures request metadata (IP, user agent, duration, etc.)
- Adds request IDs for traceability

The middleware is automatically applied to all routes when the SecurityModule is imported.

## Configuration

### Environment Variables

```bash
# Encryption key (hex-encoded 32-byte key for AES-256)
ENCRYPTION_KEY=your-32-byte-hex-key-here

# Data directory (where secrets and audit logs are stored)
DATA_DIR=/path/to/data/directory

# Enable HTTPS (for encryption in transit)
HTTPS_ENABLED=true
HTTPS_KEY_PATH=/path/to/key.pem
HTTPS_CERT_PATH=/path/to/cert.pem
```

### Generating Encryption Key

```bash
# Generate a secure 32-byte key
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## Security Best Practices

1. **Encryption Key Management:**
   - Never commit encryption keys to version control
   - Use environment variables or a secrets management service
   - Rotate keys periodically
   - Use different keys for different environments

2. **Secrets Management:**
   - Store all sensitive configuration in the secrets service
   - Use tags to organize secrets
   - Rotate secrets regularly
   - Limit access to secrets using permissions

3. **Audit Logging:**
   - Review audit logs regularly
   - Set up alerts for critical security events
   - Retain logs according to compliance requirements
   - Monitor for suspicious activity patterns

4. **Access Control:**
   - Follow principle of least privilege
   - Use role-based access for broad permissions
   - Use permission-based access for fine-grained control
   - Regularly review and update user permissions

5. **HTTPS/TLS:**
   - Always use HTTPS in production
   - Use strong TLS configurations
   - Regularly update certificates
   - Enable HSTS (HTTP Strict Transport Security)

## Compliance

This security module helps meet requirements for:
- **SOC 2 Type II:** Access controls, encryption, audit logging
- **ISO 27001:** Information security management
- **GDPR:** Data protection and audit trails
- **NIST 800-53:** Security controls (AC-3, SC-8, SC-12, SC-28, AU-2, AU-3)

