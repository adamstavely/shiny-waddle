/**
 * Integration Tests for User Management Workflow
 * 
 * Tests the complete workflow:
 * 1. Query users (users are loaded from JSON, not created via API)
 * 2. Query users by role
 * 3. Query users by application
 * 4. Query audit logs
 * 5. Verify permissions and access
 */

import { INestApplication } from '@nestjs/common';
import { createIntegrationApp, getService } from './integration-setup';
import { UsersService } from '../src/users/users.service';
import { SecurityAuditLogService, SecurityAuditEventType, SecurityAuditSeverity } from '../src/security/audit-log.service';
import { ApplicationsService } from '../src/applications/applications.service';
import { CreateApplicationDto, ApplicationType } from '../src/applications/dto/create-application.dto';

describe('User Management Workflow (Integration)', () => {
  let app: INestApplication;
  let usersService: UsersService;
  let auditLogService: SecurityAuditLogService;
  let applicationsService: ApplicationsService;

  beforeAll(async () => {
    app = await createIntegrationApp();
    usersService = getService(app, UsersService);
    auditLogService = getService(app, SecurityAuditLogService);
    applicationsService = getService(app, ApplicationsService);
  });

  afterAll(async () => {
    await app.close();
  });

  it('should query users, filter by role and application, and verify audit logs', async () => {
    // Step 1: Get all users
    const allUsers = await usersService.getAllUsers();
    expect(Array.isArray(allUsers)).toBe(true);

    // Step 2: Query users by role (if any users exist)
    if (allUsers.length > 0) {
      const firstUser = allUsers[0];
      if (firstUser.roles && firstUser.roles.length > 0) {
        const role = firstUser.roles[0];
        const usersByRole = await usersService.getUsersByRole(role);
        expect(Array.isArray(usersByRole)).toBe(true);
        expect(usersByRole.every(u => u.roles.includes(role))).toBe(true);
      }
    }

    // Step 3: Create an application and query users by application
    const applicationDto: CreateApplicationDto = {
      id: `user-test-app-${Date.now()}`,
      name: 'User Test Application',
      description: 'Application for user management testing',
      type: ApplicationType.API,
      team: 'test-team',
      infrastructure: {
        databases: [],
        networkSegments: [],
      },
    };
    const application = await applicationsService.create(applicationDto);
    expect(application).toBeDefined();

    // Query users by application (if any users are associated)
    const usersByApplication = await usersService.getUsersByApplication(application.id);
    expect(Array.isArray(usersByApplication)).toBe(true);

    // Step 4: Create audit log entry (simulating user action)
    const auditLog = await auditLogService.log({
      type: SecurityAuditEventType.ACCESS_GRANTED,
      action: 'view-application',
      description: `User accessed application ${application.name}`,
      userId: 'test-user-id',
      username: 'test-user',
      resourceType: 'application',
      resourceId: application.id,
      success: true,
      ipAddress: '127.0.0.1',
    });
    expect(auditLog).toBeDefined();
    expect(auditLog.id).toBeDefined();
    expect(auditLog.resourceId).toBe(application.id);

    // Step 5: Query audit logs
    const auditLogs = await auditLogService.queryLogs({
      resourceId: application.id,
      limit: 10,
    });
    expect(Array.isArray(auditLogs)).toBe(true);
    expect(auditLogs.length).toBeGreaterThan(0);
    expect(auditLogs.some(log => log.id === auditLog.id)).toBe(true);

    // Verify permissions by checking audit logs for access patterns
    const accessLogs = await auditLogService.queryLogs({
      type: SecurityAuditEventType.ACCESS_GRANTED,
      resourceType: 'application',
      limit: 10,
    });
    expect(Array.isArray(accessLogs)).toBe(true);
  });

  it('should query users by team and context', async () => {
    // Query users by team
    const usersByTeam = await usersService.getUsersByTeam('test-team');
    expect(Array.isArray(usersByTeam)).toBe(true);

    // Query users by applications and teams
    const applicationDto: CreateApplicationDto = {
      id: `context-test-app-${Date.now()}`,
      name: 'Context Test Application',
      description: 'Application for context testing',
      type: ApplicationType.API,
      team: 'test-team',
      infrastructure: {
        databases: [],
        networkSegments: [],
      },
    };
    const application = await applicationsService.create(applicationDto);

    const usersByContext = await usersService.getUsersByApplicationsAndTeams(
      [application.id],
      ['test-team']
    );
    expect(Array.isArray(usersByContext)).toBe(true);
  });

  it('should track user access in audit logs', async () => {
    const applicationDto: CreateApplicationDto = {
      id: `audit-test-app-${Date.now()}`,
      name: 'Audit Test Application',
      description: 'Application for audit testing',
      type: ApplicationType.API,
      team: 'test-team',
      infrastructure: {
        databases: [],
        networkSegments: [],
      },
    };
    const application = await applicationsService.create(applicationDto);

    // Log multiple access events
    const log1 = await auditLogService.log({
      type: SecurityAuditEventType.ACCESS_GRANTED,
      action: 'view',
      description: 'User viewed application',
      userId: 'user-1',
      username: 'testuser1',
      resourceType: 'application',
      resourceId: application.id,
      success: true,
    });

    const log2 = await auditLogService.log({
      type: SecurityAuditEventType.ACCESS_DENIED,
      action: 'delete',
      description: 'User attempted to delete application',
      userId: 'user-2',
      username: 'testuser2',
      resourceType: 'application',
      resourceId: application.id,
      success: false,
    });

    expect(log1).toBeDefined();
    expect(log2).toBeDefined();

    // Query logs for this application
    const logs = await auditLogService.queryLogs({
      resourceId: application.id,
      limit: 10,
    });
    expect(logs.length).toBeGreaterThanOrEqual(2);
    expect(logs.some(log => log.id === log1.id)).toBe(true);
    expect(logs.some(log => log.id === log2.id)).toBe(true);
  });
});
