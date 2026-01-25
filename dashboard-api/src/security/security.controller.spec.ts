/**
 * Security Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus } from '@nestjs/common';
import { SecurityController } from './security.controller';
import { SecretsService, CreateSecretDto, UpdateSecretDto } from './secrets.service';
import { SecurityAuditLogService, SecurityAuditEventType } from './audit-log.service';
import { AccessControlGuard } from './guards/access-control.guard';

describe('SecurityController', () => {
  let controller: SecurityController;
  let secretsService: jest.Mocked<SecretsService>;
  let auditLogService: jest.Mocked<SecurityAuditLogService>;

  const mockRequest = {
    user: {
      id: 'user-1',
      userId: 'user-1',
      username: 'testuser',
      email: 'test@example.com',
    },
    ip: '127.0.0.1',
    get: jest.fn(() => 'test-agent'),
    headers: { 'x-request-id': 'req-1' },
  };

  const mockSecret = {
    id: 'secret-1',
    key: 'test-key',
    value: 'test-value',
    tags: [],
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  beforeEach(async () => {
    const mockSecretsService = {
      createSecret: jest.fn(),
      listSecrets: jest.fn(),
      getSecretByKey: jest.fn(),
      getSecretById: jest.fn(),
      updateSecret: jest.fn(),
      deleteSecret: jest.fn(),
      rotateSecret: jest.fn(),
    };

    const mockAuditLogService = {
      log: jest.fn(),
      queryLogs: jest.fn(),
      getLogById: jest.fn(),
      exportToCSV: jest.fn(),
      exportToJSON: jest.fn(),
      detectSuspiciousActivity: jest.fn(),
      applyRetentionPolicy: jest.fn(),
      getRetentionPolicy: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [SecurityController],
      providers: [
        {
          provide: SecretsService,
          useValue: mockSecretsService,
        },
        {
          provide: SecurityAuditLogService,
          useValue: mockAuditLogService,
        },
      ],
    })
      .overrideGuard(AccessControlGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<SecurityController>(SecurityController);
    secretsService = module.get(SecretsService) as jest.Mocked<SecretsService>;
    auditLogService = module.get(SecurityAuditLogService) as jest.Mocked<SecurityAuditLogService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('createSecret', () => {
    const dto: CreateSecretDto = {
      key: 'test-key',
      value: 'test-value',
    };

    it('should create a secret', async () => {
      // Arrange
      secretsService.createSecret.mockResolvedValue(mockSecret as any);

      // Act
      const result = await controller.createSecret(dto, mockRequest as any);

      // Assert
      expect(result).toEqual(mockSecret);
      expect(secretsService.createSecret).toHaveBeenCalledWith({
        ...dto,
        createdBy: 'user-1',
      });
      expect(auditLogService.log).toHaveBeenCalled();
    });
  });

  describe('listSecrets', () => {
    it('should list secrets', async () => {
      // Arrange
      secretsService.listSecrets.mockResolvedValue([mockSecret] as any);

      // Act
      const result = await controller.listSecrets();

      // Assert
      expect(result).toEqual([mockSecret]);
      expect(secretsService.listSecrets).toHaveBeenCalledWith(undefined);
    });

    it('should list secrets with tags filter', async () => {
      // Arrange
      secretsService.listSecrets.mockResolvedValue([mockSecret] as any);

      // Act
      const result = await controller.listSecrets('tag1,tag2');

      // Assert
      expect(result).toEqual([mockSecret]);
      expect(secretsService.listSecrets).toHaveBeenCalledWith(['tag1', 'tag2']);
    });
  });

  describe('getSecret', () => {
    it('should get secret by key', async () => {
      // Arrange
      secretsService.getSecretByKey.mockResolvedValue(mockSecret as any);

      // Act
      const result = await controller.getSecret('test-key', mockRequest as any);

      // Assert
      expect(result).toEqual(mockSecret);
      expect(secretsService.getSecretByKey).toHaveBeenCalledWith('test-key');
      expect(auditLogService.log).toHaveBeenCalled();
    });
  });

  describe('updateSecret', () => {
    const dto: UpdateSecretDto = {
      value: 'updated-value',
    };

    it('should update a secret', async () => {
      // Arrange
      const updated = { ...mockSecret, ...dto };
      secretsService.updateSecret.mockResolvedValue(updated as any);

      // Act
      const result = await controller.updateSecret('secret-1', dto, mockRequest as any);

      // Assert
      expect(result).toEqual(updated);
      expect(secretsService.updateSecret).toHaveBeenCalledWith('secret-1', {
        ...dto,
        updatedBy: 'user-1',
      });
      expect(auditLogService.log).toHaveBeenCalled();
    });
  });

  describe('deleteSecret', () => {
    it('should delete a secret', async () => {
      // Arrange
      secretsService.getSecretById.mockResolvedValue(mockSecret as any);
      secretsService.deleteSecret.mockResolvedValue(undefined);

      // Act
      const result = await controller.deleteSecret('secret-1', mockRequest as any);

      // Assert
      expect(result).toEqual({ message: 'Secret deleted successfully' });
      expect(secretsService.deleteSecret).toHaveBeenCalledWith('secret-1');
      expect(auditLogService.log).toHaveBeenCalled();
    });
  });

  describe('rotateSecret', () => {
    it('should rotate a secret', async () => {
      // Arrange
      const rotated = { ...mockSecret, value: 'new-value' };
      secretsService.rotateSecret.mockResolvedValue(rotated as any);

      // Act
      const result = await controller.rotateSecret('secret-1', { value: 'new-value' }, mockRequest as any);

      // Assert
      expect(result).toEqual(rotated);
      expect(secretsService.rotateSecret).toHaveBeenCalledWith('secret-1', 'new-value', 'user-1');
      expect(auditLogService.log).toHaveBeenCalled();
    });
  });

  describe('getAuditLogs', () => {
    it('should get audit logs', async () => {
      // Arrange
      const logs = [{ id: 'log-1' }];
      auditLogService.queryLogs.mockResolvedValue(logs as any);

      // Act
      const result = await controller.getAuditLogs();

      // Assert
      expect(result).toEqual(logs);
      expect(auditLogService.queryLogs).toHaveBeenCalledWith({});
    });
  });

  describe('getAuditLog', () => {
    it('should get audit log by id', async () => {
      // Arrange
      const log = { id: 'log-1' };
      auditLogService.getLogById.mockResolvedValue(log as any);

      // Act
      const result = await controller.getAuditLog('log-1');

      // Assert
      expect(result).toEqual(log);
      expect(auditLogService.getLogById).toHaveBeenCalledWith('log-1');
    });
  });

  describe('exportAuditLogsCSV', () => {
    it('should export audit logs as CSV', async () => {
      // Arrange
      const csv = 'id,action\nlog-1,test';
      auditLogService.exportToCSV.mockResolvedValue(csv);

      // Act
      const result = await controller.exportAuditLogsCSV();

      // Assert
      expect(result).toEqual({ format: 'csv', data: csv });
      expect(auditLogService.exportToCSV).toHaveBeenCalledWith({});
    });
  });

  describe('exportAuditLogsJSON', () => {
    it('should export audit logs as JSON', async () => {
      // Arrange
      const json = JSON.stringify([{ id: 'log-1' }]);
      auditLogService.exportToJSON.mockResolvedValue(json);

      // Act
      const result = await controller.exportAuditLogsJSON();

      // Assert
      expect(result).toEqual({ format: 'json', data: [{ id: 'log-1' }] });
      expect(auditLogService.exportToJSON).toHaveBeenCalledWith({});
    });
  });

  describe('detectSuspiciousActivity', () => {
    it('should detect suspicious activity', async () => {
      // Arrange
      const activity = { suspicious: true };
      auditLogService.detectSuspiciousActivity.mockResolvedValue(activity as any);

      // Act
      const result = await controller.detectSuspiciousActivity();

      // Assert
      expect(result).toEqual(activity);
      expect(auditLogService.detectSuspiciousActivity).toHaveBeenCalledTimes(1);
    });
  });

  describe('applyRetentionPolicy', () => {
    it('should apply retention policy', async () => {
      // Arrange
      auditLogService.getRetentionPolicy.mockReturnValue({ enabled: true, retentionDays: 90 });
      auditLogService.applyRetentionPolicy.mockResolvedValue(10);

      // Act
      const result = await controller.applyRetentionPolicy(90);

      // Assert
      expect(result).toEqual({
        message: 'Retention policy applied. 10 log(s) removed.',
        removedCount: 10,
        retentionDays: 90,
      });
      expect(auditLogService.applyRetentionPolicy).toHaveBeenCalledWith(90);
    });
  });

  describe('getRetentionPolicy', () => {
    it('should get retention policy', async () => {
      // Arrange
      const policy = { enabled: true, retentionDays: 90 };
      auditLogService.getRetentionPolicy.mockReturnValue(policy as any);

      // Act
      const result = await controller.getRetentionPolicy();

      // Assert
      expect(result).toEqual(policy);
      expect(auditLogService.getRetentionPolicy).toHaveBeenCalledTimes(1);
    });
  });
});
