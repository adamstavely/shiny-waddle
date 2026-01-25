/**
 * Integrations Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { IntegrationsService } from './integrations.service';

describe('IntegrationsService', () => {
  let service: IntegrationsService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [IntegrationsService],
    }).compile();

    service = module.get<IntegrationsService>(IntegrationsService);
  });

  describe('getIntegrationStatus', () => {
    it('should return integration status for all types', async () => {
      // Act
      const result = await service.getIntegrationStatus();

      // Assert
      expect(result).toBeDefined();
      expect(result.cicd).toBeDefined();
      expect(result.siem).toBeDefined();
      expect(result.cloud).toBeDefined();
      expect(result.iam).toBeDefined();
    });

    it('should return enabled status for all integrations', async () => {
      // Act
      const result = await service.getIntegrationStatus();

      // Assert
      expect(result.cicd.enabled).toBe(true);
      expect(result.siem.enabled).toBe(true);
      expect(result.cloud.enabled).toBe(true);
      expect(result.iam.enabled).toBe(true);
    });

    it('should return providers for each integration type', async () => {
      // Act
      const result = await service.getIntegrationStatus();

      // Assert
      expect(Array.isArray(result.cicd.providers)).toBe(true);
      expect(Array.isArray(result.siem.providers)).toBe(true);
      expect(Array.isArray(result.cloud.providers)).toBe(true);
      expect(Array.isArray(result.iam.providers)).toBe(true);
      expect(result.cicd.providers.length).toBeGreaterThan(0);
    });

    it('should include expected CI/CD providers', async () => {
      // Act
      const result = await service.getIntegrationStatus();

      // Assert
      expect(result.cicd.providers).toContain('github');
      expect(result.cicd.providers).toContain('jenkins');
    });

    it('should include expected SIEM providers', async () => {
      // Act
      const result = await service.getIntegrationStatus();

      // Assert
      expect(result.siem.providers).toContain('splunk');
      expect(result.siem.providers).toContain('qradar');
    });

    it('should include expected cloud providers', async () => {
      // Act
      const result = await service.getIntegrationStatus();

      // Assert
      expect(result.cloud.providers).toContain('aws');
      expect(result.cloud.providers).toContain('azure');
      expect(result.cloud.providers).toContain('gcp');
    });
  });
});
