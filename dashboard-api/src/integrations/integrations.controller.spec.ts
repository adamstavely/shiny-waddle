/**
 * Integrations Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { IntegrationsController } from './integrations.controller';
import { IntegrationsService } from './integrations.service';

describe('IntegrationsController', () => {
  let controller: IntegrationsController;
  let service: jest.Mocked<IntegrationsService>;

  const mockIntegrationStatus = {
    cicd: {
      enabled: true,
      providers: ['github', 'jenkins', 'gitlab', 'azure-devops'],
    },
    siem: {
      enabled: true,
      providers: ['splunk', 'qradar', 'sentinel', 'custom'],
    },
    cloud: {
      enabled: true,
      providers: ['aws', 'azure', 'gcp'],
    },
    iam: {
      enabled: true,
      providers: ['sso', 'rbac', 'pam', 'idp'],
    },
  };

  beforeEach(async () => {
    const mockService = {
      getIntegrationStatus: jest.fn().mockResolvedValue(mockIntegrationStatus),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [IntegrationsController],
      providers: [
        {
          provide: IntegrationsService,
          useValue: mockService,
        },
      ],
    }).compile();

    controller = module.get<IntegrationsController>(IntegrationsController);
    service = module.get(IntegrationsService) as jest.Mocked<IntegrationsService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('getStatus', () => {
    it('should return integration status', async () => {
      // Act
      const result = await controller.getStatus();

      // Assert
      expect(result).toEqual(mockIntegrationStatus);
      expect(service.getIntegrationStatus).toHaveBeenCalledTimes(1);
    });

    it('should call service.getIntegrationStatus', async () => {
      // Act
      await controller.getStatus();

      // Assert
      expect(service.getIntegrationStatus).toHaveBeenCalled();
    });
  });
});
