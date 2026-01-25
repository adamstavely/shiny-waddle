/**
 * Network Policy Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus } from '@nestjs/common';
import { NetworkPolicyController } from './network-policy.controller';
import { NetworkPolicyService } from './network-policy.service';

describe('NetworkPolicyController', () => {
  let controller: NetworkPolicyController;
  let networkPolicyService: jest.Mocked<NetworkPolicyService>;

  const mockTestResult = {
    passed: true,
    testType: 'network-policy' as const,
    testName: 'Network Policy Test',
    timestamp: new Date(),
    details: {},
  };

  beforeEach(async () => {
    const mockNetworkPolicyService = {
      testFirewallRules: jest.fn(),
      testServiceToService: jest.fn(),
      validateSegmentation: jest.fn(),
      testServiceMeshPolicies: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [NetworkPolicyController],
      providers: [
        {
          provide: NetworkPolicyService,
          useValue: mockNetworkPolicyService,
        },
      ],
    }).compile();

    controller = module.get<NetworkPolicyController>(NetworkPolicyController);
    networkPolicyService = module.get(NetworkPolicyService) as jest.Mocked<NetworkPolicyService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('testFirewallRules', () => {
    it('should test firewall rules with applicationId', async () => {
      // Arrange
      const dto = {
        applicationId: 'app-1',
        networkSegmentId: 'segment-1',
      };
      networkPolicyService.testFirewallRules.mockResolvedValue([mockTestResult]);

      // Act
      const result = await controller.testFirewallRules(dto);

      // Assert
      expect(result).toEqual([mockTestResult]);
      expect(networkPolicyService.testFirewallRules).toHaveBeenCalledWith(dto);
    });

    it('should test firewall rules with rules array', async () => {
      // Arrange
      const dto = {
        rules: [
          { source: '10.0.0.0/8', target: '20.0.0.0/8', port: 443 },
        ],
      };
      networkPolicyService.testFirewallRules.mockResolvedValue([mockTestResult]);

      // Act
      const result = await controller.testFirewallRules(dto);

      // Assert
      expect(result).toEqual([mockTestResult]);
      expect(networkPolicyService.testFirewallRules).toHaveBeenCalledWith(dto);
    });
  });

  describe('testServiceToService', () => {
    it('should test service-to-service with applicationId', async () => {
      // Arrange
      const dto = {
        applicationId: 'app-1',
        networkSegmentId: 'segment-1',
      };
      networkPolicyService.testServiceToService.mockResolvedValue(mockTestResult);

      // Act
      const result = await controller.testServiceToService(dto);

      // Assert
      expect(result).toEqual(mockTestResult);
      expect(networkPolicyService.testServiceToService).toHaveBeenCalledWith(dto);
    });

    it('should test service-to-service with source and target', async () => {
      // Arrange
      const dto = {
        source: 'service-1',
        target: 'service-2',
      };
      networkPolicyService.testServiceToService.mockResolvedValue(mockTestResult);

      // Act
      const result = await controller.testServiceToService(dto);

      // Assert
      expect(result).toEqual(mockTestResult);
      expect(networkPolicyService.testServiceToService).toHaveBeenCalledWith(dto);
    });
  });

  describe('validateSegmentation', () => {
    it('should validate segmentation with applicationId', async () => {
      // Arrange
      const dto = {
        applicationId: 'app-1',
      };
      networkPolicyService.validateSegmentation.mockResolvedValue([mockTestResult]);

      // Act
      const result = await controller.validateSegmentation(dto);

      // Assert
      expect(result).toEqual([mockTestResult]);
      expect(networkPolicyService.validateSegmentation).toHaveBeenCalledWith(dto);
    });

    it('should validate segmentation with segments array', async () => {
      // Arrange
      const dto = {
        segments: [
          { id: 'segment-1', cidr: '10.0.0.0/8' },
          { id: 'segment-2', cidr: '20.0.0.0/8' },
        ],
      };
      networkPolicyService.validateSegmentation.mockResolvedValue([mockTestResult]);

      // Act
      const result = await controller.validateSegmentation(dto);

      // Assert
      expect(result).toEqual([mockTestResult]);
      expect(networkPolicyService.validateSegmentation).toHaveBeenCalledWith(dto);
    });
  });

  describe('testServiceMeshPolicies', () => {
    it('should test service mesh policies with applicationId', async () => {
      // Arrange
      const dto = {
        applicationId: 'app-1',
        networkSegmentId: 'segment-1',
      };
      networkPolicyService.testServiceMeshPolicies.mockResolvedValue([mockTestResult]);

      // Act
      const result = await controller.testServiceMeshPolicies(dto);

      // Assert
      expect(result).toEqual([mockTestResult]);
      expect(networkPolicyService.testServiceMeshPolicies).toHaveBeenCalledWith(dto);
    });

    it('should test service mesh policies with config', async () => {
      // Arrange
      const dto = {
        config: {
          name: 'istio-config',
          policies: [],
        },
      };
      networkPolicyService.testServiceMeshPolicies.mockResolvedValue([mockTestResult]);

      // Act
      const result = await controller.testServiceMeshPolicies(dto);

      // Assert
      expect(result).toEqual([mockTestResult]);
      expect(networkPolicyService.testServiceMeshPolicies).toHaveBeenCalledWith(dto);
    });
  });
});
