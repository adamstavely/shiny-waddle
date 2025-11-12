/**
 * Network Policy Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NetworkPolicyService } from './network-policy.service';
import { NetworkMicrosegmentationTester } from '../../../services/network-microsegmentation-tester';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';

// Mock the dependencies
jest.mock('../../../services/network-microsegmentation-tester');

describe('NetworkPolicyService', () => {
  let service: NetworkPolicyService;
  let mockTester: jest.Mocked<NetworkMicrosegmentationTester>;

  beforeEach(async () => {
    // Reset mocks
    jest.clearAllMocks();

    // Create mock instance
    mockTester = {
      testFirewallRules: jest.fn(),
      testServiceToServiceTraffic: jest.fn(),
      validateNetworkSegmentation: jest.fn(),
      testServiceMeshPolicies: jest.fn(),
    } as any;

    // Mock the constructor
    (NetworkMicrosegmentationTester as jest.Mock).mockImplementation(() => mockTester);

    const module: TestingModule = await Test.createTestingModule({
      providers: [NetworkPolicyService],
    }).compile();

    service = module.get<NetworkPolicyService>(NetworkPolicyService);
  });

  describe('testFirewallRules', () => {
    it('should successfully test firewall rules', async () => {
      const mockResult = [
        {
          testType: 'access-control' as const,
          testName: 'Firewall Rule Test',
          passed: true,
          details: {},
          timestamp: new Date(),
        },
      ];

      mockTester.testFirewallRules.mockResolvedValue(mockResult);

      const result = await service.testFirewallRules({
        rules: [
          { id: 'rule-1', name: 'Rule 1', source: '10.0.0.0/8', destination: '20.0.0.0/8', protocol: 'tcp' as const, port: 80, action: 'allow' as const, enabled: true },
        ],
      });

      expect(result).toEqual(mockResult);
    });

    it('should throw ValidationException for missing rules array', async () => {
      await expect(service.testFirewallRules({ rules: null as any })).rejects.toThrow(
        ValidationException,
      );
    });

    it('should throw ValidationException for empty rules array', async () => {
      await expect(service.testFirewallRules({ rules: [] })).rejects.toThrow(
        ValidationException,
      );
    });
  });

  describe('testServiceToService', () => {
    it('should successfully test service-to-service traffic', async () => {
      const mockResult = {
        testType: 'access-control' as const,
        testName: 'Service-to-Service Traffic Test',
        passed: true,
        details: {
          source: 'frontend',
          target: 'backend',
        },
        timestamp: new Date(),
      };

      mockTester.testServiceToServiceTraffic.mockResolvedValue(mockResult);

      const result = await service.testServiceToService({
        source: 'frontend',
        target: 'backend',
      });

      expect(result).toEqual(mockResult);
    });

    it('should throw ValidationException for missing source', async () => {
      await expect(
        service.testServiceToService({
          source: '',
          target: 'backend',
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for missing target', async () => {
      await expect(
        service.testServiceToService({
          source: 'frontend',
          target: '',
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for same source and target', async () => {
      await expect(
        service.testServiceToService({
          source: 'frontend',
          target: 'frontend',
        }),
      ).rejects.toThrow(ValidationException);
    });
  });

  describe('validateSegmentation', () => {
    it('should successfully validate network segmentation', async () => {
      const mockResult = [
        {
          testType: 'access-control' as const,
          testName: 'Network Segmentation Validation',
          passed: true,
          details: {},
          timestamp: new Date(),
        },
      ];

      mockTester.validateNetworkSegmentation.mockResolvedValue(mockResult);

      const result = await service.validateSegmentation({
        segments: [
          { id: 'segment-1', name: 'Segment 1', cidr: '10.0.0.0/8', services: [], allowedConnections: [], deniedConnections: [] },
        ],
      });

      expect(result).toEqual(mockResult);
    });

    it('should throw ValidationException for missing segments array', async () => {
      await expect(service.validateSegmentation({ segments: null as any })).rejects.toThrow(
        ValidationException,
      );
    });

    it('should throw ValidationException for empty segments array', async () => {
      await expect(service.validateSegmentation({ segments: [] })).rejects.toThrow(
        ValidationException,
      );
    });
  });

  describe('testServiceMeshPolicies', () => {
    it('should successfully test service mesh policies', async () => {
      const mockResult = [
        {
          testType: 'access-control' as const,
          testName: 'Service Mesh Policy Test',
          passed: true,
          details: {},
          timestamp: new Date(),
        },
      ];

      mockTester.testServiceMeshPolicies.mockResolvedValue(mockResult);

      const result = await service.testServiceMeshPolicies({
        config: {
          type: 'istio' as const,
          controlPlaneEndpoint: 'https://istio-control-plane:8080',
        },
      });

      expect(result).toEqual(mockResult);
    });

    it('should throw ValidationException for missing config', async () => {
      await expect(service.testServiceMeshPolicies({ config: null as any })).rejects.toThrow(
        ValidationException,
      );
    });

    it('should throw ValidationException for missing config type', async () => {
      await expect(
        service.testServiceMeshPolicies({
          config: {
            controlPlaneEndpoint: 'https://istio-control-plane:8080',
          } as any,
        }),
      ).rejects.toThrow(ValidationException);
    });
  });
});

