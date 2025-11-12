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
          rule: { id: 'rule-1', source: '10.0.0.0/8', destination: '20.0.0.0/8', port: 80 },
          passed: true,
        },
      ];

      mockTester.testFirewallRules.mockResolvedValue(mockResult);

      const result = await service.testFirewallRules({
        rules: [
          { id: 'rule-1', source: '10.0.0.0/8', destination: '20.0.0.0/8', port: 80 },
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
        passed: true,
        details: {
          source: 'frontend',
          target: 'backend',
        },
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
      const mockResult = {
        validated: true,
        violations: [],
      };

      mockTester.validateNetworkSegmentation.mockResolvedValue(mockResult);

      const result = await service.validateSegmentation({
        segments: [
          { id: 'segment-1', name: 'Segment 1', cidr: '10.0.0.0/8' },
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
      const mockResult = {
        passed: true,
        details: {},
      };

      mockTester.testServiceMeshPolicies.mockResolvedValue(mockResult);

      const result = await service.testServiceMeshPolicies({
        config: {
          name: 'istio-mesh',
          policies: [],
        },
      });

      expect(result).toEqual(mockResult);
    });

    it('should throw ValidationException for missing config', async () => {
      await expect(service.testServiceMeshPolicies({ config: null as any })).rejects.toThrow(
        ValidationException,
      );
    });

    it('should throw ValidationException for missing config name', async () => {
      await expect(
        service.testServiceMeshPolicies({
          config: {
            policies: [],
          } as any,
        }),
      ).rejects.toThrow(ValidationException);
    });
  });
});

