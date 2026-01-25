/**
 * Salesforce Experience Cloud Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { SalesforceExperienceCloudService } from './salesforce-experience-cloud.service';
import { SalesforceExperienceCloudTester } from '../../../heimdall-framework/services/salesforce-experience-cloud-tester';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';

// Mock the dependencies
jest.mock('../../../services/salesforce-experience-cloud-tester');
jest.mock('fs/promises');
jest.mock('path');
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'mock-uuid'),
}));

describe('SalesforceExperienceCloudService', () => {
  let service: SalesforceExperienceCloudService;
  let tester: jest.Mocked<SalesforceExperienceCloudTester>;

  beforeEach(async () => {
    // Reset mocks
    jest.clearAllMocks();

    // Create mock instance
    tester = {
      testGuestAccess: jest.fn(),
      testAuthenticatedAccess: jest.fn(),
      testGraphQLCapability: jest.fn(),
      testSelfRegistration: jest.fn(),
      testRecordListComponents: jest.fn(),
      testHomeURLs: jest.fn(),
      testObjectAccess: jest.fn(),
      runFullAudit: jest.fn(),
    } as any;

    // Mock the constructor
    (SalesforceExperienceCloudTester as jest.Mock).mockImplementation(() => tester);

    const module: TestingModule = await Test.createTestingModule({
      providers: [SalesforceExperienceCloudService],
    }).compile();

    service = module.get<SalesforceExperienceCloudService>(SalesforceExperienceCloudService);
    
    // Initialize with mock data
    (service as any).configs = [
      {
        id: 'config-1',
        name: 'Test Config',
        url: 'https://example.force.com',
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    ];
  });

  describe('createConfig', () => {
    it('should successfully create a configuration', async () => {
      const dto = {
        name: 'New Config',
        url: 'https://test.force.com',
      };

      const result = await service.createConfig(dto);

      expect(result).toHaveProperty('id');
      expect(result.name).toBe(dto.name);
      expect(result.url).toBe(dto.url);
      expect(result.createdAt).toBeInstanceOf(Date);
    });

    it('should throw ValidationException for invalid URL', async () => {
      const dto = {
        name: 'Invalid Config',
        url: 'not-a-url',
      };

      await expect(service.createConfig(dto as any)).rejects.toThrow();
    });
  });

  describe('findOneConfig', () => {
    it('should return configuration by ID', async () => {
      const result = await service.findOneConfig('config-1');

      expect(result).toBeDefined();
      expect(result.id).toBe('config-1');
    });

    it('should throw NotFoundException for non-existent config', async () => {
      await expect(service.findOneConfig('non-existent')).rejects.toThrow(NotFoundException);
    });
  });

  describe('runGuestAccessTest', () => {
    it('should successfully run guest access test', async () => {
      const mockResult = {
        testType: 'salesforce-experience-cloud',
        testName: 'Guest Access Test',
        passed: false,
        timestamp: new Date(),
        details: {
          findings: [],
          summary: {
            totalFindings: 0,
            criticalCount: 0,
            highCount: 0,
            mediumCount: 0,
          },
        },
      };

      tester.testGuestAccess.mockResolvedValue(mockResult as any);

      const result = await service.runGuestAccessTest({ configId: 'config-1' });

      expect(result).toHaveProperty('id');
      expect(result.testType).toBe('guest-access');
      expect(result.configId).toBe('config-1');
      expect(tester.testGuestAccess).toHaveBeenCalled();
    });

    it('should throw NotFoundException for non-existent config', async () => {
      await expect(
        service.runGuestAccessTest({ configId: 'non-existent' }),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('runAuthenticatedAccessTest', () => {
    it('should successfully run authenticated access test', async () => {
      const mockResult = {
        testType: 'salesforce-experience-cloud',
        testName: 'Authenticated Access Test',
        passed: true,
        timestamp: new Date(),
        details: {
          findings: [],
          summary: {
            totalFindings: 0,
            criticalCount: 0,
            highCount: 0,
            mediumCount: 0,
          },
        },
      };

      tester.testAuthenticatedAccess.mockResolvedValue(mockResult as any);

      const result = await service.runAuthenticatedAccessTest({ configId: 'config-1' });

      expect(result).toHaveProperty('id');
      expect(result.testType).toBe('authenticated-access');
      expect(tester.testAuthenticatedAccess).toHaveBeenCalled();
    });

    it('should use provided cookies override', async () => {
      const mockResult = {
        testType: 'salesforce-experience-cloud',
        testName: 'Authenticated Access Test',
        passed: true,
        timestamp: new Date(),
        details: {},
      };

      tester.testAuthenticatedAccess.mockResolvedValue(mockResult as any);

      await service.runAuthenticatedAccessTest({
        configId: 'config-1',
        cookies: 'custom-cookies',
      });

      expect(SalesforceExperienceCloudTester).toHaveBeenCalledWith(
        expect.objectContaining({
          cookies: 'custom-cookies',
        }),
      );
    });
  });

  describe('runGraphQLTest', () => {
    it('should successfully run GraphQL test', async () => {
      const mockResult = {
        testType: 'salesforce-experience-cloud',
        testName: 'GraphQL Capability Test',
        passed: true,
        timestamp: new Date(),
        details: {
          findings: [],
          graphqlAvailable: true,
        },
      };

      tester.testGraphQLCapability.mockResolvedValue(mockResult as any);

      const result = await service.runGraphQLTest({ configId: 'config-1' });

      expect(result.testType).toBe('graphql');
      expect(tester.testGraphQLCapability).toHaveBeenCalled();
    });
  });

  describe('runSelfRegistrationTest', () => {
    it('should successfully run self-registration test', async () => {
      const mockResult = {
        testType: 'salesforce-experience-cloud',
        testName: 'Self-Registration Test',
        passed: true,
        timestamp: new Date(),
        details: {
          findings: [],
          selfRegistrationAvailable: false,
        },
      };

      tester.testSelfRegistration.mockResolvedValue(mockResult as any);

      const result = await service.runSelfRegistrationTest({ configId: 'config-1' });

      expect(result.testType).toBe('self-registration');
      expect(tester.testSelfRegistration).toHaveBeenCalled();
    });
  });

  describe('runRecordListTest', () => {
    it('should successfully run record list test', async () => {
      const mockResult = {
        testType: 'salesforce-experience-cloud',
        testName: 'Record List Components Test',
        passed: false,
        timestamp: new Date(),
        details: {
          findings: [],
          objects: ['Account', 'Contact'],
          summary: {
            totalFindings: 0,
            misconfiguredObjects: 0,
          },
        },
      };

      tester.testRecordListComponents.mockResolvedValue(mockResult as any);

      const result = await service.runRecordListTest({ configId: 'config-1' });

      expect(result.testType).toBe('record-lists');
      expect(tester.testRecordListComponents).toHaveBeenCalled();
    });
  });

  describe('runHomeURLTest', () => {
    it('should successfully run home URL test', async () => {
      const mockResult = {
        testType: 'salesforce-experience-cloud',
        testName: 'Home URLs Test',
        passed: true,
        timestamp: new Date(),
        details: {
          findings: [],
          urls: [],
          summary: {
            totalFindings: 0,
            unauthorizedURLs: 0,
          },
        },
      };

      tester.testHomeURLs.mockResolvedValue(mockResult as any);

      const result = await service.runHomeURLTest({ configId: 'config-1' });

      expect(result.testType).toBe('home-urls');
      expect(tester.testHomeURLs).toHaveBeenCalled();
    });
  });

  describe('runObjectAccessTest', () => {
    it('should successfully run object access test', async () => {
      const mockResult = {
        testType: 'salesforce-experience-cloud',
        testName: 'Object Access Test',
        passed: true,
        timestamp: new Date(),
        details: {
          findings: [],
          testedObjects: ['Account', 'Contact'],
          summary: {
            totalFindings: 0,
            unauthorizedAccess: 0,
          },
        },
      };

      tester.testObjectAccess.mockResolvedValue(mockResult as any);

      const result = await service.runObjectAccessTest({
        configId: 'config-1',
        objects: ['Account', 'Contact'],
      });

      expect(result.testType).toBe('object-access');
      expect(tester.testObjectAccess).toHaveBeenCalledWith(['Account', 'Contact']);
    });
  });

  describe('runFullAudit', () => {
    it('should successfully run full audit', async () => {
      const mockResults = [
        {
          testType: 'salesforce-experience-cloud',
          testName: 'Guest Access - Full Audit',
          passed: false,
          timestamp: new Date(),
          details: {},
        },
        {
          testType: 'salesforce-experience-cloud',
          testName: 'GraphQL - Full Audit',
          passed: true,
          timestamp: new Date(),
          details: {},
        },
      ];

      tester.runFullAudit.mockResolvedValue(mockResults as any);

      const results = await service.runFullAudit({ configId: 'config-1' });

      expect(results).toHaveLength(2);
      expect(results[0].testType).toBe('full-audit');
      expect(tester.runFullAudit).toHaveBeenCalled();
    });
  });

  describe('findAllResults', () => {
    it('should return all results when no configId provided', async () => {
      (service as any).results = [
        {
          id: 'result-1',
          configId: 'config-1',
          testName: 'Test 1',
          timestamp: new Date(),
          createdAt: new Date(),
        },
        {
          id: 'result-2',
          configId: 'config-2',
          testName: 'Test 2',
          timestamp: new Date(),
          createdAt: new Date(),
        },
      ];

      const results = await service.findAllResults();

      expect(results).toHaveLength(2);
    });

    it('should filter results by configId when provided', async () => {
      (service as any).results = [
        {
          id: 'result-1',
          configId: 'config-1',
          testName: 'Test 1',
          timestamp: new Date(),
          createdAt: new Date(),
        },
        {
          id: 'result-2',
          configId: 'config-2',
          testName: 'Test 2',
          timestamp: new Date(),
          createdAt: new Date(),
        },
      ];

      const results = await service.findAllResults('config-1');

      expect(results).toHaveLength(1);
      expect(results[0].configId).toBe('config-1');
    });
  });

  describe('findOneResult', () => {
    it('should return result by ID', async () => {
      (service as any).results = [
        {
          id: 'result-1',
          configId: 'config-1',
          testName: 'Test 1',
          timestamp: new Date(),
          createdAt: new Date(),
        },
      ];

      const result = await service.findOneResult('result-1');

      expect(result).toBeDefined();
      expect(result.id).toBe('result-1');
    });

    it('should throw NotFoundException for non-existent result', async () => {
      await expect(service.findOneResult('non-existent')).rejects.toThrow(NotFoundException);
    });
  });
});
