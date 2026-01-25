/**
 * Cloud Provider Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { CloudProviderController } from './cloud-provider.controller';
import { CloudProviderService } from './cloud-provider.service';

describe('CloudProviderController', () => {
  let controller: CloudProviderController;
  let service: jest.Mocked<CloudProviderService>;

  const mockConfig = {
    provider: 'aws',
    enabled: true,
    config: {},
  } as any;

  beforeEach(async () => {
    const mockService = {
      createProvider: jest.fn(),
      findAllProviders: jest.fn(),
      findOneProvider: jest.fn(),
      updateProvider: jest.fn(),
      deleteProvider: jest.fn(),
      normalizeFindings: jest.fn(),
      aggregateFindings: jest.fn(),
      getProviderSummaries: jest.fn(),
      findCrossCloudDuplicates: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [CloudProviderController],
      providers: [
        {
          provide: CloudProviderService,
          useValue: mockService,
        },
      ],
    }).compile();

    controller = module.get<CloudProviderController>(CloudProviderController);
    service = module.get(CloudProviderService) as jest.Mocked<CloudProviderService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('createProvider', () => {
    it('should create provider', async () => {
      // Arrange
      service.createProvider.mockResolvedValue(mockConfig as any);

      // Act
      const result = await controller.createProvider(mockConfig);

      // Assert
      expect(result).toEqual(mockConfig);
      expect(service.createProvider).toHaveBeenCalledWith(mockConfig);
    });
  });

  describe('findAllProviders', () => {
    it('should find all providers', async () => {
      // Arrange
      service.findAllProviders.mockResolvedValue([mockConfig] as any);

      // Act
      const result = await controller.findAllProviders();

      // Assert
      expect(result).toEqual([mockConfig]);
      expect(service.findAllProviders).toHaveBeenCalledTimes(1);
    });
  });

  describe('findOneProvider', () => {
    it('should find one provider', async () => {
      // Arrange
      service.findOneProvider.mockResolvedValue(mockConfig as any);

      // Act
      const result = await controller.findOneProvider('aws');

      // Assert
      expect(result).toEqual(mockConfig);
      expect(service.findOneProvider).toHaveBeenCalledWith('aws');
    });
  });

  describe('updateProvider', () => {
    it('should update provider', async () => {
      // Arrange
      const updates = { config: { updated: true } };
      const updated = { ...mockConfig, ...updates };
      service.updateProvider.mockResolvedValue(updated as any);

      // Act
      const result = await controller.updateProvider('aws', updates);

      // Assert
      expect(result).toEqual(updated);
      expect(service.updateProvider).toHaveBeenCalledWith('aws', updates);
    });
  });

  describe('deleteProvider', () => {
    it('should delete provider', async () => {
      // Arrange
      service.deleteProvider.mockResolvedValue(undefined);

      // Act
      const result = await controller.deleteProvider('aws');

      // Assert
      expect(result).toEqual({ message: 'Provider deleted' });
      expect(service.deleteProvider).toHaveBeenCalledWith('aws');
    });
  });

  describe('normalizeFindings', () => {
    it('should normalize findings', async () => {
      // Arrange
      const rawFindings = [{ id: 'finding-1' }];
      const normalized = [{ id: 'finding-1', normalized: true }];
      service.normalizeFindings.mockResolvedValue(normalized as any);

      // Act
      const result = await controller.normalizeFindings('aws', rawFindings);

      // Assert
      expect(result).toEqual(normalized);
      expect(service.normalizeFindings).toHaveBeenCalledWith('aws', rawFindings);
    });
  });

  describe('aggregateFindings', () => {
    it('should aggregate findings', async () => {
      // Arrange
      const providerFindings = { aws: [{ id: 'finding-1' }] };
      const aggregated = { total: 1 };
      service.aggregateFindings.mockResolvedValue(aggregated as any);

      // Act
      const result = await controller.aggregateFindings(providerFindings);

      // Assert
      expect(result).toEqual(aggregated);
      expect(service.aggregateFindings).toHaveBeenCalledWith(providerFindings);
    });
  });

  describe('getProviderSummaries', () => {
    it('should get provider summaries', async () => {
      // Arrange
      const findings = [{ id: 'finding-1', provider: 'aws' }];
      const summaries = new Map([['aws', { count: 1 }]]);
      service.getProviderSummaries.mockResolvedValue(summaries as any);

      // Act
      const result = await controller.getProviderSummaries(findings as any);

      // Assert
      expect(result).toEqual({ aws: { count: 1 } });
      expect(service.getProviderSummaries).toHaveBeenCalledWith(findings);
    });
  });

  describe('findCrossCloudDuplicates', () => {
    it('should find cross-cloud duplicates', async () => {
      // Arrange
      const findings = [{ id: 'finding-1' }];
      const duplicates = new Map([['finding-1', ['finding-2']]]);
      service.findCrossCloudDuplicates.mockResolvedValue(duplicates as any);

      // Act
      const result = await controller.findCrossCloudDuplicates(findings as any);

      // Assert
      expect(result).toEqual({ 'finding-1': ['finding-2'] });
      expect(service.findCrossCloudDuplicates).toHaveBeenCalledWith(findings);
    });
  });
});
