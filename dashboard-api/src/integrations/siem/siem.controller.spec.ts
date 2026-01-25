/**
 * SIEM Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { SIEMController } from './siem.controller';
import { SIEMService } from './siem.service';

describe('SIEMController', () => {
  let controller: SIEMController;
  let service: jest.Mocked<SIEMService>;

  const mockSIEMConfig = {
    type: 'splunk',
    enabled: true,
    endpoint: 'https://splunk.example.com',
    authentication: {},
    config: {},
  } as any;

  const mockFinding = {
    id: 'finding-1',
    source: 'scanner-1',
  };

  beforeEach(async () => {
    const mockService = {
      createIntegration: jest.fn(),
      findAllIntegrations: jest.fn(),
      findOneIntegration: jest.fn(),
      updateIntegration: jest.fn(),
      deleteIntegration: jest.fn(),
      testConnection: jest.fn(),
      sendFinding: jest.fn(),
      queryEvents: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [SIEMController],
      providers: [
        {
          provide: SIEMService,
          useValue: mockService,
        },
      ],
    }).compile();

    controller = module.get<SIEMController>(SIEMController);
    service = module.get(SIEMService) as jest.Mocked<SIEMService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('createIntegration', () => {
    it('should create SIEM integration', async () => {
      // Arrange
      service.createIntegration.mockResolvedValue(mockSIEMConfig as any);

      // Act
      const result = await controller.createIntegration(mockSIEMConfig);

      // Assert
      expect(result).toEqual(mockSIEMConfig);
      expect(service.createIntegration).toHaveBeenCalledWith(mockSIEMConfig);
    });
  });

  describe('findAllIntegrations', () => {
    it('should find all integrations', async () => {
      // Arrange
      service.findAllIntegrations.mockResolvedValue([mockSIEMConfig] as any);

      // Act
      const result = await controller.findAllIntegrations();

      // Assert
      expect(result).toEqual([mockSIEMConfig]);
      expect(service.findAllIntegrations).toHaveBeenCalledTimes(1);
    });
  });

  describe('findOneIntegration', () => {
    it('should find one integration', async () => {
      // Arrange
      service.findOneIntegration.mockResolvedValue(mockSIEMConfig as any);

      // Act
      const result = await controller.findOneIntegration('splunk');

      // Assert
      expect(result).toEqual(mockSIEMConfig);
      expect(service.findOneIntegration).toHaveBeenCalledWith('splunk');
    });
  });

  describe('updateIntegration', () => {
    it('should update integration', async () => {
      // Arrange
      const updates = { enabled: false };
      const updated = { ...mockSIEMConfig, ...updates };
      service.updateIntegration.mockResolvedValue(updated as any);

      // Act
      const result = await controller.updateIntegration('splunk', updates);

      // Assert
      expect(result).toEqual(updated);
      expect(service.updateIntegration).toHaveBeenCalledWith('splunk', updates);
    });
  });

  describe('deleteIntegration', () => {
    it('should delete integration', async () => {
      // Arrange
      service.deleteIntegration.mockResolvedValue(undefined);

      // Act
      const result = await controller.deleteIntegration('splunk');

      // Assert
      expect(result).toEqual({ message: 'Integration deleted' });
      expect(service.deleteIntegration).toHaveBeenCalledWith('splunk');
    });
  });

  describe('testConnection', () => {
    it('should test connection', async () => {
      // Arrange
      service.testConnection.mockResolvedValue(true);

      // Act
      const result = await controller.testConnection('splunk');

      // Assert
      expect(result).toEqual({ connected: true });
      expect(service.testConnection).toHaveBeenCalledWith('splunk');
    });
  });

  describe('sendFinding', () => {
    it('should send finding', async () => {
      // Arrange
      service.sendFinding.mockResolvedValue(true);

      // Act
      const result = await controller.sendFinding('splunk', mockFinding as any);

      // Assert
      expect(result).toEqual({ success: true });
      expect(service.sendFinding).toHaveBeenCalledWith('splunk', mockFinding);
    });
  });

  describe('queryEvents', () => {
    it('should query events', async () => {
      // Arrange
      const events = [{ id: 'event-1' }];
      service.queryEvents.mockResolvedValue(events as any);

      // Act
      const result = await controller.queryEvents('splunk', 'query', '2024-01-01', '2024-01-02');

      // Assert
      expect(result).toEqual(events);
      expect(service.queryEvents).toHaveBeenCalledWith('splunk', 'query', '2024-01-01', '2024-01-02');
    });
  });
});
