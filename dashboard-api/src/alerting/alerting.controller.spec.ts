/**
 * Alerting Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { AlertingController } from './alerting.controller';
import { AlertingService } from './alerting.service';
import { CreateAlertRuleDto } from './dto/create-alert-rule.dto';
import { CreateAlertChannelDto } from './dto/create-alert-channel.dto';
import { UpdateAlertRuleDto } from './dto/update-alert-rule.dto';
import { UpdateAlertChannelDto } from './dto/update-alert-channel.dto';
import { AlertQueryDto } from './dto/alert-query.dto';

describe('AlertingController', () => {
  let controller: AlertingController;
  let service: jest.Mocked<AlertingService>;

  const mockRule = {
    id: 'rule-1',
    name: 'High Severity Alert',
    enabled: true,
    conditions: [{ field: 'severity', operator: 'in', value: ['high'] }],
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockChannel = {
    id: 'channel-1',
    name: 'Email Channel',
    type: 'email',
    enabled: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockAlert = {
    id: 'alert-1',
    ruleId: 'rule-1',
    findingId: 'finding-1',
    status: 'pending' as const,
    createdAt: new Date(),
  };

  beforeEach(async () => {
    const mockService = {
      createRule: jest.fn().mockResolvedValue(mockRule),
      getRules: jest.fn().mockResolvedValue([mockRule]),
      getAllRules: jest.fn().mockResolvedValue([mockRule]),
      getRuleById: jest.fn().mockResolvedValue(mockRule),
      updateRule: jest.fn().mockResolvedValue(mockRule),
      deleteRule: jest.fn().mockResolvedValue(undefined),
      testRule: jest.fn().mockResolvedValue([mockAlert]),
      createChannel: jest.fn().mockResolvedValue(mockChannel),
      getChannels: jest.fn().mockResolvedValue([mockChannel]),
      getChannelById: jest.fn().mockResolvedValue(mockChannel),
      updateChannel: jest.fn().mockResolvedValue(mockChannel),
      deleteChannel: jest.fn().mockResolvedValue(undefined),
      queryAlerts: jest.fn().mockResolvedValue([mockAlert]),
      getAlertById: jest.fn().mockResolvedValue(mockAlert),
      retryAlert: jest.fn().mockResolvedValue(mockAlert),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AlertingController],
      providers: [
        {
          provide: AlertingService,
          useValue: mockService,
        },
      ],
    }).compile();

    controller = module.get<AlertingController>(AlertingController);
    service = module.get(AlertingService) as jest.Mocked<AlertingService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('createRule', () => {
    it('should call service.createRule with DTO', async () => {
      // Arrange
      const dto: CreateAlertRuleDto = {
        name: 'Test Rule',
        enabled: true,
        conditions: [{ field: 'severity', operator: 'in', value: ['high'] }],
        channels: [],
      };

      // Act
      await controller.createRule(dto);

      // Assert
      expect(service.createRule).toHaveBeenCalledWith(dto);
    });

    it('should return created rule', async () => {
      // Arrange
      const dto: CreateAlertRuleDto = {
        name: 'Test Rule',
        enabled: true,
        conditions: [{ field: 'severity', operator: 'in', value: ['high'] }],
        channels: [],
      };

      // Act
      const result = await controller.createRule(dto);

      // Assert
      expect(result).toEqual(mockRule);
    });
  });

  describe('getRules', () => {
    it('should call service.getRules', async () => {
      // Act
      await controller.getRules();

      // Assert
      expect(service.getRules).toHaveBeenCalledTimes(1);
    });

    it('should return rules array', async () => {
      // Act
      const result = await controller.getRules();

      // Assert
      expect(result).toEqual([mockRule]);
    });
  });

  describe('getRule', () => {
    it('should call service.getRuleById with id', async () => {
      // Act
      await controller.getRule('rule-1');

      // Assert
      expect(service.getRuleById).toHaveBeenCalledWith('rule-1');
    });
  });

  describe('createChannel', () => {
    it('should call service.createChannel with DTO', async () => {
      // Arrange
      const dto: CreateAlertChannelDto = {
        name: 'Test Channel',
        type: 'email',
        enabled: true,
        config: { recipients: ['test@example.com'] },
      };

      // Act
      await controller.createChannel(dto);

      // Assert
      expect(service.createChannel).toHaveBeenCalledWith(dto);
    });
  });

  describe('getChannels', () => {
    it('should call service.getChannels', async () => {
      // Act
      await controller.getChannels();

      // Assert
      expect(service.getChannels).toHaveBeenCalledTimes(1);
    });
  });

  describe('getChannel', () => {
    it('should call service.getChannelById with id', async () => {
      // Act
      await controller.getChannel('channel-1');

      // Assert
      expect(service.getChannelById).toHaveBeenCalledWith('channel-1');
    });
  });

  describe('getAlerts', () => {
    it('should call service.queryAlerts with query', async () => {
      // Arrange
      const query: AlertQueryDto = { status: 'pending' };

      // Act
      await controller.getAlerts(query);

      // Assert
      expect(service.queryAlerts).toHaveBeenCalledWith(query);
    });
  });
});
