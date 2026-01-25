/**
 * Alerting Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { AlertingService } from './alerting.service';
import { NotificationsService } from '../notifications/notifications.service';
import { CreateAlertRuleDto } from './dto/create-alert-rule.dto';
import { CreateAlertChannelDto } from './dto/create-alert-channel.dto';
import * as fs from 'fs/promises';

// Mock dependencies
jest.mock('fs/promises');
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'mock-uuid-v4'),
}));

describe('AlertingService', () => {
  let service: AlertingService;
  let notificationsService: jest.Mocked<NotificationsService>;

  const createRuleDto: CreateAlertRuleDto = {
    name: 'High Severity Alert',
    enabled: true,
    conditions: [
      {
        field: 'severity',
        operator: 'in',
        value: ['high', 'critical'],
      },
    ],
    channels: [],
  };

  const createChannelDto: CreateAlertChannelDto = {
    name: 'Email Channel',
    type: 'email',
    enabled: true,
    config: {
      recipients: ['admin@example.com'],
    },
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const mockNotificationsService = {
      createNotification: jest.fn().mockResolvedValue({ id: 'notification-1' }),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AlertingService,
        {
          provide: NotificationsService,
          useValue: mockNotificationsService,
        },
      ],
    }).compile();

    service = module.get<AlertingService>(AlertingService);
    notificationsService = module.get(NotificationsService) as jest.Mocked<NotificationsService>;

    // Mock fs operations
    const fs = require('fs/promises');
    fs.mkdir = jest.fn().mockResolvedValue(undefined);
    fs.readFile = jest.fn().mockResolvedValue('[]');
    fs.writeFile = jest.fn().mockResolvedValue(undefined);

    // Clear data
    (service as any).rules = new Map();
    (service as any).channels = new Map();
    (service as any).alerts = [];
    
    // Mock loadData to prevent it from resetting our test data
    jest.spyOn(service as any, 'loadData').mockResolvedValue(undefined);
  });

  describe('createRule', () => {
    it('should successfully create an alert rule', async () => {
      // Act
      const result = await service.createRule(createRuleDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      expect(result.name).toBe(createRuleDto.name);
      expect(result.enabled).toBe(createRuleDto.enabled);
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should default enabled to true when not provided', async () => {
      // Arrange
      const dtoWithoutEnabled = { ...createRuleDto, enabled: undefined };

      // Act
      const result = await service.createRule(dtoWithoutEnabled);

      // Assert
      expect(result.enabled).toBe(true);
    });
  });

  describe('getRule', () => {
    beforeEach(async () => {
      const rule = await service.createRule(createRuleDto);
      (service as any).rules.set(rule.id, rule);
    });

    it('should return rule when found', async () => {
      // Arrange
      const rules = await service.getRules();
      const ruleId = rules[0].id;

      // Act
      const result = await service.getRuleById(ruleId);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBe(ruleId);
    });

    it('should throw NotFoundException when rule not found', async () => {
      // Act & Assert
      await expect(
        service.getRuleById('non-existent-id')
      ).rejects.toThrow();
    });
  });

  describe('createChannel', () => {
    it('should successfully create an alert channel', async () => {
      // Act
      const result = await service.createChannel(createChannelDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      expect(result.name).toBe(createChannelDto.name);
      expect(result.type).toBe(createChannelDto.type);
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });
  });

  describe('getChannel', () => {
    beforeEach(async () => {
      const channel = await service.createChannel(createChannelDto);
      (service as any).channels.set(channel.id, channel);
    });

    it('should return channel when found', async () => {
      // Arrange
      const channels = await service.getChannels();
      const channelId = channels[0].id;

      // Act
      const result = await service.getChannelById(channelId);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBe(channelId);
    });

    it('should throw NotFoundException when channel not found', async () => {
      // Act & Assert
      await expect(
        service.getChannelById('non-existent-id')
      ).rejects.toThrow();
    });
  });

  describe('getAllRules', () => {
    beforeEach(async () => {
      await service.createRule(createRuleDto);
      await service.createRule({ ...createRuleDto, name: 'Rule 2' });
    });

    it('should return all alert rules', async () => {
      // Act
      const result = await service.getRules();

      // Assert
      expect(result.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe('getAllChannels', () => {
    beforeEach(async () => {
      await service.createChannel(createChannelDto);
      await service.createChannel({ ...createChannelDto, name: 'Channel 2' });
    });

    it('should return all alert channels', async () => {
      // Act
      const result = await service.getChannels();

      // Assert
      expect(result.length).toBeGreaterThanOrEqual(2);
    });
  });
});
