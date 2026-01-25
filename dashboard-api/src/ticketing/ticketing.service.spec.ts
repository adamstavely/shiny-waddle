/**
 * Ticketing Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException, BadRequestException } from '@nestjs/common';
import { TicketingService } from './ticketing.service';
import { CreateTicketingIntegrationDto } from './dto/create-ticketing-integration.dto';
import { CreateTicketDto } from './entities/ticketing.entity';
import * as fs from 'fs/promises';

// Mock dependencies
jest.mock('fs/promises');
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'mock-uuid-v4'),
}));
jest.mock('axios', () => {
  const mockAxios = {
    create: jest.fn(() => mockAxios),
    get: jest.fn().mockResolvedValue({ status: 200, data: {} }),
    post: jest.fn().mockResolvedValue({ status: 201, data: { id: 'ticket-1' } }),
    put: jest.fn().mockResolvedValue({ status: 200, data: {} }),
    delete: jest.fn().mockResolvedValue({ status: 204 }),
  };
  return {
    __esModule: true,
    default: mockAxios,
  };
});

describe('TicketingService', () => {
  let service: TicketingService;

  const createIntegrationDto: CreateTicketingIntegrationDto = {
    name: 'Test Integration',
    provider: 'jira' as any,
    enabled: true,
    config: {
      baseUrl: 'https://test.atlassian.net',
      apiToken: 'token-123',
      projectKey: 'TEST',
      jira: {
        email: 'test@example.com',
        apiToken: 'token-123',
      },
    },
  };

  const createTicketDto: CreateTicketDto = {
    violationId: 'violation-1',
    title: 'Test Ticket',
    description: 'Test ticket description',
    priority: 'high',
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [TicketingService],
    }).compile();

    service = module.get<TicketingService>(TicketingService);

    // Mock fs operations
    const fs = require('fs/promises');
    fs.mkdir = jest.fn().mockResolvedValue(undefined);
    fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));
    fs.writeFile = jest.fn().mockResolvedValue(undefined);

    // Clear data
    (service as any).integrations = [];
    (service as any).tickets = [];
    
    // Mock loadData to prevent it from resetting our test data
    jest.spyOn(service as any, 'loadData').mockResolvedValue(undefined);
  });

  describe('createIntegration', () => {
    it('should successfully create a ticketing integration', async () => {
      // Arrange
      (service as any).integrations = [];

      // Act
      const result = await service.createIntegration(createIntegrationDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      expect(result.name).toBe(createIntegrationDto.name);
      expect(result.provider).toBe(createIntegrationDto.provider);
      expect(result.enabled).toBe(createIntegrationDto.enabled);
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });
  });

  describe('findAllIntegrations', () => {
    beforeEach(() => {
      (service as any).integrations = [
        {
          id: 'integration-1',
          name: 'Integration 1',
          provider: 'jira',
          enabled: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ];
    });

    it('should return all integrations', async () => {
      // Act
      const result = await service.findAllIntegrations();

      // Assert
      expect(result.length).toBe(1);
    });
  });

  describe('findOneIntegration', () => {
    beforeEach(() => {
      (service as any).integrations = [
        {
          id: 'integration-1',
          name: 'Integration 1',
          provider: 'jira',
          enabled: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ];
    });

    it('should return integration when found', async () => {
      // Act
      const result = await service.findOneIntegration('integration-1');

      // Assert
      expect(result.id).toBe('integration-1');
    });

    it('should throw NotFoundException when integration not found', async () => {
      // Act & Assert
      await expect(
        service.findOneIntegration('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('createTicket', () => {
    beforeEach(() => {
      (service as any).integrations = [
        {
          id: 'integration-1',
          name: 'Integration 1',
          provider: 'jira',
          enabled: true,
          config: {
            baseUrl: 'https://test.atlassian.net',
            apiToken: 'token-123',
            projectKey: 'TEST',
            jira: {
              email: 'test@example.com',
              apiToken: 'token-123',
            },
          },
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ];
      (service as any).tickets = [];
    });

    it('should successfully create a ticket', async () => {
      // Act
      const result = await service.createTicket('integration-1', createTicketDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw NotFoundException when integration not found', async () => {
      // Act & Assert
      await expect(
        service.createTicket('non-existent-id', createTicketDto)
      ).rejects.toThrow(NotFoundException);
    });
  });
});
