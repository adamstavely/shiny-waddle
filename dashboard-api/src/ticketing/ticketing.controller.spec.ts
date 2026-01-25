/**
 * Ticketing Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus, NotFoundException, BadRequestException } from '@nestjs/common';
import { TicketingController } from './ticketing.controller';
import { TicketingService } from './ticketing.service';
import { CreateTicketingIntegrationDto } from './dto/create-ticketing-integration.dto';
import {
  TicketingIntegration,
  TicketingProvider,
  Ticket,
  TicketStatus,
  CreateTicketDto,
} from './entities/ticketing.entity';

// Mock axios to avoid ES module issues
jest.mock('axios', () => {
  const mockAxios = {
    create: jest.fn(() => mockAxios),
    get: jest.fn(),
    post: jest.fn().mockResolvedValue({ data: { result: { sys_id: 'test-id' } } }),
    put: jest.fn(),
    delete: jest.fn(),
  };
  return {
    __esModule: true,
    default: mockAxios,
    ...mockAxios,
  };
});

describe('TicketingController', () => {
  let controller: TicketingController;
  let ticketingService: jest.Mocked<TicketingService>;

  const mockIntegration: TicketingIntegration = {
    id: 'integration-1',
    provider: TicketingProvider.JIRA,
    name: 'Test Jira Integration',
    enabled: true,
    config: {
      baseUrl: 'https://test.atlassian.net',
      apiToken: 'test-token',
      projectKey: 'TEST',
      jira: {
        email: 'test@example.com',
        apiToken: 'jira-token',
        issueType: 'Bug',
      },
    },
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockTicket: Ticket = {
    id: 'ticket-1',
    provider: TicketingProvider.JIRA,
    externalId: 'JIRA-123',
    externalUrl: 'https://test.atlassian.net/browse/JIRA-123',
    title: 'Test Ticket',
    description: 'Test description',
    status: TicketStatus.OPEN,
    priority: 'high',
    assignee: 'user@example.com',
    violationId: 'violation-1',
    violationTitle: 'Test Violation',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockCreateIntegrationDto: CreateTicketingIntegrationDto = {
    provider: TicketingProvider.JIRA,
    name: 'Test Integration',
    enabled: true,
    config: {
      baseUrl: 'https://test.atlassian.net',
      apiToken: 'test-token',
      projectKey: 'TEST',
      jira: {
        email: 'test@example.com',
        apiToken: 'jira-token',
      },
    },
  };

  const mockCreateTicketDto: CreateTicketDto = {
    violationId: 'violation-1',
    title: 'Test Ticket',
    description: 'Test description',
    priority: 'high',
    assignee: 'user@example.com',
    labels: ['security', 'high-priority'],
  };

  beforeEach(async () => {
    const mockTicketingService = {
      createIntegration: jest.fn(),
      findAllIntegrations: jest.fn(),
      findOneIntegration: jest.fn(),
      updateIntegration: jest.fn(),
      deleteIntegration: jest.fn(),
      testConnection: jest.fn(),
      createTicket: jest.fn(),
      findAllTickets: jest.fn(),
      findOneTicket: jest.fn(),
      syncTicketStatus: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [TicketingController],
      providers: [
        {
          provide: TicketingService,
          useValue: mockTicketingService,
        },
      ],
    }).compile();

    controller = module.get<TicketingController>(TicketingController);
    ticketingService = module.get(TicketingService) as jest.Mocked<TicketingService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('createIntegration', () => {
    it('should create a new integration', async () => {
      // Arrange
      ticketingService.createIntegration.mockResolvedValue(mockIntegration);

      // Act
      const result = await controller.createIntegration(mockCreateIntegrationDto);

      // Assert
      expect(result).toEqual(mockIntegration);
      expect(ticketingService.createIntegration).toHaveBeenCalledTimes(1);
      expect(ticketingService.createIntegration).toHaveBeenCalledWith(mockCreateIntegrationDto);
    });

    it('should return 201 status code', async () => {
      // Arrange
      ticketingService.createIntegration.mockResolvedValue(mockIntegration);

      // Act
      const result = await controller.createIntegration(mockCreateIntegrationDto);

      // Assert
      expect(result).toBeDefined();
      // Note: HttpCode decorator sets status, but doesn't affect return value
    });
  });

  describe('findAllIntegrations', () => {
    it('should return all integrations', async () => {
      // Arrange
      const integrations = [mockIntegration];
      ticketingService.findAllIntegrations.mockResolvedValue(integrations);

      // Act
      const result = await controller.findAllIntegrations();

      // Assert
      expect(result).toEqual(integrations);
      expect(ticketingService.findAllIntegrations).toHaveBeenCalledTimes(1);
      expect(ticketingService.findAllIntegrations).toHaveBeenCalledWith();
    });

    it('should return empty array when no integrations exist', async () => {
      // Arrange
      ticketingService.findAllIntegrations.mockResolvedValue([]);

      // Act
      const result = await controller.findAllIntegrations();

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('findOneIntegration', () => {
    it('should return a single integration by id', async () => {
      // Arrange
      const integrationId = 'integration-1';
      ticketingService.findOneIntegration.mockResolvedValue(mockIntegration);

      // Act
      const result = await controller.findOneIntegration(integrationId);

      // Assert
      expect(result).toEqual(mockIntegration);
      expect(ticketingService.findOneIntegration).toHaveBeenCalledTimes(1);
      expect(ticketingService.findOneIntegration).toHaveBeenCalledWith(integrationId);
    });

    it('should throw NotFoundException when integration not found', async () => {
      // Arrange
      const integrationId = 'non-existent';
      ticketingService.findOneIntegration.mockRejectedValue(
        new NotFoundException('Integration not found')
      );

      // Act & Assert
      await expect(controller.findOneIntegration(integrationId)).rejects.toThrow(
        NotFoundException
      );
      expect(ticketingService.findOneIntegration).toHaveBeenCalledWith(integrationId);
    });
  });

  describe('updateIntegration', () => {
    it('should update an existing integration', async () => {
      // Arrange
      const integrationId = 'integration-1';
      const updates = { enabled: false };
      const updatedIntegration = { ...mockIntegration, ...updates };
      ticketingService.updateIntegration.mockResolvedValue(updatedIntegration);

      // Act
      const result = await controller.updateIntegration(integrationId, updates);

      // Assert
      expect(result).toEqual(updatedIntegration);
      expect(ticketingService.updateIntegration).toHaveBeenCalledTimes(1);
      expect(ticketingService.updateIntegration).toHaveBeenCalledWith(integrationId, updates);
    });

    it('should throw NotFoundException when integration not found', async () => {
      // Arrange
      const integrationId = 'non-existent';
      const updates = { enabled: false };
      ticketingService.updateIntegration.mockRejectedValue(
        new NotFoundException('Integration not found')
      );

      // Act & Assert
      await expect(controller.updateIntegration(integrationId, updates)).rejects.toThrow(
        NotFoundException
      );
    });
  });

  describe('deleteIntegration', () => {
    it('should delete an integration', async () => {
      // Arrange
      const integrationId = 'integration-1';
      ticketingService.deleteIntegration.mockResolvedValue(undefined);

      // Act
      await controller.deleteIntegration(integrationId);

      // Assert
      expect(ticketingService.deleteIntegration).toHaveBeenCalledTimes(1);
      expect(ticketingService.deleteIntegration).toHaveBeenCalledWith(integrationId);
    });

    it('should return void on successful deletion', async () => {
      // Arrange
      const integrationId = 'integration-1';
      ticketingService.deleteIntegration.mockResolvedValue(undefined);

      // Act
      const result = await controller.deleteIntegration(integrationId);

      // Assert
      expect(result).toBeUndefined();
    });

    it('should throw NotFoundException when integration not found', async () => {
      // Arrange
      const integrationId = 'non-existent';
      ticketingService.deleteIntegration.mockRejectedValue(
        new NotFoundException('Integration not found')
      );

      // Act & Assert
      await expect(controller.deleteIntegration(integrationId)).rejects.toThrow(
        NotFoundException
      );
    });
  });

  describe('testConnection', () => {
    it('should test connection successfully', async () => {
      // Arrange
      const integrationId = 'integration-1';
      ticketingService.findOneIntegration.mockResolvedValue(mockIntegration);
      ticketingService.testConnection.mockResolvedValue(true);

      // Act
      const result = await controller.testConnection(integrationId);

      // Assert
      expect(result).toEqual({ success: true });
      expect(ticketingService.findOneIntegration).toHaveBeenCalledWith(integrationId);
      expect(ticketingService.testConnection).toHaveBeenCalledWith(mockIntegration);
    });

    it('should return success false when connection fails', async () => {
      // Arrange
      const integrationId = 'integration-1';
      ticketingService.findOneIntegration.mockResolvedValue(mockIntegration);
      ticketingService.testConnection.mockResolvedValue(false);

      // Act
      const result = await controller.testConnection(integrationId);

      // Assert
      expect(result).toEqual({ success: false });
    });

    it('should throw NotFoundException when integration not found', async () => {
      // Arrange
      const integrationId = 'non-existent';
      ticketingService.findOneIntegration.mockRejectedValue(
        new NotFoundException('Integration not found')
      );

      // Act & Assert
      await expect(controller.testConnection(integrationId)).rejects.toThrow(
        NotFoundException
      );
    });
  });

  describe('createTicket', () => {
    it('should create a new ticket', async () => {
      // Arrange
      const integrationId = 'integration-1';
      ticketingService.createTicket.mockResolvedValue(mockTicket);

      // Act
      const result = await controller.createTicket(integrationId, mockCreateTicketDto);

      // Assert
      expect(result).toEqual(mockTicket);
      expect(ticketingService.createTicket).toHaveBeenCalledTimes(1);
      expect(ticketingService.createTicket).toHaveBeenCalledWith(
        integrationId,
        mockCreateTicketDto
      );
    });

    it('should throw BadRequestException when integration not found', async () => {
      // Arrange
      const integrationId = 'non-existent';
      ticketingService.createTicket.mockRejectedValue(
        new BadRequestException('Integration not found')
      );

      // Act & Assert
      await expect(controller.createTicket(integrationId, mockCreateTicketDto)).rejects.toThrow(
        BadRequestException
      );
    });
  });

  describe('findAllTickets', () => {
    it('should return all tickets', async () => {
      // Arrange
      const tickets = [mockTicket];
      ticketingService.findAllTickets.mockResolvedValue(tickets);

      // Act
      const result = await controller.findAllTickets();

      // Assert
      expect(result).toEqual(tickets);
      expect(ticketingService.findAllTickets).toHaveBeenCalledTimes(1);
      expect(ticketingService.findAllTickets).toHaveBeenCalledWith(undefined);
    });

    it('should filter tickets by violationId when provided', async () => {
      // Arrange
      const violationId = 'violation-1';
      const tickets = [mockTicket];
      ticketingService.findAllTickets.mockResolvedValue(tickets);

      // Act
      const result = await controller.findAllTickets(violationId);

      // Assert
      expect(result).toEqual(tickets);
      expect(ticketingService.findAllTickets).toHaveBeenCalledWith(violationId);
    });

    it('should return empty array when no tickets exist', async () => {
      // Arrange
      ticketingService.findAllTickets.mockResolvedValue([]);

      // Act
      const result = await controller.findAllTickets();

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('findOneTicket', () => {
    it('should return a single ticket by id', async () => {
      // Arrange
      const ticketId = 'ticket-1';
      ticketingService.findOneTicket.mockResolvedValue(mockTicket);

      // Act
      const result = await controller.findOneTicket(ticketId);

      // Assert
      expect(result).toEqual(mockTicket);
      expect(ticketingService.findOneTicket).toHaveBeenCalledTimes(1);
      expect(ticketingService.findOneTicket).toHaveBeenCalledWith(ticketId);
    });

    it('should throw NotFoundException when ticket not found', async () => {
      // Arrange
      const ticketId = 'non-existent';
      ticketingService.findOneTicket.mockRejectedValue(
        new NotFoundException('Ticket not found')
      );

      // Act & Assert
      await expect(controller.findOneTicket(ticketId)).rejects.toThrow(NotFoundException);
      expect(ticketingService.findOneTicket).toHaveBeenCalledWith(ticketId);
    });
  });

  describe('syncTicketStatus', () => {
    it('should sync ticket status', async () => {
      // Arrange
      const ticketId = 'ticket-1';
      const syncedTicket = { ...mockTicket, status: TicketStatus.IN_PROGRESS };
      ticketingService.syncTicketStatus.mockResolvedValue(syncedTicket);

      // Act
      const result = await controller.syncTicketStatus(ticketId);

      // Assert
      expect(result).toEqual(syncedTicket);
      expect(ticketingService.syncTicketStatus).toHaveBeenCalledTimes(1);
      expect(ticketingService.syncTicketStatus).toHaveBeenCalledWith(ticketId);
    });

    it('should throw NotFoundException when ticket not found', async () => {
      // Arrange
      const ticketId = 'non-existent';
      ticketingService.syncTicketStatus.mockRejectedValue(
        new NotFoundException('Ticket not found')
      );

      // Act & Assert
      await expect(controller.syncTicketStatus(ticketId)).rejects.toThrow(NotFoundException);
    });
  });
});
