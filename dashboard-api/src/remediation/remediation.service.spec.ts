/**
 * Remediation Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { RemediationService, RemediationRule } from './remediation.service';
import { TicketingService } from '../ticketing/ticketing.service';
import { ViolationEntity } from '../violations/entities/violation.entity';
import { ViolationSeverity, ViolationStatus, ViolationType } from '../violations/dto/create-violation.dto';

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

describe('RemediationService', () => {
  let service: RemediationService;
  let ticketingService: jest.Mocked<TicketingService>;

  const mockViolation: ViolationEntity = {
    id: 'violation-1',
    title: 'Test Violation',
    description: 'Test violation description',
    type: ViolationType.ACCESS_CONTROL,
    severity: ViolationSeverity.HIGH,
    application: 'app-1',
    team: 'team-1',
    status: ViolationStatus.OPEN,
    detectedAt: new Date(),
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockRemediationRule: RemediationRule = {
    id: 'rule-1',
    name: 'High Severity Auto-Ticket',
    conditions: {
      severity: [ViolationSeverity.HIGH, ViolationSeverity.CRITICAL],
      type: [ViolationType.ACCESS_CONTROL],
    },
    actions: [
      {
        type: 'create-ticket',
        metadata: { labels: ['security', 'high-priority'] },
      },
    ],
    enabled: true,
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const mockTicketingService = {
      findAllIntegrations: jest.fn().mockResolvedValue([
        { id: 'integration-1', enabled: true, type: 'jira' },
      ]),
      createTicket: jest.fn().mockResolvedValue({ id: 'ticket-1' }),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RemediationService,
        {
          provide: TicketingService,
          useValue: mockTicketingService,
        },
      ],
    }).compile();

    service = module.get<RemediationService>(RemediationService);
    ticketingService = module.get(TicketingService) as jest.Mocked<TicketingService>;

    // Clear rules
    (service as any).remediationRules = [];
  });

  describe('processViolation', () => {
    it('should process violation with matching rule', async () => {
      // Arrange
      (service as any).remediationRules = [mockRemediationRule];

      // Act
      await service.processViolation(mockViolation);

      // Assert
      expect(ticketingService.findAllIntegrations).toHaveBeenCalled();
    });

    it('should not process violation when no rules match', async () => {
      // Arrange
      (service as any).remediationRules = [
        {
          ...mockRemediationRule,
          conditions: { severity: [ViolationSeverity.LOW] },
        },
      ];

      // Act
      await service.processViolation(mockViolation);

      // Assert
      expect(ticketingService.findAllIntegrations).not.toHaveBeenCalled();
    });

    it('should not process violation when rule is disabled', async () => {
      // Arrange
      (service as any).remediationRules = [
        {
          ...mockRemediationRule,
          enabled: false,
        },
      ];

      // Act
      await service.processViolation(mockViolation);

      // Assert
      expect(ticketingService.findAllIntegrations).not.toHaveBeenCalled();
    });

    it('should match by severity', async () => {
      // Arrange
      (service as any).remediationRules = [
        {
          ...mockRemediationRule,
          conditions: { severity: [ViolationSeverity.HIGH] },
        },
      ];

      // Act
      await service.processViolation(mockViolation);

      // Assert
      expect(ticketingService.findAllIntegrations).toHaveBeenCalled();
    });

    it('should match by type', async () => {
      // Arrange
      (service as any).remediationRules = [
        {
          ...mockRemediationRule,
          conditions: { type: [ViolationType.ACCESS_CONTROL] },
        },
      ];

      // Act
      await service.processViolation(mockViolation);

      // Assert
      expect(ticketingService.findAllIntegrations).toHaveBeenCalled();
    });

    it('should match by application', async () => {
      // Arrange
      (service as any).remediationRules = [
        {
          ...mockRemediationRule,
          conditions: { application: ['app-1'] },
        },
      ];

      // Act
      await service.processViolation(mockViolation);

      // Assert
      expect(ticketingService.findAllIntegrations).toHaveBeenCalled();
    });

    it('should match by team', async () => {
      // Arrange
      (service as any).remediationRules = [
        {
          ...mockRemediationRule,
          conditions: { team: ['team-1'] },
        },
      ];

      // Act
      await service.processViolation(mockViolation);

      // Assert
      expect(ticketingService.findAllIntegrations).toHaveBeenCalled();
    });

    it('should execute multiple actions for matching rule', async () => {
      // Arrange
      (service as any).remediationRules = [
        {
          ...mockRemediationRule,
          actions: [
            { type: 'create-ticket' },
            { type: 'assign', target: 'user-1' },
            { type: 'notify' },
          ],
        },
      ];

      // Act
      await service.processViolation(mockViolation);

      // Assert
      expect(ticketingService.findAllIntegrations).toHaveBeenCalled();
    });

    it('should handle missing ticketing integration gracefully', async () => {
      // Arrange
      (service as any).remediationRules = [mockRemediationRule];
      ticketingService.findAllIntegrations.mockResolvedValue([]);

      // Act & Assert - should not throw
      await expect(service.processViolation(mockViolation)).resolves.not.toThrow();
    });
  });

  describe('mapSeverityToPriority', () => {
    it('should map critical severity to highest priority', () => {
      // Act
      const priority = (service as any).mapSeverityToPriority(ViolationSeverity.CRITICAL);

      // Assert
      expect(priority).toBe('highest');
    });

    it('should map high severity to high priority', () => {
      // Act
      const priority = (service as any).mapSeverityToPriority(ViolationSeverity.HIGH);

      // Assert
      expect(priority).toBe('high');
    });

    it('should map medium severity to medium priority', () => {
      // Act
      const priority = (service as any).mapSeverityToPriority(ViolationSeverity.MEDIUM);

      // Assert
      expect(priority).toBe('medium');
    });

    it('should map low severity to low priority', () => {
      // Act
      const priority = (service as any).mapSeverityToPriority(ViolationSeverity.LOW);

      // Assert
      expect(priority).toBe('low');
    });
  });
});
