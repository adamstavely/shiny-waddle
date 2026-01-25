/**
 * Dashboard SSE Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { DashboardSSEController } from './dashboard-sse.controller';
import { DashboardSSEGateway } from './dashboard-sse.gateway';

describe('DashboardSSEController', () => {
  let controller: DashboardSSEController;
  let sseGateway: jest.Mocked<DashboardSSEGateway>;

  const mockResponse = {
    setHeader: jest.fn(),
    write: jest.fn(),
    end: jest.fn(),
    on: jest.fn(),
  };

  const mockRequest = {
    on: jest.fn(),
    close: false,
  };

  beforeEach(async () => {
    const mockSSEGateway = {
      registerClient: jest.fn(),
      unregisterClient: jest.fn(),
      getUpdates: jest.fn(() => ({
        subscribe: jest.fn(() => ({ unsubscribe: jest.fn() })),
      })),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [DashboardSSEController],
      providers: [
        {
          provide: DashboardSSEGateway,
          useValue: mockSSEGateway,
        },
      ],
    }).compile();

    controller = module.get<DashboardSSEController>(DashboardSSEController);
    sseGateway = module.get(DashboardSSEGateway) as jest.Mocked<DashboardSSEGateway>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('streamDashboard', () => {
    it('should set up SSE stream', async () => {
      // Arrange
      const mockSend = jest.fn();
      sseGateway.registerClient.mockImplementation((id, send) => {
        send('data: test\n\n');
      });

      // Mock setInterval and clearInterval
      jest.useFakeTimers();
      const setIntervalSpy = jest.spyOn(global, 'setInterval');
      const clearIntervalSpy = jest.spyOn(global, 'clearInterval');

      // Act
      await controller.streamDashboard(mockResponse as any, mockRequest as any);

      // Assert
      expect(mockResponse.setHeader).toHaveBeenCalledWith('Content-Type', 'text/event-stream');
      expect(mockResponse.setHeader).toHaveBeenCalledWith('Cache-Control', 'no-cache');
      expect(mockResponse.setHeader).toHaveBeenCalledWith('Connection', 'keep-alive');
      expect(sseGateway.registerClient).toHaveBeenCalled();
      expect(setIntervalSpy).toHaveBeenCalled();

      // Cleanup
      jest.useRealTimers();
    });
  });
});
