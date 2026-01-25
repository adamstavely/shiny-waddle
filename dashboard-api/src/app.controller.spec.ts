/**
 * App Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { AppController } from './app.controller';

describe('AppController', () => {
  let controller: AppController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AppController],
    }).compile();

    controller = module.get<AppController>(AppController);
  });

  describe('getRoot', () => {
    it('should return root endpoint information', () => {
      // Act
      const result = controller.getRoot();

      // Assert
      expect(result).toEqual({
        message: 'Heimdall Dashboard API',
        version: '1.0.0',
        endpoints: {
          reports: '/api/reports',
        },
        frontend: 'http://localhost:5173',
        note: 'Access the dashboard UI at http://localhost:5173',
      });
    });
  });
});
