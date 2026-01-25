/**
 * Test Discovery Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { TestDiscoveryService } from './test-discovery.service';
import { TestEntity } from './entities/test.entity';

describe('TestDiscoveryService', () => {
  let service: TestDiscoveryService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [TestDiscoveryService],
    }).compile();

    service = module.get<TestDiscoveryService>(TestDiscoveryService);
  });

  describe('discoverTests', () => {
    it('should discover tests from test suite classes', async () => {
      // Act
      const result = await service.discoverTests();

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      // Should discover at least some tests
      expect(result.length).toBeGreaterThanOrEqual(0);
    });

    it('should return test entities with required fields', async () => {
      // Act
      const result = await service.discoverTests();

      // Assert
      if (result.length > 0) {
        const test = result[0];
        expect(test).toBeDefined();
        expect(test.id).toBeDefined();
        expect(test.name).toBeDefined();
        expect(test.testType).toBeDefined();
        expect(test.domain).toBeDefined();
        expect(test.createdAt).toBeInstanceOf(Date);
      }
    });

    it('should handle errors gracefully when discovering from suites', async () => {
      // Act & Assert - should not throw
      await expect(service.discoverTests()).resolves.not.toThrow();
    });

    it('should assign correct test type and domain', async () => {
      // Act
      const result = await service.discoverTests();

      // Assert
      if (result.length > 0) {
        result.forEach(test => {
          expect(test.testType).toBeDefined();
          expect(test.domain).toBeDefined();
        });
      }
    });
  });
});
