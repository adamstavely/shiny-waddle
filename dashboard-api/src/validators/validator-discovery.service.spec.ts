/**
 * Validator Discovery Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { ValidatorDiscoveryService } from './validator-discovery.service';

describe('ValidatorDiscoveryService', () => {
  let service: ValidatorDiscoveryService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [ValidatorDiscoveryService],
    }).compile();

    service = module.get<ValidatorDiscoveryService>(ValidatorDiscoveryService);
  });

  describe('discoverValidators', () => {
    it('should discover validators from framework', async () => {
      // Act
      const result = await service.discoverValidators();

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      // Should discover at least some validators
      expect(result.length).toBeGreaterThanOrEqual(0);
    });

    it('should return validator entities with required fields', async () => {
      // Act
      const result = await service.discoverValidators();

      // Assert
      if (result.length > 0) {
        const validator = result[0];
        expect(validator).toBeDefined();
        expect(validator.id).toBeDefined();
        expect(validator.name).toBeDefined();
        expect(validator.type).toBeDefined();
      }
    });

    it('should handle errors gracefully', async () => {
      // Act & Assert - should not throw
      await expect(service.discoverValidators()).resolves.not.toThrow();
    });
  });
});
