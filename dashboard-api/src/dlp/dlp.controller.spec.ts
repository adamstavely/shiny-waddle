/**
 * DLP Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus } from '@nestjs/common';
import { DLPController } from './dlp.controller';
import { DLPService } from './dlp.service';

describe('DLPController', () => {
  let controller: DLPController;
  let dlpService: jest.Mocked<DLPService>;

  const mockTestResult = {
    passed: true,
    testType: 'dlp' as const,
    testName: 'DLP Test',
    timestamp: new Date(),
    details: {},
  };

  beforeEach(async () => {
    const mockDLPService = {
      testExfiltration: jest.fn(),
      validateAPIResponse: jest.fn(),
      testQueryValidation: jest.fn(),
      testBulkExport: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [DLPController],
      providers: [
        {
          provide: DLPService,
          useValue: mockDLPService,
        },
      ],
    }).compile();

    controller = module.get<DLPController>(DLPController);
    dlpService = module.get(DLPService) as jest.Mocked<DLPService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('testExfiltration', () => {
    it('should test exfiltration with applicationId', async () => {
      // Arrange
      const dto = {
        applicationId: 'app-1',
      };
      dlpService.testExfiltration.mockResolvedValue(mockTestResult);

      // Act
      const result = await controller.testExfiltration(dto);

      // Assert
      expect(result).toEqual(mockTestResult);
      expect(dlpService.testExfiltration).toHaveBeenCalledWith(dto);
    });

    it('should test exfiltration with user and dataOperation', async () => {
      // Arrange
      const dto = {
        user: { id: 'user-1' },
        dataOperation: { type: 'export' },
      };
      dlpService.testExfiltration.mockResolvedValue(mockTestResult);

      // Act
      const result = await controller.testExfiltration(dto);

      // Assert
      expect(result).toEqual(mockTestResult);
      expect(dlpService.testExfiltration).toHaveBeenCalledWith(dto);
    });
  });

  describe('validateAPIResponse', () => {
    it('should validate API response with applicationId', async () => {
      // Arrange
      const dto = {
        applicationId: 'app-1',
        apiResponse: { data: 'test' },
      };
      dlpService.validateAPIResponse.mockResolvedValue(mockTestResult);

      // Act
      const result = await controller.validateAPIResponse(dto);

      // Assert
      expect(result).toEqual(mockTestResult);
      expect(dlpService.validateAPIResponse).toHaveBeenCalledWith(dto);
    });

    it('should validate API response with allowedFields and piiFields', async () => {
      // Arrange
      const dto = {
        apiResponse: { data: 'test' },
        allowedFields: ['field1'],
        piiFields: ['ssn'],
      };
      dlpService.validateAPIResponse.mockResolvedValue(mockTestResult);

      // Act
      const result = await controller.validateAPIResponse(dto);

      // Assert
      expect(result).toEqual(mockTestResult);
      expect(dlpService.validateAPIResponse).toHaveBeenCalledWith(dto);
    });
  });

  describe('testQueryValidation', () => {
    it('should test query validation with applicationId', async () => {
      // Arrange
      const dto = {
        applicationId: 'app-1',
        query: { sql: 'SELECT * FROM users' },
        user: { id: 'user-1' },
      };
      dlpService.testQueryValidation.mockResolvedValue(mockTestResult);

      // Act
      const result = await controller.testQueryValidation(dto);

      // Assert
      expect(result).toEqual(mockTestResult);
      expect(dlpService.testQueryValidation).toHaveBeenCalledWith(dto);
    });

    it('should test query validation with expectedFields', async () => {
      // Arrange
      const dto = {
        query: { sql: 'SELECT * FROM users' },
        user: { id: 'user-1' },
        expectedFields: ['id', 'name'],
      };
      dlpService.testQueryValidation.mockResolvedValue(mockTestResult);

      // Act
      const result = await controller.testQueryValidation(dto);

      // Assert
      expect(result).toEqual(mockTestResult);
      expect(dlpService.testQueryValidation).toHaveBeenCalledWith(dto);
    });
  });

  describe('testBulkExport', () => {
    it('should test bulk export with applicationId', async () => {
      // Arrange
      const dto = {
        applicationId: 'app-1',
      };
      dlpService.testBulkExport.mockResolvedValue(mockTestResult);

      // Act
      const result = await controller.testBulkExport(dto);

      // Assert
      expect(result).toEqual(mockTestResult);
      expect(dlpService.testBulkExport).toHaveBeenCalledWith(dto);
    });

    it('should test bulk export with user and exportRequest', async () => {
      // Arrange
      const dto = {
        user: { id: 'user-1' },
        exportRequest: {
          type: 'csv',
          recordCount: 1000,
        },
      };
      dlpService.testBulkExport.mockResolvedValue(mockTestResult);

      // Act
      const result = await controller.testBulkExport(dto);

      // Assert
      expect(result).toEqual(mockTestResult);
      expect(dlpService.testBulkExport).toHaveBeenCalledWith(dto);
    });
  });
});
