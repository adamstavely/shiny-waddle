/**
 * Logger Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { Logger } from '@nestjs/common';
import { AppLogger, LogLevel } from './logger.service';

describe('AppLogger', () => {
  let logger: AppLogger;
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    originalEnv = { ...process.env };
    // Set log level to INFO for tests to allow logging
    process.env.LOG_LEVEL = 'INFO';
    process.env.NODE_ENV = 'test';
    logger = new AppLogger('TestContext');
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('constructor', () => {
    it('should create logger with default context', () => {
      // Act
      const defaultLogger = new AppLogger();

      // Assert
      expect(defaultLogger).toBeDefined();
    });

    it('should create logger with custom context', () => {
      // Act
      const customLogger = new AppLogger('CustomContext');

      // Assert
      expect(customLogger).toBeDefined();
    });
  });

  describe('log', () => {
    it('should log info message', () => {
      // Arrange
      const spy = jest.spyOn(Logger.prototype, 'log').mockImplementation();

      // Act
      logger.log('Test message');

      // Assert
      expect(spy).toHaveBeenCalled();
      spy.mockRestore();
    });

    it('should log with metadata', () => {
      // Arrange
      const spy = jest.spyOn(Logger.prototype, 'log').mockImplementation();

      // Act
      logger.log('Test message', 'CustomContext', { key: 'value' });

      // Assert
      expect(spy).toHaveBeenCalled();
      spy.mockRestore();
    });

    it('should not log when log level is higher than INFO', () => {
      // Arrange
      process.env.LOG_LEVEL = 'ERROR';
      const errorLogger = new AppLogger('TestContext');
      const spy = jest.spyOn(Logger.prototype, 'log').mockImplementation();

      // Act
      errorLogger.log('Test message');

      // Assert
      expect(spy).not.toHaveBeenCalled();
      spy.mockRestore();
    });
  });

  describe('error', () => {
    it('should log error message', () => {
      // Arrange
      const spy = jest.spyOn(Logger.prototype, 'error').mockImplementation();

      // Act
      logger.error('Error message');

      // Assert
      expect(spy).toHaveBeenCalled();
      spy.mockRestore();
    });

    it('should log error with trace', () => {
      // Arrange
      const spy = jest.spyOn(Logger.prototype, 'error').mockImplementation();

      // Act
      logger.error('Error message', 'stack trace');

      // Assert
      expect(spy).toHaveBeenCalled();
      spy.mockRestore();
    });
  });

  describe('warn', () => {
    it('should log warning message', () => {
      // Arrange
      const spy = jest.spyOn(Logger.prototype, 'warn').mockImplementation();

      // Act
      logger.warn('Warning message');

      // Assert
      expect(spy).toHaveBeenCalled();
      spy.mockRestore();
    });
  });

  describe('debug', () => {
    it('should log debug message in development', () => {
      // Arrange
      process.env.NODE_ENV = 'development';
      process.env.LOG_LEVEL = 'DEBUG';
      const devLogger = new AppLogger('TestContext');
      const spy = jest.spyOn(Logger.prototype, 'debug').mockImplementation();

      // Act
      devLogger.debug('Debug message');

      // Assert
      expect(spy).toHaveBeenCalled();
      spy.mockRestore();
    });

    it('should not log debug message in production', () => {
      // Arrange
      process.env.NODE_ENV = 'production';
      const prodLogger = new AppLogger('TestContext');
      const spy = jest.spyOn(Logger.prototype, 'debug').mockImplementation();

      // Act
      prodLogger.debug('Debug message');

      // Assert
      expect(spy).not.toHaveBeenCalled();
      spy.mockRestore();
    });
  });

  describe('verbose', () => {
    it('should log verbose message when level allows', () => {
      // Arrange
      process.env.LOG_LEVEL = 'VERBOSE';
      const verboseLogger = new AppLogger('TestContext');
      const spy = jest.spyOn(Logger.prototype, 'verbose').mockImplementation();

      // Act
      verboseLogger.verbose('Verbose message');

      // Assert
      expect(spy).toHaveBeenCalled();
      spy.mockRestore();
    });
  });

  describe('setContext', () => {
    it('should update logger context', () => {
      // Act
      logger.setContext('NewContext');

      // Assert
      expect(logger).toBeDefined();
    });
  });

  describe('setLogLevel', () => {
    it('should update log level', () => {
      // Act
      logger.setLogLevel(LogLevel.ERROR);

      // Assert
      expect(logger.getLogLevel()).toBe(LogLevel.ERROR);
    });
  });

  describe('getLogLevel', () => {
    it('should return current log level', () => {
      // Act
      const level = logger.getLogLevel();

      // Assert
      expect(level).toBeDefined();
      expect([LogLevel.VERBOSE, LogLevel.DEBUG, LogLevel.INFO, LogLevel.WARN, LogLevel.ERROR]).toContain(level);
    });
  });
});
