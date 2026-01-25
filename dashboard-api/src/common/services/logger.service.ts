import { Injectable, Logger, LoggerService } from '@nestjs/common';

/**
 * Log levels in order of severity (higher number = more severe)
 */
export enum LogLevel {
  VERBOSE = 0,
  DEBUG = 1,
  INFO = 2,
  WARN = 3,
  ERROR = 4,
}

/**
 * Get current log level from environment
 * Defaults: production=WARN, development=DEBUG, test=ERROR
 */
function getLogLevel(): LogLevel {
  const envLevel = process.env.LOG_LEVEL?.toUpperCase();
  if (envLevel) {
    const levelMap: Record<string, LogLevel> = {
      VERBOSE: LogLevel.VERBOSE,
      DEBUG: LogLevel.DEBUG,
      INFO: LogLevel.INFO,
      WARN: LogLevel.WARN,
      ERROR: LogLevel.ERROR,
    };
    return levelMap[envLevel] ?? LogLevel.WARN;
  }

  // Default based on NODE_ENV
  if (process.env.NODE_ENV === 'production') {
    return LogLevel.WARN;
  } else if (process.env.NODE_ENV === 'test') {
    return LogLevel.ERROR;
  }
  return LogLevel.DEBUG;
}

/**
 * Format log entry as JSON for production
 */
function formatLogEntry(
  level: string,
  message: string,
  context: string,
  trace?: string,
  metadata?: Record<string, any>,
): string {
  const isProduction = process.env.NODE_ENV === 'production';
  const useJsonFormat = process.env.LOG_FORMAT === 'json' || isProduction;

  if (useJsonFormat) {
    const entry: Record<string, any> = {
      timestamp: new Date().toISOString(),
      level: level.toUpperCase(),
      context,
      message,
    };

    if (trace) {
      entry.trace = trace;
    }

    if (metadata && Object.keys(metadata).length > 0) {
      entry.metadata = metadata;
    }

    return JSON.stringify(entry);
  }

  // Human-readable format for development
  const parts = [`[${level.toUpperCase()}]`, `[${context}]`, message];
  if (trace) {
    parts.push(`\n${trace}`);
  }
  if (metadata && Object.keys(metadata).length > 0) {
    parts.push(`\nMetadata: ${JSON.stringify(metadata, null, 2)}`);
  }
  return parts.join(' ');
}

/**
 * Structured logging service for the dashboard API
 * Provides consistent logging with context, levels, and structured data
 */
@Injectable()
export class AppLogger implements LoggerService {
  private logger: Logger;
  private context: string;
  private currentLogLevel: LogLevel;

  constructor(context?: string) {
    this.context = context || 'App';
    this.logger = new Logger(this.context);
    this.currentLogLevel = getLogLevel();
  }

  /**
   * Check if a log level should be logged
   */
  private shouldLog(level: LogLevel): boolean {
    return level >= this.currentLogLevel;
  }

  /**
   * Log informational message
   */
  log(message: string, context?: string, metadata?: Record<string, any>): void {
    if (!this.shouldLog(LogLevel.INFO)) return;
    const logContext = context || this.context;
    const formatted = formatLogEntry('info', message, logContext, undefined, metadata);
    this.logger.log(formatted);
  }

  /**
   * Log error message
   */
  error(message: string, trace?: string, context?: string, metadata?: Record<string, any>): void {
    if (!this.shouldLog(LogLevel.ERROR)) return;
    const logContext = context || this.context;
    const formatted = formatLogEntry('error', message, logContext, trace, metadata);
    this.logger.error(formatted);
  }

  /**
   * Log warning message
   */
  warn(message: string, context?: string, metadata?: Record<string, any>): void {
    if (!this.shouldLog(LogLevel.WARN)) return;
    const logContext = context || this.context;
    const formatted = formatLogEntry('warn', message, logContext, undefined, metadata);
    this.logger.warn(formatted);
  }

  /**
   * Log debug message
   */
  debug(message: string, context?: string, metadata?: Record<string, any>): void {
    if (!this.shouldLog(LogLevel.DEBUG)) return;
    const logContext = context || this.context;
    const formatted = formatLogEntry('debug', message, logContext, undefined, metadata);
    this.logger.debug(formatted);
  }

  /**
   * Log verbose message
   */
  verbose(message: string, context?: string, metadata?: Record<string, any>): void {
    if (!this.shouldLog(LogLevel.VERBOSE)) return;
    const logContext = context || this.context;
    const formatted = formatLogEntry('verbose', message, logContext, undefined, metadata);
    this.logger.verbose(formatted);
  }

  /**
   * Set logger context
   */
  setContext(context: string): void {
    this.context = context;
    this.logger = new Logger(context);
  }

  /**
   * Get current log level
   */
  getLogLevel(): LogLevel {
    return this.currentLogLevel;
  }

  /**
   * Set log level (useful for testing)
   */
  setLogLevel(level: LogLevel): void {
    this.currentLogLevel = level;
  }
}

/**
 * Factory function to create a logger instance with context
 */
export function createLogger(context: string): AppLogger {
  return new AppLogger(context);
}
