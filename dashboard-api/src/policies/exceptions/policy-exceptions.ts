import { HttpException, HttpStatus } from '@nestjs/common';

/**
 * Custom exceptions for Policy module
 */
export class PolicyNotFoundException extends HttpException {
  constructor(policyId: string) {
    super(
      {
        statusCode: HttpStatus.NOT_FOUND,
        message: `Policy with ID ${policyId} not found`,
        error: 'Policy Not Found',
        policyId,
      },
      HttpStatus.NOT_FOUND,
    );
  }
}

export class PolicyValidationException extends HttpException {
  constructor(message: string, errors?: string[]) {
    super(
      {
        statusCode: HttpStatus.BAD_REQUEST,
        message,
        error: 'Policy Validation Failed',
        errors: errors || [],
      },
      HttpStatus.BAD_REQUEST,
    );
  }
}

export class SummaryGenerationException extends HttpException {
  constructor(message: string, cause?: Error) {
    super(
      {
        statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
        message: `Failed to generate summary: ${message}`,
        error: 'Summary Generation Failed',
        cause: cause?.message,
      },
      HttpStatus.INTERNAL_SERVER_ERROR,
    );
  }
}

export class LLMServiceException extends HttpException {
  constructor(message: string, provider?: string) {
    super(
      {
        statusCode: HttpStatus.SERVICE_UNAVAILABLE,
        message: `LLM service error: ${message}`,
        error: 'LLM Service Unavailable',
        provider,
      },
      HttpStatus.SERVICE_UNAVAILABLE,
    );
  }
}

export class CacheException extends HttpException {
  constructor(message: string) {
    super(
      {
        statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
        message: `Cache error: ${message}`,
        error: 'Cache Error',
      },
      HttpStatus.INTERNAL_SERVER_ERROR,
    );
  }
}
