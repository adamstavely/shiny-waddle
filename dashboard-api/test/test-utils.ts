/**
 * Test Utilities
 * 
 * Common utilities for testing NestJS modules and services
 */

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';

/**
 * Create a testing module with mocked dependencies
 */
export async function createTestingModule(
  moduleClass: any,
  providers: any[] = [],
  imports: any[] = []
): Promise<TestingModule> {
  return Test.createTestingModule({
    imports,
    providers: [
      ...providers,
    ],
  })
    .overrideModule(moduleClass)
    .useModule(moduleClass)
    .compile();
}

/**
 * Create a test application with validation pipes
 */
export function createTestApp(module: TestingModule): INestApplication {
  const app = module.createNestApplication();
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );
  return app;
}

/**
 * Helper to make authenticated requests (if needed in future)
 */
export function authenticatedRequest(app: INestApplication, token?: string) {
  const req = request(app.getHttpServer());
  if (token) {
    return req.set('Authorization', `Bearer ${token}`);
  }
  return req;
}

/**
 * Mock factory helpers
 */
export const MockFactory = {
  /**
   * Create a mock service with all methods as jest.fn()
   */
  createMockService<T>(serviceClass: new (...args: any[]) => T): jest.Mocked<T> {
    const mock = {} as any;
    const prototype = serviceClass.prototype;
    
    Object.getOwnPropertyNames(prototype).forEach((name) => {
      if (name !== 'constructor' && typeof prototype[name] === 'function') {
        mock[name] = jest.fn();
      }
    });
    
    return mock as jest.Mocked<T>;
  },

  /**
   * Create a mock database config
   */
  createDatabaseConfig(overrides: Partial<any> = {}): any {
    return {
      type: 'postgresql',
      host: 'localhost',
      port: 5432,
      database: 'test_db',
      username: 'test_user',
      password: 'test_password',
      ...overrides,
    };
  },

  /**
   * Create a mock user
   */
  createUser(overrides: Partial<any> = {}): any {
    return {
      id: 'user-123',
      email: 'test@example.com',
      role: 'viewer',
      attributes: {},
      ...overrides,
    };
  },

  /**
   * Create a mock resource
   */
  createResource(overrides: Partial<any> = {}): any {
    return {
      id: 'resource-123',
      type: 'dataset',
      attributes: {},
      ...overrides,
    };
  },

  /**
   * Create a mock policy
   */
  createPolicy(overrides: Partial<any> = {}): any {
    return {
      id: 'policy-123',
      name: 'Test Policy',
      description: 'Test policy description',
      effect: 'allow',
      conditions: [],
      ...overrides,
    };
  },

  /**
   * Create a mock test result
   */
  createTestResult(overrides: Partial<any> = {}): any {
    return {
      testType: 'access-control' as const,
      testName: 'Test',
      passed: true,
      details: {},
      timestamp: new Date(),
      ...overrides,
    };
  },
};

/**
 * Common test data fixtures
 */
export const TestFixtures = {
  validDatabaseConfig: {
    type: 'postgresql',
    database: 'test_db',
  },

  validUser: {
    id: 'user-123',
    email: 'test@example.com',
    role: 'viewer',
    attributes: {},
  },

  validResource: {
    id: 'resource-123',
    type: 'dataset',
    attributes: {},
  },

  validPolicy: {
    id: 'policy-123',
    name: 'Test Policy',
    description: 'Test policy description',
    effect: 'allow',
    conditions: [],
  },
};

