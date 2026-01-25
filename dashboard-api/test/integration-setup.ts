/**
 * Integration Test Setup
 * 
 * Sets up the NestJS application for integration testing
 * Integration tests use actual services (not mocked) to test multi-service workflows
 */

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { AppModule } from '../src/app.module';
import { AllExceptionsFilter } from '../src/common/filters/http-exception.filter';

export async function createIntegrationApp(): Promise<INestApplication> {
  const moduleFixture: TestingModule = await Test.createTestingModule({
    imports: [AppModule],
  }).compile();

  const app = moduleFixture.createNestApplication();
  
  // Apply global validation pipe (same as main.ts)
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  // Apply global exception filter (same as main.ts)
  app.useGlobalFilters(new AllExceptionsFilter());

  // Enable CORS for testing
  app.enableCors({
    origin: '*',
    credentials: true,
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
    allowedHeaders: 'Content-Type,Authorization',
  });

  await app.init();
  return app;
}

/**
 * Get a service from the application context
 */
export function getService<T>(app: INestApplication, serviceClass: new (...args: any[]) => T): T {
  return app.get(serviceClass);
}
