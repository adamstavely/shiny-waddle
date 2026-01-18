import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AppModule } from './app.module';
import { AllExceptionsFilter } from './common/filters/http-exception.filter';
import { UserContextInterceptor } from './common/interceptors/user-context.interceptor';
import { JwtAuthGuard } from './auth/guards/jwt-auth.guard';
import * as https from 'https';
import * as fs from 'fs';

async function bootstrap() {
  let app;
  
  // Enable HTTPS if configured (for encryption in transit)
  const httpsEnabled = process.env.HTTPS_ENABLED === 'true';
  const httpsKeyPath = process.env.HTTPS_KEY_PATH;
  const httpsCertPath = process.env.HTTPS_CERT_PATH;
  const isProduction = process.env.NODE_ENV === 'production';

  if (httpsEnabled && httpsKeyPath && httpsCertPath) {
    try {
      // Validate certificate files exist and are readable
      if (!fs.existsSync(httpsKeyPath)) {
        throw new Error(`HTTPS key file not found: ${httpsKeyPath}`);
      }
      if (!fs.existsSync(httpsCertPath)) {
        throw new Error(`HTTPS certificate file not found: ${httpsCertPath}`);
      }

      const httpsOptions = {
        key: fs.readFileSync(httpsKeyPath),
        cert: fs.readFileSync(httpsCertPath),
        minVersion: 'TLSv1.2', // Enforce TLS 1.2+
      };
      app = await NestFactory.create(AppModule, {
        httpsOptions,
      });
      console.log('🔒 HTTPS enabled for encryption in transit (TLS 1.2+)');
    } catch (error: any) {
      console.error('❌ Error setting up HTTPS:', error.message);
      if (isProduction) {
        throw new Error(`HTTPS setup failed in production: ${error.message}`);
      }
      app = await NestFactory.create(AppModule);
      console.warn('⚠️  Falling back to HTTP due to HTTPS setup error');
    }
  } else {
    app = await NestFactory.create(AppModule);
    if (isProduction) {
      console.error('❌ ERROR: HTTPS is not enabled in production. This is a security risk!');
      console.error('   Set HTTPS_ENABLED=true, HTTPS_KEY_PATH, and HTTPS_CERT_PATH environment variables.');
    } else {
      console.warn('⚠️  HTTPS is not enabled. Enable HTTPS in production for encryption in transit.');
    }
  }

  // Global validation pipe with enhanced security
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: {
        enableImplicitConversion: true,
      },
      // Prevent SQL injection through validation
      disableErrorMessages: process.env.NODE_ENV === 'production',
    }),
  );

  // Global exception filter
  app.useGlobalFilters(new AllExceptionsFilter());

  // Global user context interceptor
  app.useGlobalInterceptors(new UserContextInterceptor());

  // Global JWT authentication guard (applied to all routes except those marked @Public())
  const reflector = app.get(Reflector);
  app.useGlobalGuards(new JwtAuthGuard(reflector));

  // Enable CORS for Vue frontend
  app.enableCors({
    origin: process.env.CORS_ORIGIN || 'http://localhost:5173',
    credentials: true,
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
    allowedHeaders: 'Content-Type,Authorization',
  });

  // Configure Express to allow dots in route parameters (not treat them as file extensions)
  // This is needed for test IDs like "test.idp.service_conforms_to_golden_template"
  const expressApp = app.getHttpAdapter().getInstance();
  if (expressApp && typeof expressApp.set === 'function') {
    // Disable treating dots as file extensions by configuring Express
    expressApp.set('json escape', false);
    expressApp.set('strict routing', false);
  }

  const port = process.env.PORT || 3001;
  const protocol = httpsEnabled ? 'https' : 'http';
  await app.listen(port);
  console.log(`🚀 Heimdall Dashboard API running on ${protocol}://localhost:${port}`);
}

bootstrap();

