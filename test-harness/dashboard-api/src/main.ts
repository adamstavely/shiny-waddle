import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';
import { AllExceptionsFilter } from './common/filters/http-exception.filter';
import { UserContextInterceptor } from './common/interceptors/user-context.interceptor';
import * as https from 'https';
import * as fs from 'fs';

async function bootstrap() {
  let app;
  
  // Enable HTTPS if configured (for encryption in transit)
  const httpsEnabled = process.env.HTTPS_ENABLED === 'true';
  const httpsKeyPath = process.env.HTTPS_KEY_PATH;
  const httpsCertPath = process.env.HTTPS_CERT_PATH;

  if (httpsEnabled && httpsKeyPath && httpsCertPath) {
    const httpsOptions = {
      key: fs.readFileSync(httpsKeyPath),
      cert: fs.readFileSync(httpsCertPath),
    };
    app = await NestFactory.create(AppModule, {
      httpsOptions,
    });
    console.log('🔒 HTTPS enabled for encryption in transit');
  } else {
    app = await NestFactory.create(AppModule);
    if (process.env.NODE_ENV === 'production') {
      console.warn('⚠️  WARNING: HTTPS is not enabled. Enable HTTPS in production for encryption in transit.');
    }
  }

  // Global validation pipe
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  // Global exception filter
  app.useGlobalFilters(new AllExceptionsFilter());

  // Global user context interceptor
  app.useGlobalInterceptors(new UserContextInterceptor());

  // Enable CORS for Vue frontend
  app.enableCors({
    origin: process.env.CORS_ORIGIN || 'http://localhost:5173',
    credentials: true,
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
    allowedHeaders: 'Content-Type,Authorization',
  });

  const port = process.env.PORT || 3001;
  const protocol = httpsEnabled ? 'https' : 'http';
  await app.listen(port);
  console.log(`🚀 Heimdall Dashboard API running on ${protocol}://localhost:${port}`);
}

bootstrap();

