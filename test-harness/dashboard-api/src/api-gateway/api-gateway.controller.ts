import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  ValidationPipe,
  Logger,
} from '@nestjs/common';
import { APIGatewayService } from './api-gateway.service';

@Controller('api/api-gateway')
export class APIGatewayController {
  private readonly logger = new Logger(APIGatewayController.name);

  constructor(private readonly apiGatewayService: APIGatewayService) {}

  @Post('test-gateway-policy')
  @HttpCode(HttpStatus.OK)
  async testGatewayPolicy(@Body(ValidationPipe) dto: { policy: any; request: any }) {
    this.logger.log(`Testing gateway policy: ${dto.policy?.id || 'unknown'}`);
    return this.apiGatewayService.testGatewayPolicy(dto);
  }

  @Post('test-rate-limiting')
  @HttpCode(HttpStatus.OK)
  async testRateLimiting(@Body(ValidationPipe) dto: { endpoint: string; requests: number }) {
    this.logger.log(`Testing rate limiting: ${dto.endpoint} with ${dto.requests} requests`);
    return this.apiGatewayService.testRateLimiting(dto);
  }

  @Post('test-api-versioning')
  @HttpCode(HttpStatus.OK)
  async testAPIVersioning(@Body(ValidationPipe) dto: { version: string; endpoint: string }) {
    this.logger.log(`Testing API versioning: ${dto.version} on ${dto.endpoint}`);
    return this.apiGatewayService.testAPIVersioning(dto);
  }

  @Post('test-service-auth')
  @HttpCode(HttpStatus.OK)
  async testServiceAuth(@Body(ValidationPipe) dto: { source: string; target: string }) {
    this.logger.log(`Testing service auth: ${dto.source} -> ${dto.target}`);
    return this.apiGatewayService.testServiceAuth(dto);
  }
}

