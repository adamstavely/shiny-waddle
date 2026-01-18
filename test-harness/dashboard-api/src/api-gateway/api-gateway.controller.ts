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
  async testGatewayPolicy(@Body(ValidationPipe) dto: { applicationId?: string; policy?: any; request: any }) {
    this.logger.log(dto.applicationId
      ? `Testing gateway policy for application: ${dto.applicationId}`
      : `Testing gateway policy: ${dto.policy?.id || 'unknown'}`);
    return this.apiGatewayService.testGatewayPolicy(dto);
  }

  @Post('test-rate-limiting')
  @HttpCode(HttpStatus.OK)
  async testRateLimiting(@Body(ValidationPipe) dto: { applicationId?: string; endpoint?: string; requests?: number }) {
    this.logger.log(dto.applicationId
      ? `Testing rate limiting for application: ${dto.applicationId}`
      : `Testing rate limiting: ${dto.endpoint} with ${dto.requests} requests`);
    return this.apiGatewayService.testRateLimiting(dto);
  }

  @Post('test-api-versioning')
  @HttpCode(HttpStatus.OK)
  async testAPIVersioning(@Body(ValidationPipe) dto: { applicationId?: string; version: string; endpoint: string }) {
    this.logger.log(dto.applicationId
      ? `Testing API versioning for application: ${dto.applicationId}`
      : `Testing API versioning: ${dto.version} on ${dto.endpoint}`);
    return this.apiGatewayService.testAPIVersioning(dto);
  }

  @Post('test-service-auth')
  @HttpCode(HttpStatus.OK)
  async testServiceAuth(@Body(ValidationPipe) dto: { applicationId?: string; source?: string; target?: string }) {
    this.logger.log(dto.applicationId
      ? `Testing service auth for application: ${dto.applicationId}`
      : `Testing service auth: ${dto.source} -> ${dto.target}`);
    return this.apiGatewayService.testServiceAuth(dto);
  }
}

