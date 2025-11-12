import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  ValidationPipe,
  Logger,
} from '@nestjs/common';
import { IdentityLifecycleService } from './identity-lifecycle.service';

@Controller('api/identity-lifecycle')
export class IdentityLifecycleController {
  private readonly logger = new Logger(IdentityLifecycleController.name);

  constructor(private readonly identityLifecycleService: IdentityLifecycleService) {}

  @Post('test-onboarding')
  @HttpCode(HttpStatus.OK)
  async testOnboarding(@Body(ValidationPipe) dto: { configId?: string; user?: any; request?: any }) {
    // Support both old format (request) and new format (user/configId)
    const user = dto.user || (dto.request?.user ? dto.request.user : { id: dto.request?.userId || 'test-user', email: 'test@example.com', role: 'viewer', attributes: {} });
    this.logger.log(dto.configId
      ? `Testing onboarding with config: ${dto.configId}`
      : `Testing onboarding for user: ${user?.id || 'unknown'}`);
    return this.identityLifecycleService.testOnboarding({ configId: dto.configId, user });
  }

  @Post('test-role-change')
  @HttpCode(HttpStatus.OK)
  async testRoleChange(@Body(ValidationPipe) dto: { configId?: string; user: any; newRole: string }) {
    this.logger.log(dto.configId
      ? `Testing role change with config: ${dto.configId}`
      : `Testing role change for user: ${dto.user?.id || 'unknown'} to role: ${dto.newRole}`);
    return this.identityLifecycleService.testRoleChange(dto);
  }

  @Post('test-offboarding')
  @HttpCode(HttpStatus.OK)
  async testOffboarding(@Body(ValidationPipe) dto: { configId?: string; user: any }) {
    this.logger.log(dto.configId
      ? `Testing offboarding with config: ${dto.configId}`
      : `Testing offboarding for user: ${dto.user?.id || 'unknown'}`);
    return this.identityLifecycleService.testOffboarding(dto);
  }

  @Post('validate-credential-rotation')
  @HttpCode(HttpStatus.OK)
  async validateCredentialRotation(@Body(ValidationPipe) dto: { configId?: string; user: any }) {
    this.logger.log(dto.configId
      ? `Validating credential rotation with config: ${dto.configId}`
      : `Validating credential rotation for user: ${dto.user?.id || 'unknown'}`);
    return this.identityLifecycleService.validateCredentialRotation(dto);
  }

  @Post('test-mfa-enforcement')
  @HttpCode(HttpStatus.OK)
  async testMFAEnforcement(@Body(ValidationPipe) dto: { configId?: string; user: any }) {
    this.logger.log(dto.configId
      ? `Testing MFA enforcement with config: ${dto.configId}`
      : `Testing MFA enforcement for user: ${dto.user?.id || 'unknown'}`);
    return this.identityLifecycleService.testMFAEnforcement(dto);
  }

  @Post('test-jit-access')
  @HttpCode(HttpStatus.OK)
  async testJITAccess(@Body(ValidationPipe) dto: { configId?: string; request?: any }) {
    this.logger.log(dto.configId
      ? `Testing JIT access with config: ${dto.configId}`
      : `Testing JIT access for user: ${dto.request?.userId || 'unknown'}`);
    return this.identityLifecycleService.testJITAccess({ configId: dto.configId, request: dto.request });
  }

  @Post('test-break-glass')
  @HttpCode(HttpStatus.OK)
  async testBreakGlass(@Body(ValidationPipe) dto: { configId?: string; request?: any }) {
    this.logger.log(dto.configId
      ? `Testing break-glass access with config: ${dto.configId}`
      : `Testing break-glass access for user: ${dto.request?.userId || 'unknown'}`);
    return this.identityLifecycleService.testBreakGlass({ configId: dto.configId, request: dto.request });
  }
}

