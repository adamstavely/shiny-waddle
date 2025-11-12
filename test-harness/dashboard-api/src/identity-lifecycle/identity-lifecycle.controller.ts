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
  async testOnboarding(@Body(ValidationPipe) dto: { user: any }) {
    this.logger.log(`Testing onboarding for user: ${dto.user?.id || 'unknown'}`);
    return this.identityLifecycleService.testOnboarding(dto);
  }

  @Post('test-role-change')
  @HttpCode(HttpStatus.OK)
  async testRoleChange(@Body(ValidationPipe) dto: { user: any; newRole: string }) {
    this.logger.log(
      `Testing role change for user: ${dto.user?.id || 'unknown'} to role: ${dto.newRole}`,
    );
    return this.identityLifecycleService.testRoleChange(dto);
  }

  @Post('test-offboarding')
  @HttpCode(HttpStatus.OK)
  async testOffboarding(@Body(ValidationPipe) dto: { user: any }) {
    this.logger.log(`Testing offboarding for user: ${dto.user?.id || 'unknown'}`);
    return this.identityLifecycleService.testOffboarding(dto);
  }

  @Post('validate-credential-rotation')
  @HttpCode(HttpStatus.OK)
  async validateCredentialRotation(@Body(ValidationPipe) dto: { user: any }) {
    this.logger.log(`Validating credential rotation for user: ${dto.user?.id || 'unknown'}`);
    return this.identityLifecycleService.validateCredentialRotation(dto);
  }

  @Post('test-mfa-enforcement')
  @HttpCode(HttpStatus.OK)
  async testMFAEnforcement(@Body(ValidationPipe) dto: { user: any }) {
    this.logger.log(`Testing MFA enforcement for user: ${dto.user?.id || 'unknown'}`);
    return this.identityLifecycleService.testMFAEnforcement(dto);
  }

  @Post('test-jit-access')
  @HttpCode(HttpStatus.OK)
  async testJITAccess(@Body(ValidationPipe) dto: { request: any }) {
    this.logger.log(`Testing JIT access for user: ${dto.request?.userId || 'unknown'}`);
    return this.identityLifecycleService.testJITAccess(dto);
  }

  @Post('test-break-glass')
  @HttpCode(HttpStatus.OK)
  async testBreakGlass(@Body(ValidationPipe) dto: { request: any }) {
    this.logger.log(`Testing break-glass access for user: ${dto.request?.userId || 'unknown'}`);
    return this.identityLifecycleService.testBreakGlass(dto);
  }
}

