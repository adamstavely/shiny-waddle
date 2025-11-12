import { Injectable, Logger } from '@nestjs/common';
import { IdentityLifecycleTester } from '../../../services/identity-lifecycle-tester';
import { PAMTester } from '../../../services/pam-tester';
import { IdentityVerificationTester } from '../../../services/identity-verification-tester';
import { User, PAMRequest } from '../../../core/types';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';

@Injectable()
export class IdentityLifecycleService {
  private readonly logger = new Logger(IdentityLifecycleService.name);
  private lifecycleTester: IdentityLifecycleTester;
  private pamTester: PAMTester;
  private verificationTester: IdentityVerificationTester;

  constructor() {
    this.lifecycleTester = new IdentityLifecycleTester();
    this.pamTester = new PAMTester();
    this.verificationTester = new IdentityVerificationTester();
  }

  async testOnboarding(dto: { user: User }) {
    try {
      this.validateUser(dto.user);
      return await this.lifecycleTester.testOnboardingWorkflow(dto.user);
    } catch (error: any) {
      this.logger.error(`Error testing onboarding: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test onboarding workflow',
        { originalError: error.message },
      );
    }
  }

  async testRoleChange(dto: { user: User; newRole: string }) {
    try {
      this.validateUser(dto.user);
      if (!dto.newRole || typeof dto.newRole !== 'string') {
        throw new ValidationException('newRole is required and must be a string');
      }
      const validRoles = ['admin', 'researcher', 'analyst', 'viewer'];
      if (!validRoles.includes(dto.newRole)) {
        throw new ValidationException(
          `Invalid role. Must be one of: ${validRoles.join(', ')}`,
        );
      }
      return await this.lifecycleTester.testRoleChangeWorkflow(dto.user, dto.newRole);
    } catch (error: any) {
      this.logger.error(`Error testing role change: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test role change workflow',
        { originalError: error.message },
      );
    }
  }

  async testOffboarding(dto: { user: User }) {
    try {
      this.validateUser(dto.user);
      return await this.lifecycleTester.testOffboardingWorkflow(dto.user);
    } catch (error: any) {
      this.logger.error(`Error testing offboarding: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test offboarding workflow',
        { originalError: error.message },
      );
    }
  }

  async validateCredentialRotation(dto: { user: User }) {
    try {
      this.validateUser(dto.user);
      return await this.lifecycleTester.validateCredentialRotation(dto.user);
    } catch (error: any) {
      this.logger.error(`Error validating credential rotation: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to validate credential rotation',
        { originalError: error.message },
      );
    }
  }

  async testMFAEnforcement(dto: { user: User }) {
    try {
      this.validateUser(dto.user);
      return await this.lifecycleTester.testMFAEnforcement(dto.user);
    } catch (error: any) {
      this.logger.error(`Error testing MFA enforcement: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test MFA enforcement',
        { originalError: error.message },
      );
    }
  }

  async testJITAccess(dto: { request: PAMRequest }) {
    try {
      this.validatePAMRequest(dto.request);
      return await this.pamTester.testJITAccess(dto.request);
    } catch (error: any) {
      this.logger.error(`Error testing JIT access: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test JIT access',
        { originalError: error.message },
      );
    }
  }

  async testBreakGlass(dto: { request: PAMRequest }) {
    try {
      this.validatePAMRequest(dto.request);
      return await this.pamTester.testBreakGlassAccess(dto.request);
    } catch (error: any) {
      this.logger.error(`Error testing break-glass access: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException(
        'Failed to test break-glass access',
        { originalError: error.message },
      );
    }
  }

  private validateUser(user: User): void {
    if (!user) {
      throw new ValidationException('User is required');
    }
    if (!user.id) {
      throw new ValidationException('User id is required');
    }
  }

  private validatePAMRequest(request: PAMRequest): void {
    if (!request) {
      throw new ValidationException('PAM request is required');
    }
    if (!request.userId) {
      throw new ValidationException('PAM request userId is required');
    }
    if (!request.resource) {
      throw new ValidationException('PAM request resource is required');
    }
  }
}

