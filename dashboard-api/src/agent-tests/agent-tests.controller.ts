/**
 * Agent Tests Controller
 * 
 * API endpoints for agent access control testing
 */

import {
  Controller,
  Post,
  Get,
  Body,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { AgentTestsService } from './agent-tests.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { AccessControlGuard, RequirePermission, Permission } from '../security/guards/access-control.guard';

@Controller('api/agent-tests')
@UseGuards(JwtAuthGuard, AccessControlGuard)
export class AgentTestsController {
  constructor(private readonly agentTestsService: AgentTestsService) {}

  /**
   * Run delegated access tests
   */
  @Post('delegated-access')
  @HttpCode(HttpStatus.OK)
  @RequirePermission(Permission.MANAGE_APPLICATION_TESTS)
  async runDelegatedAccessTests(
    @Body() dto: {
      agentId: string;
      userContext: {
        userId: string;
        email: string;
        role: string;
        permissions: string[];
      };
      resources: Array<{
        id: string;
        type: string;
        attributes?: Record<string, any>;
      }>;
      actions: string[];
      oauthConfig?: {
        authorizationEndpoint: string;
        tokenEndpoint: string;
        clientId: string;
        redirectUri: string;
        scopes: string[];
      };
    }
  ) {
    return this.agentTestsService.runDelegatedAccessTests(dto);
  }

  /**
   * Run direct access tests
   */
  @Post('direct-access')
  @HttpCode(HttpStatus.OK)
  @RequirePermission(Permission.MANAGE_APPLICATION_TESTS)
  async runDirectAccessTests(
    @Body() dto: {
      agentId: string;
      agentType: 'autonomous' | 'event-driven' | 'scheduled';
      resources: Array<{
        id: string;
        type: string;
        attributes?: Record<string, any>;
      }>;
      actions: string[];
      oauthConfig?: {
        tokenEndpoint: string;
        clientId: string;
        clientSecret?: string;
        scopes: string[];
      };
    }
  ) {
    return this.agentTestsService.runDirectAccessTests(dto);
  }

  /**
   * Get agent audit trail
   */
  @Get('audit-trail/:agentId')
  @RequirePermission(Permission.READ_AUDIT_LOGS)
  async getAuditTrail(
    @Param('agentId') agentId: string,
    @Body() filters?: {
      startDate?: Date;
      endDate?: Date;
      serviceId?: string;
      action?: string;
    }
  ) {
    return this.agentTestsService.getAuditTrail(agentId, filters);
  }

  /**
   * Test multi-service access
   */
  @Post('multi-service')
  @HttpCode(HttpStatus.OK)
  @RequirePermission(Permission.MANAGE_APPLICATION_TESTS)
  async testMultiServiceAccess(
    @Body() dto: {
      agentId: string;
      agentType: 'delegated' | 'direct';
      userContext?: {
        userId: string;
        permissions: string[];
      };
      services: Array<{
        serviceId: string;
        resource: {
          id: string;
          type: string;
          attributes?: Record<string, any>;
        };
        action: string;
        expectedAllowed: boolean;
      }>;
    }
  ) {
    return this.agentTestsService.testMultiServiceAccess(dto);
  }

  /**
   * Test dynamic access
   */
  @Post('dynamic-access')
  @HttpCode(HttpStatus.OK)
  @RequirePermission(Permission.MANAGE_APPLICATION_TESTS)
  async testDynamicAccess(
    @Body() dto: {
      agentId: string;
      agentType: 'delegated' | 'direct';
      userContext?: {
        userId: string;
        permissions: string[];
      };
      scenarios: Array<{
        name: string;
        context: {
          ipAddress?: string;
          timeOfDay?: string;
          location?: string;
          device?: string;
          additionalAttributes?: Record<string, any>;
        };
        requestedPermission: string;
        expectedGranted: boolean;
        jitAccess?: boolean;
      }>;
    }
  ) {
    return this.agentTestsService.testDynamicAccess(dto);
  }

  /**
   * Validate audit trail
   */
  @Post('audit-trail/validate')
  @HttpCode(HttpStatus.OK)
  @RequirePermission(Permission.READ_AUDIT_LOGS)
  async validateAuditTrail(
    @Body() dto: {
      agentId: string;
      agentType: 'delegated' | 'direct';
      userId?: string;
      actions: Array<{
        serviceId: string;
        action: string;
        resourceId: string;
        resourceType: string;
        timestamp: Date;
        expectedLogged: boolean;
      }>;
      auditSources?: string[];
      retentionPeriod?: number;
    }
  ) {
    return this.agentTestsService.validateAuditTrail(dto);
  }
}
