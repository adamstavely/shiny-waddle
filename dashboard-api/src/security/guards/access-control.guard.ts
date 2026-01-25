import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { SecurityAuditLogService, SecurityAuditEventType } from '../audit-log.service';
import { Request } from 'express';

export enum UserRole {
  ADMIN = 'admin',
  EDITOR = 'editor',
  VIEWER = 'viewer',
  AUDITOR = 'auditor',
  DATA_STEWARD = 'data-steward',
  CYBER_RISK_MANAGER = 'cyber-risk-manager',
}

export enum Permission {
  // Read permissions
  READ_POLICIES = 'read:policies',
  READ_APPLICATIONS = 'read:applications',
  READ_VIOLATIONS = 'read:violations',
  READ_REPORTS = 'read:reports',
  READ_AUDIT_LOGS = 'read:audit-logs',
  READ_SECRETS = 'read:secrets',
  READ_CONFIG = 'read:config',

  // Write permissions
  WRITE_POLICIES = 'write:policies',
  WRITE_APPLICATIONS = 'write:applications',
  WRITE_VIOLATIONS = 'write:violations',
  WRITE_REPORTS = 'write:reports',
  WRITE_SECRETS = 'write:secrets',
  WRITE_CONFIG = 'write:config',

  // Delete permissions
  DELETE_POLICIES = 'delete:policies',
  DELETE_APPLICATIONS = 'delete:applications',
  DELETE_VIOLATIONS = 'delete:violations',
  DELETE_REPORTS = 'delete:reports',
  DELETE_SECRETS = 'delete:secrets',

  // Admin permissions
  MANAGE_USERS = 'manage:users',
  MANAGE_ROLES = 'manage:roles',
  MANAGE_SYSTEM = 'manage:system',
  VIEW_AUDIT_LOGS = 'view:audit-logs',
  
  // Application test/validator management
  MANAGE_APPLICATION_TESTS = 'manage:application-tests',
  MANAGE_APPLICATION_VALIDATORS = 'manage:application-validators',
}

// Role to permissions mapping
const ROLE_PERMISSIONS: Record<UserRole, Permission[]> = {
  [UserRole.ADMIN]: [
    // Admins have all permissions
    ...Object.values(Permission),
  ],
  [UserRole.EDITOR]: [
    Permission.READ_POLICIES,
    Permission.READ_APPLICATIONS,
    Permission.READ_VIOLATIONS,
    Permission.READ_REPORTS,
    Permission.READ_CONFIG,
    Permission.WRITE_POLICIES,
    Permission.WRITE_APPLICATIONS,
    Permission.WRITE_VIOLATIONS,
    Permission.WRITE_REPORTS,
    Permission.DELETE_POLICIES,
    Permission.DELETE_APPLICATIONS,
    Permission.DELETE_VIOLATIONS,
    Permission.DELETE_REPORTS,
  ],
  [UserRole.VIEWER]: [
    Permission.READ_POLICIES,
    Permission.READ_APPLICATIONS,
    Permission.READ_VIOLATIONS,
    Permission.READ_REPORTS,
    Permission.READ_CONFIG,
  ],
  [UserRole.AUDITOR]: [
    Permission.READ_POLICIES,
    Permission.READ_APPLICATIONS,
    Permission.READ_VIOLATIONS,
    Permission.READ_REPORTS,
    Permission.READ_AUDIT_LOGS,
    Permission.VIEW_AUDIT_LOGS,
  ],
  [UserRole.DATA_STEWARD]: [
    Permission.READ_POLICIES,
    Permission.READ_APPLICATIONS,
    Permission.READ_VIOLATIONS,
    Permission.READ_REPORTS,
    Permission.READ_CONFIG,
    Permission.MANAGE_APPLICATION_TESTS,
    Permission.MANAGE_APPLICATION_VALIDATORS,
  ],
  [UserRole.CYBER_RISK_MANAGER]: [
    Permission.READ_POLICIES,
    Permission.READ_APPLICATIONS,
    Permission.READ_VIOLATIONS,
    Permission.READ_REPORTS,
    Permission.READ_CONFIG,
    Permission.READ_AUDIT_LOGS,
    Permission.VIEW_AUDIT_LOGS,
    Permission.MANAGE_APPLICATION_TESTS,
    Permission.MANAGE_APPLICATION_VALIDATORS,
  ],
};

export const RequirePermission = (permission: Permission) => {
  return (target: any, propertyKey: string, descriptor: PropertyDescriptor) => {
    Reflect.defineMetadata('permission', permission, descriptor.value);
  };
};

export const RequireRole = (role: UserRole) => {
  return (target: any, propertyKey: string, descriptor: PropertyDescriptor) => {
    Reflect.defineMetadata('role', role, descriptor.value);
  };
};

@Injectable()
export class AccessControlGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly auditLogService: SecurityAuditLogService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    
    // Get required permission or role from metadata
    const requiredPermission = this.reflector.get<Permission>(
      'permission',
      context.getHandler(),
    );
    const requiredRole = this.reflector.get<UserRole>(
      'role',
      context.getHandler(),
    );

    // If no permission or role required, allow access
    if (!requiredPermission && !requiredRole) {
      return true;
    }

    // Get user from request (this would come from authentication middleware)
    const user = (request as any).user;
    
    if (!user) {
      await this.auditLogService.log({
        type: SecurityAuditEventType.ACCESS_DENIED,
        action: 'access-denied',
        description: `Unauthenticated access attempt to ${request.path}`,
        ipAddress: request.ip,
        userAgent: request.get('user-agent'),
        success: false,
        errorMessage: 'User not authenticated',
        requestId: request.headers['x-request-id'] as string,
      });
      
      throw new UnauthorizedException('Authentication required');
    }

    const userRole = user.role as UserRole;
    const userId = user.id || user.userId;
    const username = user.username || user.email;

    // Check role requirement
    if (requiredRole) {
      if (userRole !== requiredRole && userRole !== UserRole.ADMIN) {
        await this.auditLogService.log({
          type: SecurityAuditEventType.ACCESS_DENIED,
          action: 'access-denied',
          description: `User ${username} attempted to access ${request.path} but lacks required role ${requiredRole}`,
          userId,
          username,
          ipAddress: request.ip,
          userAgent: request.get('user-agent'),
          resourceType: 'endpoint',
          resourceId: request.path,
          success: false,
          errorMessage: `Required role: ${requiredRole}, user role: ${userRole}`,
          requestId: request.headers['x-request-id'] as string,
        });
        
        throw new ForbiddenException(`Required role: ${requiredRole}`);
      }
    }

    // Check permission requirement
    if (requiredPermission) {
      const userPermissions = ROLE_PERMISSIONS[userRole] || [];
      
      if (!userPermissions.includes(requiredPermission)) {
        await this.auditLogService.log({
          type: SecurityAuditEventType.ACCESS_DENIED,
          action: 'access-denied',
          description: `User ${username} attempted to access ${request.path} but lacks required permission ${requiredPermission}`,
          userId,
          username,
          ipAddress: request.ip,
          userAgent: request.get('user-agent'),
          resourceType: 'endpoint',
          resourceId: request.path,
          success: false,
          errorMessage: `Required permission: ${requiredPermission}`,
          requestId: request.headers['x-request-id'] as string,
        });
        
        throw new ForbiddenException(`Required permission: ${requiredPermission}`);
      }
    }

    // Log successful access
    await this.auditLogService.log({
      type: SecurityAuditEventType.ACCESS_GRANTED,
      action: 'access-granted',
      description: `User ${username} accessed ${request.path}`,
      userId,
      username,
      ipAddress: request.ip,
      userAgent: request.get('user-agent'),
      resourceType: 'endpoint',
      resourceId: request.path,
      success: true,
      requestId: request.headers['x-request-id'] as string,
    });

    return true;
  }
}


