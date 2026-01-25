import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { Request } from 'express';
import { UserContext } from '../interfaces/user-context.interface';

@Injectable()
export class UserContextInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest<Request>();

    // If user is not already set (from auth guard), set a mock user for development
    if (!request.user) {
      request.user = this.getMockUser(request);
    }

    return next.handle();
  }

  /**
   * Get mock user from request headers or use default
   * In production, this would extract from JWT token
   */
  private getMockUser(request: Request): UserContext {
    // Check for user ID in headers (for testing)
    const userId = request.headers['x-user-id'] as string;
    const userEmail = request.headers['x-user-email'] as string;
    const userRoles = request.headers['x-user-roles'] as string;

    // Default mock user
    const defaultUser: UserContext = {
      id: userId || 'current-user',
      email: userEmail || 'developer@example.com',
      roles: userRoles ? userRoles.split(',') : ['editor'],
      applicationIds: [],
      teamNames: [],
    };

    // Add cyber-risk-manager or data-steward role if in headers
    if (request.headers['x-user-role'] === 'cyber-risk-manager') {
      defaultUser.roles.push('cyber-risk-manager');
    }
    if (request.headers['x-user-role'] === 'data-steward') {
      defaultUser.roles.push('data-steward');
    }

    return defaultUser;
  }
}

