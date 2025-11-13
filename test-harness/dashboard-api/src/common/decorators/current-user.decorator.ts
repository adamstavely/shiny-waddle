import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { UserContext } from '../interfaces/user-context.interface';

export const CurrentUser = createParamDecorator(
  (data: unknown, ctx: ExecutionContext): UserContext => {
    const request = ctx.switchToHttp().getRequest();
    return request.user || getMockUser();
  },
);

/**
 * Get mock user for development
 * In production, this would come from JWT token or session
 */
function getMockUser(): UserContext {
  // For development, return a default user
  // In production, extract from JWT token or session
  return {
    id: 'current-user',
    email: 'developer@example.com',
    roles: ['editor', 'cyber-risk-manager'],
    applicationIds: [],
    teamNames: [],
  };
}

