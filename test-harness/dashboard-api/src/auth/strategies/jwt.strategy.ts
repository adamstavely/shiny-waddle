import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { UsersService } from '../../users/users.service';
import { User } from '../../users/entities/user.entity';

export interface JwtPayload {
  sub: string; // user id
  email: string;
  roles: string[];
  iat?: number;
  exp?: number;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly usersService: UsersService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET || 'your-secret-key-change-in-production',
    });
  }

  async validate(payload: JwtPayload): Promise<any> {
    const user = await this.usersService.getUserById(payload.sub);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }
    return {
      id: user.id,
      userId: user.id,
      email: user.email,
      username: user.email,
      name: user.name,
      role: user.roles[0] || 'viewer', // Primary role for AccessControlGuard
      roles: user.roles,
      applicationIds: user.applicationIds,
      teamNames: user.teamNames,
    };
  }
}

