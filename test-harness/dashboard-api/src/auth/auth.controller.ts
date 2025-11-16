import { Controller, Post, Body, HttpCode, HttpStatus, Request, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { Public } from './decorators/public.decorator';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

@Controller('api/v1/auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() registerDto: RegisterDto, @Request() req: any) {
    const ipAddress = req.ip || req.connection?.remoteAddress;
    const userAgent = req.get('user-agent');
    return this.authService.register(registerDto, ipAddress, userAgent);
  }

  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() loginDto: LoginDto, @Request() req: any) {
    const ipAddress = req.ip || req.connection?.remoteAddress;
    const userAgent = req.get('user-agent');
    return this.authService.login(loginDto, ipAddress, userAgent);
  }

  @Public()
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(@Body() refreshTokenDto: RefreshTokenDto, @Request() req: any) {
    const ipAddress = req.ip || req.connection?.remoteAddress;
    const userAgent = req.get('user-agent');
    return this.authService.refreshToken(refreshTokenDto.refreshToken, ipAddress, userAgent);
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(@Body() refreshTokenDto: RefreshTokenDto, @Request() req: any) {
    const ipAddress = req.ip || req.connection?.remoteAddress;
    const userAgent = req.get('user-agent');
    const userId = req.user?.id || req.user?.userId;
    await this.authService.revokeToken(refreshTokenDto.refreshToken, userId, ipAddress, userAgent);
    return { message: 'Logged out successfully' };
  }
}

