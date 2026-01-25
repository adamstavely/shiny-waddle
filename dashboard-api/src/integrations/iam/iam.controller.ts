import { Controller, Get, Post, Put, Delete, Param, Body, Query, HttpStatus, HttpException } from '@nestjs/common';
import { IAMService } from './iam.service';
import { SSOConfig, RBACConfig, PAMConfig, IdPConfig } from '../../../../services/iam-integration';

@Controller('api/integrations/iam')
export class IAMController {
  constructor(private readonly service: IAMService) {}

  // SSO
  @Post('sso')
  async createSSO(@Body() config: SSOConfig) {
    return this.service.createSSO(config);
  }

  @Get('sso')
  async findAllSSO() {
    return this.service.findAllSSO();
  }

  @Get('sso/:type/auth-url')
  async generateSSOAuthUrl(@Param('type') type: string, @Query('state') state?: string) {
    const url = await this.service.generateSSOAuthUrl(type, state);
    return { url };
  }

  // RBAC
  @Post('rbac')
  async createRBAC(@Body() config: RBACConfig) {
    return this.service.createRBAC(config);
  }

  @Get('rbac')
  async findAllRBAC() {
    return this.service.findAllRBAC();
  }

  @Get('rbac/:provider/users/:userId/roles')
  async getUserRoles(@Param('provider') provider: string, @Param('userId') userId: string) {
    return this.service.getUserRoles(provider, userId);
  }

  @Get('rbac/:provider/users/:userId/permissions')
  async hasPermission(
    @Param('provider') provider: string,
    @Param('userId') userId: string,
    @Query('resource') resource: string,
    @Query('action') action: string,
  ) {
    const hasPermission = await this.service.hasPermission(provider, userId, resource, action);
    return { hasPermission };
  }

  // PAM
  @Post('pam')
  async createPAM(@Body() config: PAMConfig) {
    return this.service.createPAM(config);
  }

  @Get('pam')
  async findAllPAM() {
    return this.service.findAllPAM();
  }

  @Get('pam/:provider/secrets/:path(*)')
  async getSecret(@Param('provider') provider: string, @Param('path') path: string) {
    return this.service.getSecret(provider, path);
  }

  // IdP
  @Post('idp')
  async createIdP(@Body() config: IdPConfig) {
    return this.service.createIdP(config);
  }

  @Get('idp')
  async findAllIdP() {
    return this.service.findAllIdP();
  }

  @Post('idp/:type/authenticate')
  async authenticateUser(
    @Param('type') type: string,
    @Body() credentials: { username: string; password: string },
  ) {
    return this.service.authenticateUser(type, credentials.username, credentials.password);
  }
}

