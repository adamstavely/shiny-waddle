import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { IAMIntegration, SSOConfig, RBACConfig, PAMConfig, IdPConfig, User, Role, Permission } from '../../../../services/iam-integration';

@Injectable()
export class IAMService {
  private readonly configFile = path.join(process.cwd(), '..', 'data', 'iam-integrations.json');
  private iamIntegration: IAMIntegration = new IAMIntegration();
  private ssoConfigs: Map<string, SSOConfig> = new Map();
  private rbacConfigs: Map<string, RBACConfig> = new Map();
  private pamConfigs: Map<string, PAMConfig> = new Map();
  private idpConfigs: Map<string, IdPConfig> = new Map();

  constructor() {
    this.loadConfig();
  }

  private async loadConfig(): Promise<void> {
    try {
      const data = await fs.readFile(this.configFile, 'utf-8');
      const config = JSON.parse(data);
      
      (config.sso || []).forEach((c: SSOConfig) => {
        this.ssoConfigs.set(c.type, c);
        this.iamIntegration.registerSSO(c.type, c);
      });
      
      (config.rbac || []).forEach((c: RBACConfig) => {
        this.rbacConfigs.set(c.provider, c);
        this.iamIntegration.registerRBAC(c.provider, c);
      });
      
      (config.pam || []).forEach((c: PAMConfig) => {
        this.pamConfigs.set(c.provider, c);
        this.iamIntegration.registerPAM(c.provider, c);
      });
      
      (config.idp || []).forEach((c: IdPConfig) => {
        this.idpConfigs.set(c.type, c);
        this.iamIntegration.registerIdP(c.type, c);
      });
    } catch {
      // File doesn't exist, start with empty config
    }
  }

  private async saveConfig(): Promise<void> {
    try {
      const dir = path.dirname(this.configFile);
      await fs.mkdir(dir, { recursive: true });
      await fs.writeFile(this.configFile, JSON.stringify({
        sso: Array.from(this.ssoConfigs.values()),
        rbac: Array.from(this.rbacConfigs.values()),
        pam: Array.from(this.pamConfigs.values()),
        idp: Array.from(this.idpConfigs.values()),
      }, null, 2));
    } catch (error) {
      console.error('Error saving IAM config:', error);
      throw error;
    }
  }

  // SSO
  async createSSO(config: SSOConfig): Promise<SSOConfig> {
    this.ssoConfigs.set(config.type, config);
    this.iamIntegration.registerSSO(config.type, config);
    await this.saveConfig();
    return config;
  }

  async findAllSSO(): Promise<SSOConfig[]> {
    return Array.from(this.ssoConfigs.values());
  }

  async generateSSOAuthUrl(type: string, state?: string): Promise<string> {
    const sso = this.iamIntegration.getSSO(type);
    if (!sso) {
      throw new NotFoundException(`SSO integration ${type} not found`);
    }

    if (sso['config'].type === 'saml') {
      return sso.generateSAMLAuthUrl(state);
    } else {
      return sso.generateOIDCAuthUrl(state);
    }
  }

  // RBAC
  async createRBAC(config: RBACConfig): Promise<RBACConfig> {
    this.rbacConfigs.set(config.provider, config);
    this.iamIntegration.registerRBAC(config.provider, config);
    await this.saveConfig();
    return config;
  }

  async findAllRBAC(): Promise<RBACConfig[]> {
    return Array.from(this.rbacConfigs.values());
  }

  async getUserRoles(provider: string, userId: string): Promise<Role[]> {
    const rbac = this.iamIntegration.getRBAC(provider);
    if (!rbac) {
      throw new NotFoundException(`RBAC integration ${provider} not found`);
    }
    return await rbac.getUserRoles(userId);
  }

  async hasPermission(provider: string, userId: string, resource: string, action: string): Promise<boolean> {
    const rbac = this.iamIntegration.getRBAC(provider);
    if (!rbac) {
      throw new NotFoundException(`RBAC integration ${provider} not found`);
    }
    return await rbac.hasPermission(userId, resource, action);
  }

  // PAM
  async createPAM(config: PAMConfig): Promise<PAMConfig> {
    this.pamConfigs.set(config.provider, config);
    this.iamIntegration.registerPAM(config.provider, config);
    await this.saveConfig();
    return config;
  }

  async findAllPAM(): Promise<PAMConfig[]> {
    return Array.from(this.pamConfigs.values());
  }

  async getSecret(provider: string, secretPath: string): Promise<{ value: string; metadata?: Record<string, any> }> {
    const pam = this.iamIntegration.getPAM(provider);
    if (!pam) {
      throw new NotFoundException(`PAM integration ${provider} not found`);
    }
    return await pam.getSecret(secretPath);
  }

  // IdP
  async createIdP(config: IdPConfig): Promise<IdPConfig> {
    this.idpConfigs.set(config.type, config);
    this.iamIntegration.registerIdP(config.type, config);
    await this.saveConfig();
    return config;
  }

  async findAllIdP(): Promise<IdPConfig[]> {
    return Array.from(this.idpConfigs.values());
  }

  async authenticateUser(type: string, username: string, password: string): Promise<{ success: boolean; user?: User; error?: string }> {
    const idp = this.iamIntegration.getIdP(type);
    if (!idp) {
      throw new NotFoundException(`IdP integration ${type} not found`);
    }
    return await idp.authenticateUser(username, password);
  }
}

