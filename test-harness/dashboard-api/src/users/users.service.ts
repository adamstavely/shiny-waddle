import { Injectable, Logger } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { User } from './entities/user.entity';

@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);
  private readonly usersFile = path.join(process.cwd(), '..', '..', 'data', 'users.json');
  private users: User[] = [];

  constructor() {
    this.loadUsers().catch(err => {
      this.logger.error('Error loading users on startup:', err);
    });
  }

  private async loadUsers(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.usersFile), { recursive: true });
      const data = await fs.readFile(this.usersFile, 'utf-8');
      if (data && data.trim()) {
        this.users = JSON.parse(data);
      } else {
        this.users = [];
      }
    } catch (error: any) {
      if (error.code === 'ENOENT') {
        // File doesn't exist yet, start with empty array
        this.users = [];
      } else {
        this.logger.error('Error loading users:', error);
        this.users = [];
      }
    }
  }

  private async saveUsers(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.usersFile), { recursive: true });
      await fs.writeFile(
        this.usersFile,
        JSON.stringify(this.users, null, 2),
        'utf-8'
      );
    } catch (error) {
      this.logger.error('Error saving users:', error);
      throw error;
    }
  }

  /**
   * Get all users
   */
  async getAllUsers(): Promise<User[]> {
    if (this.users.length === 0) {
      await this.loadUsers();
    }
    return [...this.users];
  }

  /**
   * Get user by ID
   */
  async getUserById(id: string): Promise<User | null> {
    if (this.users.length === 0) {
      await this.loadUsers();
    }
    return this.users.find(u => u.id === id) || null;
  }

  /**
   * Get users by application ID
   */
  async getUsersByApplication(applicationId: string): Promise<User[]> {
    if (this.users.length === 0) {
      await this.loadUsers();
    }
    return this.users.filter(u => u.applicationIds.includes(applicationId));
  }

  /**
   * Get users by team name
   */
  async getUsersByTeam(teamName: string): Promise<User[]> {
    if (this.users.length === 0) {
      await this.loadUsers();
    }
    return this.users.filter(u => u.teamNames.includes(teamName));
  }

  /**
   * Get users by role
   */
  async getUsersByRole(role: string): Promise<User[]> {
    if (this.users.length === 0) {
      await this.loadUsers();
    }
    return this.users.filter(u => u.roles.includes(role));
  }

  /**
   * Get users by multiple roles (users must have at least one of the roles)
   */
  async getUsersByRoles(roles: string[]): Promise<User[]> {
    if (this.users.length === 0) {
      await this.loadUsers();
    }
    return this.users.filter(u => roles.some(role => u.roles.includes(role)));
  }

  /**
   * Get users by applications and/or teams
   * Returns users associated with any of the provided applications or teams
   */
  async getUsersByApplicationsAndTeams(
    applicationIds?: string[],
    teamNames?: string[]
  ): Promise<User[]> {
    if (this.users.length === 0) {
      await this.loadUsers();
    }

    if (!applicationIds && !teamNames) {
      return [];
    }

    const result = new Set<User>();

    if (applicationIds && applicationIds.length > 0) {
      for (const appId of applicationIds) {
        const users = await this.getUsersByApplication(appId);
        users.forEach(u => result.add(u));
      }
    }

    if (teamNames && teamNames.length > 0) {
      for (const teamName of teamNames) {
        const users = await this.getUsersByTeam(teamName);
        users.forEach(u => result.add(u));
      }
    }

    return Array.from(result);
  }

  /**
   * Get users who have any of the specified roles and are associated with the applications/teams
   */
  async getUsersByRoleAndContext(
    roles: string[],
    applicationIds?: string[],
    teamNames?: string[]
  ): Promise<User[]> {
    const usersByRole = await this.getUsersByRoles(roles);
    
    if (!applicationIds && !teamNames) {
      return usersByRole;
    }

    // Filter to users associated with the applications/teams
    return usersByRole.filter(user => {
      if (applicationIds && applicationIds.length > 0) {
        const hasApp = applicationIds.some(appId => user.applicationIds.includes(appId));
        if (hasApp) return true;
      }
      if (teamNames && teamNames.length > 0) {
        const hasTeam = teamNames.some(team => user.teamNames.includes(team));
        if (hasTeam) return true;
      }
      return false;
    });
  }
}

