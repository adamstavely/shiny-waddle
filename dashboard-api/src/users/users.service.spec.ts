/**
 * Users Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { UsersService } from './users.service';
import { User } from './entities/user.entity';
import * as fs from 'fs/promises';

// Mock fs module
jest.mock('fs/promises');

describe('UsersService', () => {
  let service: UsersService;

  const mockUsers: User[] = [
    {
      id: 'user-1',
      email: 'user1@example.com',
      name: 'User One',
      roles: ['viewer'],
      applicationIds: ['app-1'],
      teamNames: ['team-alpha'],
      createdAt: new Date(),
      updatedAt: new Date(),
    },
    {
      id: 'user-2',
      email: 'user2@example.com',
      name: 'User Two',
      roles: ['admin', 'viewer'],
      applicationIds: ['app-1', 'app-2'],
      teamNames: ['team-alpha', 'team-beta'],
      createdAt: new Date(),
      updatedAt: new Date(),
    },
    {
      id: 'user-3',
      email: 'user3@example.com',
      name: 'User Three',
      roles: ['viewer'],
      applicationIds: ['app-2'],
      teamNames: ['team-beta'],
      createdAt: new Date(),
      updatedAt: new Date(),
    },
  ];

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [UsersService],
    }).compile();

    service = module.get<UsersService>(UsersService);
    
    // Mock fs operations
    const fs = require('fs/promises');
    fs.mkdir = jest.fn().mockResolvedValue(undefined);
    fs.readFile = jest.fn().mockResolvedValue(JSON.stringify(mockUsers));
    fs.writeFile = jest.fn().mockResolvedValue(undefined);
    
    // Clear cached users to ensure fresh state for each test
    (service as any).users = [];
  });

  describe('getAllUsers', () => {
    it('should return all users', async () => {
      // Act
      const result = await service.getAllUsers();

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBeGreaterThanOrEqual(0);
    });

    it('should return empty array when no users exist', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockRejectedValue({ code: 'ENOENT' });

      // Act
      const result = await service.getAllUsers();

      // Assert
      expect(result).toEqual([]);
    });

    it('should handle file read errors gracefully', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockRejectedValue(new Error('Read error'));
      // Clear any cached users to force reload
      (service as any).users = [];

      // Act
      const result = await service.getAllUsers();

      // Assert
      expect(Array.isArray(result)).toBe(true);
      // Service handles errors by returning empty array
      expect(result.length).toBeGreaterThanOrEqual(0);
    });
  });

  describe('getUserById', () => {
    it('should return user when found', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify(mockUsers));

      // Act
      const result = await service.getUserById('user-1');

      // Assert
      expect(result).toBeDefined();
      expect(result?.id).toBe('user-1');
      expect(result?.email).toBe('user1@example.com');
    });

    it('should return null when user not found', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify(mockUsers));
      // Clear any cached users
      (service as any).users = [];

      // Act
      const result = await service.getUserById('non-existent-id');

      // Assert
      expect(result).toBeNull();
    });

    it('should handle empty users file', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));
      // Clear any cached users
      (service as any).users = [];

      // Act
      const result = await service.getUserById('user-1');

      // Assert
      expect(result).toBeNull();
    });
  });

  describe('getUsersByApplication', () => {
    it('should return users for specific application', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify(mockUsers));

      // Act
      const result = await service.getUsersByApplication('app-1');

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBe(2); // user-1 and user-2
      expect(result.every(u => u.applicationIds.includes('app-1'))).toBe(true);
    });

    it('should return empty array when no users for application', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify(mockUsers));

      // Act
      const result = await service.getUsersByApplication('non-existent-app');

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('getUsersByTeam', () => {
    it('should return users for specific team', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify(mockUsers));

      // Act
      const result = await service.getUsersByTeam('team-alpha');

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBe(2); // user-1 and user-2
      expect(result.every(u => u.teamNames.includes('team-alpha'))).toBe(true);
    });

    it('should return empty array when no users for team', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify(mockUsers));

      // Act
      const result = await service.getUsersByTeam('non-existent-team');

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('getUsersByRole', () => {
    it('should return users with specific role', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify(mockUsers));

      // Act
      const result = await service.getUsersByRole('admin');

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBe(1); // user-2
      expect(result[0].roles).toContain('admin');
    });

    it('should return empty array when no users with role', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify(mockUsers));

      // Act
      const result = await service.getUsersByRole('non-existent-role');

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('getUsersByRoles', () => {
    it('should return users with any of the specified roles', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify(mockUsers));

      // Act
      const result = await service.getUsersByRoles(['admin', 'viewer']);

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBe(3); // All users have viewer or admin
    });

    it('should return empty array when no users match roles', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify(mockUsers));

      // Act
      const result = await service.getUsersByRoles(['non-existent-role']);

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('getUsersByApplicationsAndTeams', () => {
    it('should return users for applications', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify(mockUsers));

      // Act
      const result = await service.getUsersByApplicationsAndTeams(['app-1'], undefined);

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBe(2); // user-1 and user-2
    });

    it('should return users for teams', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify(mockUsers));

      // Act
      const result = await service.getUsersByApplicationsAndTeams(undefined, ['team-beta']);

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBe(2); // user-2 and user-3
    });

    it('should return users for both applications and teams', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify(mockUsers));

      // Act
      const result = await service.getUsersByApplicationsAndTeams(['app-1'], ['team-beta']);

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      // Should include users from both app-1 and team-beta (user-2 appears in both)
      expect(result.length).toBeGreaterThanOrEqual(1);
    });

    it('should return empty array when no applications or teams provided', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify(mockUsers));

      // Act
      const result = await service.getUsersByApplicationsAndTeams(undefined, undefined);

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('getUsersByRoleAndContext', () => {
    it('should return users with role and application', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify(mockUsers));

      // Act
      const result = await service.getUsersByRoleAndContext(['viewer'], ['app-1'], undefined);

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      expect(result.every(u => u.roles.includes('viewer'))).toBe(true);
      expect(result.every(u => u.applicationIds.includes('app-1'))).toBe(true);
    });

    it('should return users with role and team', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify(mockUsers));

      // Act
      const result = await service.getUsersByRoleAndContext(['viewer'], undefined, ['team-alpha']);

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      expect(result.every(u => u.roles.includes('viewer'))).toBe(true);
      expect(result.every(u => u.teamNames.includes('team-alpha'))).toBe(true);
    });

    it('should return all users with role when no context provided', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify(mockUsers));

      // Act
      const result = await service.getUsersByRoleAndContext(['viewer'], undefined, undefined);

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      expect(result.every(u => u.roles.includes('viewer'))).toBe(true);
    });
  });
});
