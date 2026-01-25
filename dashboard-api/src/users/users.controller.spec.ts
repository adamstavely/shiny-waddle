/**
 * Users Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { User } from './entities/user.entity';

describe('UsersController', () => {
  let controller: UsersController;
  let usersService: jest.Mocked<UsersService>;

  const mockUser: User = {
    id: 'user-1',
    email: 'test@example.com',
    name: 'Test User',
    roles: ['admin', 'developer'],
    applicationIds: ['app-1', 'app-2'],
    teamNames: ['team-1'],
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockUsers: User[] = [
    mockUser,
    {
      id: 'user-2',
      email: 'user2@example.com',
      name: 'User Two',
      roles: ['developer'],
      applicationIds: ['app-1'],
      teamNames: ['team-2'],
      createdAt: new Date(),
      updatedAt: new Date(),
    },
  ];

  beforeEach(async () => {
    const mockUsersService = {
      getAllUsers: jest.fn(),
      getUserById: jest.fn(),
      getUsersByApplication: jest.fn(),
      getUsersByTeam: jest.fn(),
      getUsersByRole: jest.fn(),
      getUsersByApplicationsAndTeams: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [UsersController],
      providers: [
        {
          provide: UsersService,
          useValue: mockUsersService,
        },
      ],
    }).compile();

    controller = module.get<UsersController>(UsersController);
    usersService = module.get(UsersService) as jest.Mocked<UsersService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('getAllUsers', () => {
    it('should return all users', async () => {
      // Arrange
      usersService.getAllUsers.mockResolvedValue(mockUsers);

      // Act
      const result = await controller.getAllUsers();

      // Assert
      expect(result).toEqual(mockUsers);
      expect(usersService.getAllUsers).toHaveBeenCalledTimes(1);
      expect(usersService.getAllUsers).toHaveBeenCalledWith();
    });

    it('should return empty array when no users exist', async () => {
      // Arrange
      usersService.getAllUsers.mockResolvedValue([]);

      // Act
      const result = await controller.getAllUsers();

      // Assert
      expect(result).toEqual([]);
      expect(usersService.getAllUsers).toHaveBeenCalledTimes(1);
    });
  });

  describe('getUserById', () => {
    it('should return a user by id', async () => {
      // Arrange
      const userId = 'user-1';
      usersService.getUserById.mockResolvedValue(mockUser);

      // Act
      const result = await controller.getUserById(userId);

      // Assert
      expect(result).toEqual(mockUser);
      expect(usersService.getUserById).toHaveBeenCalledTimes(1);
      expect(usersService.getUserById).toHaveBeenCalledWith(userId);
    });

    it('should return null when user not found', async () => {
      // Arrange
      const userId = 'non-existent';
      usersService.getUserById.mockResolvedValue(null);

      // Act
      const result = await controller.getUserById(userId);

      // Assert
      expect(result).toBeNull();
      expect(usersService.getUserById).toHaveBeenCalledWith(userId);
    });
  });

  describe('getUsersByApplication', () => {
    it('should return users for a specific application', async () => {
      // Arrange
      const applicationId = 'app-1';
      const expectedUsers = [mockUser];
      usersService.getUsersByApplication.mockResolvedValue(expectedUsers);

      // Act
      const result = await controller.getUsersByApplication(applicationId);

      // Assert
      expect(result).toEqual(expectedUsers);
      expect(usersService.getUsersByApplication).toHaveBeenCalledTimes(1);
      expect(usersService.getUsersByApplication).toHaveBeenCalledWith(applicationId);
    });

    it('should return empty array when no users found for application', async () => {
      // Arrange
      const applicationId = 'non-existent-app';
      usersService.getUsersByApplication.mockResolvedValue([]);

      // Act
      const result = await controller.getUsersByApplication(applicationId);

      // Assert
      expect(result).toEqual([]);
      expect(usersService.getUsersByApplication).toHaveBeenCalledWith(applicationId);
    });
  });

  describe('getUsersByTeam', () => {
    it('should return users for a specific team', async () => {
      // Arrange
      const teamName = 'team-1';
      const expectedUsers = [mockUser];
      usersService.getUsersByTeam.mockResolvedValue(expectedUsers);

      // Act
      const result = await controller.getUsersByTeam(teamName);

      // Assert
      expect(result).toEqual(expectedUsers);
      expect(usersService.getUsersByTeam).toHaveBeenCalledTimes(1);
      expect(usersService.getUsersByTeam).toHaveBeenCalledWith(teamName);
    });

    it('should return empty array when no users found for team', async () => {
      // Arrange
      const teamName = 'non-existent-team';
      usersService.getUsersByTeam.mockResolvedValue([]);

      // Act
      const result = await controller.getUsersByTeam(teamName);

      // Assert
      expect(result).toEqual([]);
      expect(usersService.getUsersByTeam).toHaveBeenCalledWith(teamName);
    });
  });

  describe('getUsersByRole', () => {
    it('should return users for a specific role', async () => {
      // Arrange
      const role = 'admin';
      const expectedUsers = [mockUser];
      usersService.getUsersByRole.mockResolvedValue(expectedUsers);

      // Act
      const result = await controller.getUsersByRole(role);

      // Assert
      expect(result).toEqual(expectedUsers);
      expect(usersService.getUsersByRole).toHaveBeenCalledTimes(1);
      expect(usersService.getUsersByRole).toHaveBeenCalledWith(role);
    });

    it('should return empty array when no users found for role', async () => {
      // Arrange
      const role = 'non-existent-role';
      usersService.getUsersByRole.mockResolvedValue([]);

      // Act
      const result = await controller.getUsersByRole(role);

      // Assert
      expect(result).toEqual([]);
      expect(usersService.getUsersByRole).toHaveBeenCalledWith(role);
    });
  });

  describe('getUsersByContext', () => {
    it('should return users by application IDs', async () => {
      // Arrange
      const applicationIds = 'app-1,app-2';
      const expectedUsers = [mockUser];
      usersService.getUsersByApplicationsAndTeams.mockResolvedValue(expectedUsers);

      // Act
      const result = await controller.getUsersByContext(applicationIds, undefined);

      // Assert
      expect(result).toEqual(expectedUsers);
      expect(usersService.getUsersByApplicationsAndTeams).toHaveBeenCalledTimes(1);
      expect(usersService.getUsersByApplicationsAndTeams).toHaveBeenCalledWith(
        ['app-1', 'app-2'],
        undefined
      );
    });

    it('should return users by team names', async () => {
      // Arrange
      const teamNames = 'team-1,team-2';
      const expectedUsers = [mockUser];
      usersService.getUsersByApplicationsAndTeams.mockResolvedValue(expectedUsers);

      // Act
      const result = await controller.getUsersByContext(undefined, teamNames);

      // Assert
      expect(result).toEqual(expectedUsers);
      expect(usersService.getUsersByApplicationsAndTeams).toHaveBeenCalledWith(
        undefined,
        ['team-1', 'team-2']
      );
    });

    it('should return users by both application IDs and team names', async () => {
      // Arrange
      const applicationIds = 'app-1';
      const teamNames = 'team-1';
      const expectedUsers = [mockUser];
      usersService.getUsersByApplicationsAndTeams.mockResolvedValue(expectedUsers);

      // Act
      const result = await controller.getUsersByContext(applicationIds, teamNames);

      // Assert
      expect(result).toEqual(expectedUsers);
      expect(usersService.getUsersByApplicationsAndTeams).toHaveBeenCalledWith(
        ['app-1'],
        ['team-1']
      );
    });

    it('should handle single application ID without comma', async () => {
      // Arrange
      const applicationIds = 'app-1';
      const expectedUsers = [mockUser];
      usersService.getUsersByApplicationsAndTeams.mockResolvedValue(expectedUsers);

      // Act
      const result = await controller.getUsersByContext(applicationIds, undefined);

      // Assert
      expect(result).toEqual(expectedUsers);
      expect(usersService.getUsersByApplicationsAndTeams).toHaveBeenCalledWith(
        ['app-1'],
        undefined
      );
    });

    it('should handle empty query parameters', async () => {
      // Arrange
      usersService.getUsersByApplicationsAndTeams.mockResolvedValue([]);

      // Act
      const result = await controller.getUsersByContext(undefined, undefined);

      // Assert
      expect(result).toEqual([]);
      expect(usersService.getUsersByApplicationsAndTeams).toHaveBeenCalledWith(
        undefined,
        undefined
      );
    });

    it('should handle empty string query parameters', async () => {
      // Arrange
      usersService.getUsersByApplicationsAndTeams.mockResolvedValue([]);

      // Act
      const result = await controller.getUsersByContext('', '');

      // Assert
      expect(result).toEqual([]);
      expect(usersService.getUsersByApplicationsAndTeams).toHaveBeenCalledWith(
        undefined,
        undefined
      );
    });
  });
});
