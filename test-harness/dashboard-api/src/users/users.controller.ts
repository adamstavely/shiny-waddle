import { Controller, Get, Param, Query } from '@nestjs/common';
import { UsersService } from './users.service';

@Controller('api/users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get()
  async getAllUsers() {
    return this.usersService.getAllUsers();
  }

  @Get(':id')
  async getUserById(@Param('id') id: string) {
    return this.usersService.getUserById(id);
  }

  @Get('by-application/:applicationId')
  async getUsersByApplication(@Param('applicationId') applicationId: string) {
    return this.usersService.getUsersByApplication(applicationId);
  }

  @Get('by-team/:teamName')
  async getUsersByTeam(@Param('teamName') teamName: string) {
    return this.usersService.getUsersByTeam(teamName);
  }

  @Get('by-role/:role')
  async getUsersByRole(@Param('role') role: string) {
    return this.usersService.getUsersByRole(role);
  }

  @Get('by-context/query')
  async getUsersByContext(
    @Query('applicationIds') applicationIds?: string,
    @Query('teamNames') teamNames?: string,
  ) {
    const appIds = applicationIds ? applicationIds.split(',') : undefined;
    const teams = teamNames ? teamNames.split(',') : undefined;
    return this.usersService.getUsersByApplicationsAndTeams(appIds, teams);
  }
}

