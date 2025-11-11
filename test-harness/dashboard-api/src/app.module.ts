import { Module } from '@nestjs/common';
import { DashboardModule } from './dashboard/dashboard.module';
import { ApplicationsModule } from './applications/applications.module';
import { AppController } from './app.controller';

@Module({
  imports: [DashboardModule, ApplicationsModule],
  controllers: [AppController],
})
export class AppModule {}

