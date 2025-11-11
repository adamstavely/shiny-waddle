import { Module } from '@nestjs/common';
import { DashboardModule } from './dashboard/dashboard.module';
import { AppController } from './app.controller';

@Module({
  imports: [DashboardModule],
  controllers: [AppController],
})
export class AppModule {}

