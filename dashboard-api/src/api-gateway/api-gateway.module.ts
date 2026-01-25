import { Module } from '@nestjs/common';
import { APIGatewayController } from './api-gateway.controller';
import { APIGatewayService } from './api-gateway.service';
import { ApplicationDataModule } from '../shared/application-data.module';

@Module({
  imports: [ApplicationDataModule],
  controllers: [APIGatewayController],
  providers: [APIGatewayService],
  exports: [APIGatewayService],
})
export class APIGatewayModule {}

