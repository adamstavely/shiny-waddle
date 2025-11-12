import { Module } from '@nestjs/common';
import { APIGatewayController } from './api-gateway.controller';
import { APIGatewayService } from './api-gateway.service';

@Module({
  controllers: [APIGatewayController],
  providers: [APIGatewayService],
  exports: [APIGatewayService],
})
export class APIGatewayModule {}

