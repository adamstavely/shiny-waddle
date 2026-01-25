import { Module, forwardRef } from '@nestjs/common';
import { APIGatewayController } from './api-gateway.controller';
import { APIGatewayService } from './api-gateway.service';
import { ApplicationsModule } from '../applications/applications.module';

@Module({
  imports: [forwardRef(() => ApplicationsModule)],
  controllers: [APIGatewayController],
  providers: [APIGatewayService],
  exports: [APIGatewayService],
})
export class APIGatewayModule {}

