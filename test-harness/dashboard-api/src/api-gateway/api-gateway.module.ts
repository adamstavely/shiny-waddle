import { Module, forwardRef } from '@nestjs/common';
import { APIGatewayController } from './api-gateway.controller';
import { APIGatewayService } from './api-gateway.service';
import { TestConfigurationsModule } from '../test-configurations/test-configurations.module';

@Module({
  imports: [forwardRef(() => TestConfigurationsModule)],
  controllers: [APIGatewayController],
  providers: [APIGatewayService],
  exports: [APIGatewayService],
})
export class APIGatewayModule {}

