import { Module } from '@nestjs/common';
import { StandardsMappingController } from './standards-mapping.controller';
import { StandardsMappingService } from './standards-mapping.service';

@Module({
  controllers: [StandardsMappingController],
  providers: [StandardsMappingService],
  exports: [StandardsMappingService],
})
export class StandardsMappingModule {}

