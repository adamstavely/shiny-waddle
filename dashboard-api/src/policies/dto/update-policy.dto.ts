import { PartialType } from '@nestjs/mapped-types';
import { CreatePolicyDto, PolicyStatus } from './create-policy.dto';

export class UpdatePolicyDto extends PartialType(CreatePolicyDto) {
  status?: PolicyStatus;
}

