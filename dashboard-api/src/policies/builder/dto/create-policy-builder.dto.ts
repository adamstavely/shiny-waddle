import { PolicyType } from '../../dto/create-policy.dto';

export class CreateBuilderStateDto {
  policyType: PolicyType;
  policyId?: string; // If editing existing policy
}

export class UpdateBuilderStateDto {
  currentStep?: number;
  formData?: any;
  jsonData?: string;
}

export class CreatePolicyFromBuilderDto {
  stateId: string;
}

export class UpdatePolicyFromBuilderDto {
  stateId: string;
}
