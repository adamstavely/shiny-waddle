export class BatchOperationDto {
  type: 'test' | 'validate' | 'report';
  suite?: string;
  policyFile?: string;
  output?: string;
  config?: string;
}

export class BatchFileDto {
  operations: BatchOperationDto[];
  config?: {
    outputDir?: string;
    parallel?: boolean;
    stopOnError?: boolean;
  };
}
