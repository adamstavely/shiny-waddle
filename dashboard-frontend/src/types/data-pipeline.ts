export interface DataPipelineConfigurationEntity {
  id: string;
  name: string;
  type: 'data-pipeline';
  description?: string;
  pipelineType: 'etl' | 'streaming' | 'batch' | 'real-time';
  connection?: {
    type: 'kafka' | 'spark' | 'airflow' | 'dbt' | 'custom';
    endpoint?: string;
    credentials?: Record<string, string>;
  };
  dataSource?: {
    type: 'database' | 'api' | 'file' | 'stream';
    connectionString?: string;
  };
  dataDestination?: {
    type: 'database' | 'data-warehouse' | 'data-lake' | 'api';
    connectionString?: string;
  };
  testLogic?: {
    validateAccessControl?: boolean;
    checkDataQuality?: boolean;
    validateTransformations?: boolean;
    customValidations?: Array<{
      name: string;
      condition: string;
      description?: string;
    }>;
  };
  createdAt: Date;
  updatedAt: Date;
  createdBy?: string;
  tags?: string[];
  enabled: boolean;
}

