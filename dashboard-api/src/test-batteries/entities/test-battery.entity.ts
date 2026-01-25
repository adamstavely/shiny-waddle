import { BatteryExecutionConfig } from '../../../../heimdall-framework/core/types';

export interface TestBatteryEntity {
  id: string;
  name: string;
  description?: string;
  harnessIds: string[]; // Collection of test harnesses
  executionConfig?: BatteryExecutionConfig;
  team?: string;
  createdAt: Date;
  updatedAt: Date;
}

