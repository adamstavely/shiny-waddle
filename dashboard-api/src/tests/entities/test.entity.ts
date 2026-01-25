import { Test, TestVersion } from '../../../../heimdall-framework/core/types';

export interface TestEntity extends Test {
  // Test entity matches the core Test type
  // Additional fields can be added here if needed for persistence
}

export interface TestVersionEntity extends TestVersion {
  // Version entity matches the core TestVersion type
}

