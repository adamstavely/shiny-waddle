import { BaseTest, TestVersion } from '../../../../heimdall-framework/core/types';

export interface TestEntity extends BaseTest {
  // Test entity extends BaseTest to access common properties
  // The actual test can be any Test type (union), but we use BaseTest
  // for type safety when accessing common properties
}

export interface TestVersionEntity extends TestVersion {
  // Version entity matches the core TestVersion type
}

