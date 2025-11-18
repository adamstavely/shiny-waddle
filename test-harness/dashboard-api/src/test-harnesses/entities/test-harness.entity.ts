export interface TestHarnessEntity {
  id: string;
  name: string;
  description: string;
  domain: string; // Required: all suites in harness must have this domain
  testType?: string; // Deprecated: kept for backward compatibility during migration
  testSuiteIds: string[]; // Many-to-many: suites can be in multiple harnesses (all must match domain)
  applicationIds: string[]; // Assigned to applications
  team?: string;
  createdAt: Date;
  updatedAt: Date;
}

