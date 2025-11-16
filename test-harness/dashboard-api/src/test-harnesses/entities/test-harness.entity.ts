export interface TestHarnessEntity {
  id: string;
  name: string;
  description: string;
  testType: string; // Required: all suites in harness must have this type
  testSuiteIds: string[]; // Many-to-many: suites can be in multiple harnesses (all must match testType)
  applicationIds: string[]; // Assigned to applications
  team?: string;
  createdAt: Date;
  updatedAt: Date;
}

