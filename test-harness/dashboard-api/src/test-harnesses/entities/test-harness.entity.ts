export interface TestHarnessEntity {
  id: string;
  name: string;
  description: string;
  testSuiteIds: string[]; // Many-to-many: suites can be in multiple harnesses
  applicationIds: string[]; // Assigned to applications
  team?: string;
  createdAt: Date;
  updatedAt: Date;
}

