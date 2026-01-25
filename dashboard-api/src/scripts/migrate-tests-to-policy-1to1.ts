/**
 * Migration Script: Tests → 1:1 Policy Relationship
 * 
 * Migrates existing tests that reference multiple policies to
 * have a 1:1 relationship with a single policy.
 * 
 * Usage:
 *   npm run migrate:tests-to-policy-1to1
 */

import { TestsService } from '../tests/tests.service';
import { PoliciesService } from '../policies/policies.service';
import { AccessControlTest } from '../../../heimdall-framework/core/types';

/**
 * Main migration function
 */
export async function migrateTestsToPolicy1to1(
  testsService: TestsService,
  policiesService: PoliciesService
): Promise<void> {
  console.log('Starting migration: Tests → 1:1 Policy Relationship');
  
  try {
    // 1. Load all tests
    const allTests = await testsService.findAll();
    console.log(`Found ${allTests.length} tests`);

    // 2. Filter access control tests
    const accessControlTests = allTests.filter(t => t.testType === 'access-control');
    console.log(`Found ${accessControlTests.length} access control tests`);

    let migrated = 0;
    let created = 0;
    let deprecated = 0;

    // 3. For each access control test
    for (const test of accessControlTests) {
      const acTest = test as any; // Type assertion for migration

      // Check if test uses old structure (policyIds array)
      if (acTest.policyIds && Array.isArray(acTest.policyIds)) {
        if (acTest.policyIds.length === 0) {
          console.warn(`Test "${test.name}" (${test.id}) has empty policyIds, skipping`);
          continue;
        }

        if (acTest.policyIds.length === 1) {
          // Single policy - just update to use policyId
          await testsService.update(test.id, {
            policyId: acTest.policyIds[0],
            // Keep policyIds for backward compatibility during migration
          });

          console.log(`✓ Migrated test "${test.name}" (${test.id}) to use policyId: ${acTest.policyIds[0]}`);
          migrated++;
        } else {
          // Multiple policies - create separate tests for each
          console.log(`Test "${test.name}" (${test.id}) references ${acTest.policyIds.length} policies, creating separate tests`);

          for (let i = 0; i < acTest.policyIds.length; i++) {
            const policyId = acTest.policyIds[i];
            
            // Verify policy exists
            try {
              await policiesService.findOne(policyId);
            } catch (error) {
              console.warn(`Policy ${policyId} not found, skipping`);
              continue;
            }

            // Create new test for this policy
            const newTest = {
              ...test,
              id: `${test.id}-policy-${i + 1}`,
              name: `${test.name} (Policy: ${policyId})`,
              policyId: policyId, // 1:1 relationship
              // Convert old structure to new structure if needed
              inputs: acTest.inputs || {
                subject: {
                  role: acTest.role,
                  attributes: {},
                },
                resource: acTest.resource,
                context: acTest.context,
              },
              expected: acTest.expected || {
                allowed: acTest.expectedDecision ?? true,
              },
            };

            await testsService.create(newTest);
            console.log(`  ✓ Created test "${newTest.name}" (${newTest.id}) for policy ${policyId}`);
            created++;
          }

          // Mark original test as deprecated
          await testsService.update(test.id, {
            enabled: false,
            description: `DEPRECATED: Split into ${acTest.policyIds.length} tests with 1:1 policy relationship. Original policyIds: ${acTest.policyIds.join(', ')}`,
          });

          console.log(`  ✓ Deprecated original test "${test.name}" (${test.id})`);
          deprecated++;
        }
      } else if (!acTest.policyId) {
        // Test has no policy reference - warn
        console.warn(`Test "${test.name}" (${test.id}) has no policyId or policyIds, may need manual review`);
      }
    }

    console.log('\nMigration Summary:');
    console.log(`  - Tests migrated (single policy): ${migrated}`);
    console.log(`  - New tests created (multiple policies): ${created}`);
    console.log(`  - Original tests deprecated: ${deprecated}`);
    console.log('Migration complete!');
    
  } catch (error) {
    console.error('Migration failed:', error);
    throw error;
  }
}

/**
 * Standalone execution (if run directly)
 */
if (require.main === module) {
  // This script should be run via run-migrations.ts which bootstraps NestJS
  console.log('This migration script should be run via: npm run migrate');
  process.exit(1);
}
