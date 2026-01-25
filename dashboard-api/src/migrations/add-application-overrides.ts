/**
 * Migration script to initialize testConfigurationOverrides and validatorOverrides
 * fields for existing applications in the applications.json file.
 * 
 * This ensures backward compatibility by initializing these fields as empty objects
 * for all existing applications.
 */

import * as fs from 'fs/promises';
import * as path from 'path';

const applicationsFile = path.join(process.cwd(), 'data', 'applications.json');

async function migrateApplications() {
  try {
    console.log('Starting migration: Adding override fields to applications...');

    // Read existing applications
    const data = await fs.readFile(applicationsFile, 'utf-8');
    const applications = JSON.parse(data);

    if (!Array.isArray(applications)) {
      console.log('Applications file does not contain an array, skipping migration');
      return;
    }

    let updated = 0;
    const migratedApplications = applications.map((app: any) => {
      const needsUpdate = !app.testConfigurationOverrides || !app.validatorOverrides;
      
      if (needsUpdate) {
        updated++;
        return {
          ...app,
          testConfigurationOverrides: app.testConfigurationOverrides || {},
          validatorOverrides: app.validatorOverrides || {},
        };
      }
      
      return app;
    });

    if (updated > 0) {
      // Create backup
      const backupFile = `${applicationsFile}.backup.${Date.now()}`;
      await fs.copyFile(applicationsFile, backupFile);
      console.log(`Created backup: ${backupFile}`);

      // Write migrated applications
      await fs.writeFile(
        applicationsFile,
        JSON.stringify(migratedApplications, null, 2),
        'utf-8'
      );

      console.log(`Migration completed: Updated ${updated} application(s)`);
    } else {
      console.log('Migration completed: No applications needed updates');
    }
  } catch (error: any) {
    if (error.code === 'ENOENT') {
      console.log('Applications file does not exist, skipping migration');
      return;
    }
    console.error('Error during migration:', error);
    throw error;
  }
}

// Run migration if this file is executed directly
if (require.main === module) {
  migrateApplications()
    .then(() => {
      console.log('Migration script completed successfully');
      process.exit(0);
    })
    .catch((error) => {
      console.error('Migration script failed:', error);
      process.exit(1);
    });
}

export { migrateApplications };

