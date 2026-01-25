# Archived Migration Scripts

This directory contains one-time migration scripts that have been archived.

## Scripts

- `migrate-to-individual-tests.ts` - Converts Test Suites with configuration into individual Test entities
- `migrate-test-types.ts` - Migrates test suites and harnesses to type-based structure

## Status

These scripts were used for one-time data migrations and are no longer needed for regular operations. They are kept here for historical reference.

## Usage (if needed)

If you need to run these migrations again (e.g., for a new environment), use:

```bash
npx ts-node scripts/archive/migrate-to-individual-tests.ts
npx ts-node scripts/archive/migrate-test-types.ts
```

**Note**: Always backup your data before running migration scripts.
