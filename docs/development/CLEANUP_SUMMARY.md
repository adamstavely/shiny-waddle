# Codebase Cleanup Summary

This document summarizes cleanup opportunities identified in the codebase.

## ✅ Completed

1. **Removed `compliance-dashboard.ts`** - Unused dashboard generation code that produced unused JSON files
2. **Removed empty `dashboard/` directory**
3. **Updated `.gitignore`** - Added exclusions for compiled TypeScript output (`.js`, `.js.map` files)

## 🔍 Identified Cleanup Opportunities

### High Priority

#### 1. Compiled JavaScript Files (95+ files)
**Location**: Throughout `test-harness/` directory
**Issue**: TypeScript compilation outputs (`.js` and `.js.map` files) are committed to source control
**Impact**: 
- Increases repository size
- Causes merge conflicts
- Should be generated during build, not committed
**Action**: 
- ✅ Already added to `.gitignore`
- ⚠️ **Need to remove existing .js and .js.map files from git tracking**
- Run: `git rm --cached '**/*.js' '**/*.js.map'` (excluding node_modules, dist, ci-cd, scripts)

#### 2. Deprecated Fields in `core/types.ts`
**Location**: `test-harness/core/types.ts`
**Issue**: Multiple fields marked as `DEPRECATED: Keep for backward compatibility`
**Fields**:
- `policyIds` (line 111) - replaced by `policyId` (1:1 relationship)
- `testType` (line 828) - replaced by `domain`
- Other deprecated fields at lines 161, 178, 194, 217, 262
**Action**: 
- Check if these are still used in production code
- If not used, remove them
- If still used, create migration plan to remove them

#### 3. Duplicate Code: `.ts` and `.js` Files
**Location**: `services/`, `core/` directories
**Issue**: Both TypeScript source (`.ts`) and compiled JavaScript (`.js`) versions exist
**Examples**:
- `services/finding-correlation-engine.ts` + `services/finding-correlation-engine.js`
- `services/normalization-engine.ts` + `services/normalization-engine.js`
**Action**: Remove all `.js` files (they're compilation artifacts)

### Medium Priority

#### 4. TODO Comments (140+ instances)
**Location**: Throughout codebase
**Categories**:
- **Legitimate TODOs**: Features to implement (e.g., "TODO: Load from API when backend is ready")
- **Incomplete Features**: Code with placeholder implementations
- **Auth Context**: Multiple instances of `// TODO: Get from auth context`
**Action**: 
- Review and prioritize TODOs
- Remove TODOs for completed features
- Create issues for remaining TODOs

#### 5. Unused Exports in `index.ts`
**Location**: `test-harness/index.ts`
**Issue**: 24 exports - need to verify all are actually used
**Action**: 
- Check which exports are imported by:
  - `run-tests.ts`
  - Examples directory
  - External consumers
- Remove unused exports

#### 6. Archive Directory
**Location**: `dashboard-api/src/scripts/archive/` (if exists)
**Status**: ✅ **Checked** - Directory does not exist
**Issue**: Archived/migrated code that may no longer be needed
**Action**: 
- ✅ Verified directory does not exist - no action needed

### Low Priority

#### 7. Example Files
**Location**: `test-harness/examples/`
**Status**: ✅ **Keep** - These are documentation/examples, not dead code
**Note**: Examples are standalone and serve as documentation

#### 8. Console.log Statements
**Location**: Various TypeScript files
**Issue**: Debug logging statements in production code
**Action**: 
- Replace with proper logging framework
- Remove debug console.logs
- Keep important error/warn logging

#### 9. Deprecated API Versions
**Location**: Various test suites
**Status**: ✅ **Completed**
**Issue**: Hardcoded deprecated API versions in test code
**Examples**: `services/test-suites/api-design-test-suite.ts` line 308
**Action**: 
- ✅ Made deprecated versions configurable via `APISecurityTestConfig.deprecatedVersions`
- ✅ Updated `api-design-test-suite.ts` and `sensitive-data-test-suite.ts` to use configurable versions
- ✅ Removed hardcoded assumptions (e.g., v1/v0 being deprecated)
- ✅ Tests now skip deprecated version checks if none are configured
**Note**: Tests are still relevant for security testing, but now require explicit configuration of which versions are deprecated for the API being tested

## 📋 Recommended Cleanup Order

1. **Remove compiled .js and .js.map files** (High impact, low risk)
2. **Review and remove deprecated fields** (Medium impact, requires testing)
3. **Clean up TODO comments** (Low impact, improves code quality)
4. **Review unused exports** (Low impact, reduces API surface)
5. **Remove archive directories** (Low impact, if migrations complete)

## 🚨 Notes

- **Backward Compatibility**: Deprecated fields may still be in use. Check data files and API responses before removing.
- **Testing Required**: After removing deprecated fields, test thoroughly to ensure no breaking changes.
- **Git History**: Consider keeping git history for reference even after removing files.

## 📝 Commands for Cleanup

```bash
# Remove compiled JS files from git (but keep locally)
cd test-harness
git rm --cached '**/*.js' '**/*.js.map'
git rm --cached 'services/**/*.js' 'services/**/*.js.map'
git rm --cached 'core/**/*.js' 'core/**/*.js.map'

# Review deprecated field usage
grep -r "\.policyIds\|\.testType" test-harness --include="*.ts" --include="*.vue"

# Find unused exports (requires analysis tool)
# Consider using tools like depcheck or ts-prune
```
