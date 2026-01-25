# Heimdall CLI

Command-line interface for the Heimdall Data Access Testing Framework.

## Installation

The CLI is included with the Heimdall framework. To use it:

```bash
# Install dependencies
npm install

# Run CLI commands using ts-node
npx ts-node heimdall-framework/cli/index.ts <command>
```

Or add to your `package.json`:

```json
{
  "scripts": {
    "heimdall": "ts-node heimdall-framework/cli/index.ts"
  }
}
```

Then run: `npm run heimdall <command>`

## Commands

### Template Commands

#### List Templates
```bash
heimdall template list
```

Lists all available policy templates (RBAC, ABAC, HIPAA, GDPR).

#### Preview Template
```bash
heimdall template preview <template-name>
```

Shows detailed information about a template.

#### Create Policy from Template
```bash
heimdall template create <template-name> [options]
```

Creates a policy file from a template.

**Options:**
- `-a, --application-name <name>` - Application name
- `-o, --output <file>` - Output file path (default: `policy.json`)
- `-i, --interactive` - Interactive mode for configuration

**Template-specific options:**

**RBAC:**
- `--roles <roles>` - Comma-separated roles (e.g., `admin,user,viewer`)
- `--resources <resources>` - Comma-separated resources (e.g., `dataset,report`)
- `--actions <actions>` - Comma-separated actions (e.g., `read,write`)

**ABAC:**
- `--departments <departments>` - Comma-separated departments
- `--clearance-levels <levels>` - Comma-separated clearance levels
- `--data-classifications <classifications>` - Comma-separated data classifications
- `--projects <projects>` - Comma-separated projects

**HIPAA:**
- `--covered-entities <entities>` - Comma-separated covered entities
- `--business-associates <associates>` - Comma-separated business associates

**GDPR:**
- `--data-controllers <controllers>` - Comma-separated data controllers
- `--data-processors <processors>` - Comma-separated data processors
- `--eu-member-states <states>` - Comma-separated EU member state codes

**Examples:**
```bash
# Create RBAC policy
heimdall template create rbac --application-name "MyApp" \
  --roles admin,user,viewer \
  --resources dataset,report \
  --output ./policies/rbac-policy.json

# Create HIPAA policy interactively
heimdall template create hipaa --interactive

# Create GDPR policy
heimdall template create gdpr --application-name "DataApp" \
  --data-controllers company1,company2 \
  --eu-member-states DE,FR,IT
```

### Test Commands

#### Quick Test
```bash
heimdall test quick [options]
```

Runs tests with default settings.

**Options:**
- `-s, --suite <suite>` - Test suite name (default: `default`)
- `-o, --output <dir>` - Output directory (default: `./reports`)
- `-c, --config <file>` - Runtime config file

#### Test Specific Suite
```bash
heimdall test suite <suite-name> [options]
```

Runs a specific test suite.

**Options:**
- `-o, --output <dir>` - Output directory
- `-c, --config <file>` - Runtime config file

#### Test Specific Application
```bash
heimdall test app <app-name> [options]
```

Runs tests for a specific application.

**Options:**
- `-s, --suite <suite>` - Test suite name (default: `default`)
- `-o, --output <dir>` - Output directory
- `-c, --config <file>` - Runtime config file

#### Watch Mode
```bash
heimdall test watch [options]
```

Continuously watches for file changes and re-runs tests.

**Options:**
- `-s, --suite <suite>` - Test suite name
- `-o, --output <dir>` - Output directory
- `-c, --config <file>` - Runtime config file
- `--watch-dirs <dirs>` - Comma-separated directories to watch

**Note:** Requires `chokidar` package: `npm install --save-dev chokidar`

#### Parallel Execution
```bash
heimdall test parallel [options]
```

Runs tests in parallel (currently runs sequentially, parallel execution coming soon).

**Options:**
- `-s, --suite <suite>` - Test suite name
- `-o, --output <dir>` - Output directory
- `-c, --config <file>` - Runtime config file
- `-j, --jobs <count>` - Number of parallel jobs (default: `4`)

#### Filter Tests
```bash
heimdall test filter <pattern> [options]
```

Filters tests by pattern (regex).

**Options:**
- `-s, --suite <suite>` - Test suite name
- `-o, --output <dir>` - Output directory
- `-c, --config <file>` - Runtime config file

#### List Test Suites
```bash
heimdall test list-suites
```

Lists all available test suites.

**Examples:**
```bash
# Quick test
heimdall test quick

# Test specific suite
heimdall test suite abac-completeness

# Test application with watch mode
heimdall test app my-app --suite default --watch

# Filter tests
heimdall test filter "access-control" --suite default
```

### Batch Commands

#### Run Batch Operations
```bash
heimdall batch run <file>
```

Runs all operations from a batch file (JSON or YAML).

#### Batch Test
```bash
heimdall batch test <file>
```

Runs only test operations from a batch file.

#### Batch Validate
```bash
heimdall batch validate <file>
```

Runs only validation operations from a batch file.

#### Batch Report
```bash
heimdall batch report <file>
```

Runs only report operations from a batch file.

**Batch File Format:**

```json
{
  "operations": [
    {
      "type": "test",
      "suite": "default",
      "output": "test-results-default",
      "config": "./config/runtime-config.json"
    },
    {
      "type": "validate",
      "policyFile": "./policies/abac-policies.json",
      "output": "validation-results"
    },
    {
      "type": "report",
      "output": "final-report"
    }
  ],
  "config": {
    "outputDir": "./reports",
    "parallel": false,
    "stopOnError": true
  }
}
```

**YAML Format:**

```yaml
operations:
  - type: test
    suite: default
    output: test-results-default
    config: ./config/runtime-config.json
  
  - type: validate
    policyFile: ./policies/abac-policies.json
    output: validation-results
  
  - type: report
    output: final-report

config:
  outputDir: ./reports
  parallel: false
  stopOnError: true
```

**Examples:**
```bash
# Run all operations
heimdall batch run ./cli/examples/batch-example.json

# Run only tests
heimdall batch test ./cli/examples/batch-example.json

# Run with YAML file
heimdall batch run ./cli/examples/batch-example.yaml
```

## Templates

### RBAC Template
Creates role-based access control policies. Each role is assigned permissions to specific resources.

### ABAC Template
Creates attribute-based access control policies. Supports department matching, clearance levels, project access, location-based access, and time-based restrictions.

### HIPAA Template
Creates policies compliant with HIPAA regulations for protecting Protected Health Information (PHI). Includes minimum necessary rules, access controls, audit logging, encryption requirements, and business associate agreements.

### GDPR Template
Creates policies compliant with GDPR regulations for protecting personal data of EU citizens. Includes rights to access and erasure, data minimization, purpose limitation, cross-border transfer restrictions, consent requirements, and breach notification.

## Examples

See `heimdall-framework/cli/examples/` for example batch files.
