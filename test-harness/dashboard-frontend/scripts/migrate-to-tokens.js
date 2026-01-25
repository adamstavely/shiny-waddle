#!/usr/bin/env node

/**
 * Design Token Migration Helper Script
 * 
 * This script helps identify and migrate hardcoded values to design tokens.
 * 
 * Usage:
 *   node scripts/migrate-to-tokens.js analyze    # Analyze codebase
 *   node scripts/migrate-to-tokens.js migrate    # Migrate (dry-run first!)
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const SRC_DIR = path.join(__dirname, '../src');

// Color mappings
const COLOR_MAPPINGS = [
  // Text colors
  { pattern: /#ffffff/g, replacement: 'var(--color-text-primary)', description: 'White text' },
  { pattern: /#a0aec0/g, replacement: 'var(--color-text-secondary)', description: 'Secondary text' },
  { pattern: /#718096/g, replacement: 'var(--color-text-muted)', description: 'Muted text' },
  { pattern: /#6b7280/g, replacement: 'var(--color-text-muted)', description: 'Muted text alt' },
  
  // Background colors
  { pattern: /#1a1f2e/g, replacement: 'var(--color-bg-secondary)', description: 'Secondary background' },
  { pattern: /#2d3748/g, replacement: 'var(--color-bg-tertiary)', description: 'Tertiary background' },
  { pattern: /#0f1419/g, replacement: 'var(--color-bg-primary)', description: 'Primary background' },
  { pattern: /rgba\(15,\s*20,\s*25,\s*0\.4\)/g, replacement: 'var(--color-bg-overlay)', description: 'Overlay background' },
  { pattern: /rgba\(15,\s*20,\s*25,\s*0\.6\)/g, replacement: 'var(--color-bg-overlay-light)', description: 'Light overlay' },
  { pattern: /rgba\(15,\s*20,\s*25,\s*0\.8\)/g, replacement: 'var(--color-bg-overlay-dark)', description: 'Dark overlay' },
  { pattern: /rgba\(26,\s*31,\s*46,\s*0\.6\)/g, replacement: 'var(--color-bg-overlay-light)', description: 'Light overlay alt' },
  
  // Status colors
  { pattern: /#22c55e/g, replacement: 'var(--color-success)', description: 'Success green' },
  { pattern: /#ef4444/g, replacement: 'var(--color-error)', description: 'Error red' },
  { pattern: /#fc8181/g, replacement: 'var(--color-error)', description: 'Error red light' },
  { pattern: /#fbbf24/g, replacement: 'var(--color-warning)', description: 'Warning yellow' },
  { pattern: /#f59e0b/g, replacement: 'var(--color-warning-dark)', description: 'Warning yellow dark' },
  { pattern: /#4facfe/g, replacement: 'var(--color-primary)', description: 'Primary blue' },
  
  // Border colors
  { pattern: /rgba\(79,\s*172,\s*254,\s*0\.2\)/g, replacement: 'var(--border-color-primary)', description: 'Primary border' },
  { pattern: /rgba\(79,\s*172,\s*254,\s*0\.4\)/g, replacement: 'var(--border-color-primary-hover)', description: 'Primary border hover' },
  { pattern: /rgba\(79,\s*172,\s*254,\s*0\.3\)/g, replacement: 'var(--border-color-secondary)', description: 'Secondary border' },
  { pattern: /rgba\(79,\s*172,\s*254,\s*0\.1\)/g, replacement: 'var(--border-color-muted)', description: 'Muted border' },
  
  // Status backgrounds
  { pattern: /rgba\(34,\s*197,\s*94,\s*0\.2\)/g, replacement: 'var(--color-success-bg)', description: 'Success background' },
  { pattern: /rgba\(239,\s*68,\s*68,\s*0\.2\)/g, replacement: 'var(--color-error-bg)', description: 'Error background' },
  { pattern: /rgba\(251,\s*191,\s*36,\s*0\.2\)/g, replacement: 'var(--color-warning-bg)', description: 'Warning background' },
  { pattern: /rgba\(79,\s*172,\s*254,\s*0\.2\)/g, replacement: 'var(--color-info-bg)', description: 'Info background' },
];

// Spacing mappings (rem values)
const SPACING_MAPPINGS = [
  { pattern: /\b0\.5rem\b/g, replacement: 'var(--spacing-sm)', description: 'Small spacing' },
  { pattern: /\b1rem\b/g, replacement: 'var(--spacing-md)', description: 'Medium spacing' },
  { pattern: /\b1\.5rem\b/g, replacement: 'var(--spacing-lg)', description: 'Large spacing' },
  { pattern: /\b2rem\b/g, replacement: 'var(--spacing-xl)', description: 'XL spacing' },
  { pattern: /\b3rem\b/g, replacement: 'var(--spacing-2xl)', description: '2XL spacing' },
];

// Font size mappings
const FONT_SIZE_MAPPINGS = [
  { pattern: /\b0\.75rem\b/g, replacement: 'var(--font-size-xs)', description: 'Extra small' },
  { pattern: /\b0\.875rem\b/g, replacement: 'var(--font-size-sm)', description: 'Small' },
  { pattern: /\b1rem\b/g, replacement: 'var(--font-size-base)', description: 'Base' },
  { pattern: /\b1\.25rem\b/g, replacement: 'var(--font-size-xl)', description: 'XL' },
  { pattern: /\b1\.5rem\b/g, replacement: 'var(--font-size-2xl)', description: '2XL' },
  { pattern: /\b2rem\b/g, replacement: 'var(--font-size-3xl)', description: '3XL' },
];

// Border radius mappings
const BORDER_RADIUS_MAPPINGS = [
  { pattern: /\b4px\b/g, replacement: 'var(--border-radius-xs)', description: 'XS radius' },
  { pattern: /\b6px\b/g, replacement: 'var(--border-radius-sm)', description: 'SM radius' },
  { pattern: /\b8px\b/g, replacement: 'var(--border-radius-md)', description: 'MD radius' },
  { pattern: /\b12px\b/g, replacement: 'var(--border-radius-lg)', description: 'LG radius' },
  { pattern: /\b16px\b/g, replacement: 'var(--border-radius-xl)', description: 'XL radius' },
];

function findVueFiles(dir) {
  const files = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
      files.push(...findVueFiles(fullPath));
    } else if (entry.isFile() && entry.name.endsWith('.vue')) {
      files.push(fullPath);
    }
  }
  
  return files;
}

function analyzeFile(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const issues = [];
  
  // Check for hardcoded colors
  const colorMatches = content.match(/#[0-9a-fA-F]{3,6}|rgba?\([^)]+\)/g);
  if (colorMatches) {
    const uniqueColors = [...new Set(colorMatches)];
    issues.push({
      type: 'color',
      count: colorMatches.length,
      unique: uniqueColors.length,
      examples: uniqueColors.slice(0, 5)
    });
  }
  
  // Check for hardcoded spacing
  const spacingMatches = content.match(/\b[0-9]+\.?[0-9]*(rem|px)\b/g);
  if (spacingMatches) {
    issues.push({
      type: 'spacing',
      count: spacingMatches.length
    });
  }
  
  return issues.length > 0 ? { file: filePath, issues } : null;
}

function analyze() {
  console.log('🔍 Analyzing codebase for hardcoded values...\n');
  
  const files = findVueFiles(SRC_DIR);
  const results = [];
  
  for (const file of files) {
    const analysis = analyzeFile(file);
    if (analysis) {
      results.push(analysis);
    }
  }
  
  // Sort by total issues
  results.sort((a, b) => {
    const aTotal = a.issues.reduce((sum, i) => sum + i.count, 0);
    const bTotal = b.issues.reduce((sum, i) => sum + i.count, 0);
    return bTotal - aTotal;
  });
  
  console.log(`Found ${results.length} files with hardcoded values:\n`);
  
  results.slice(0, 20).forEach(result => {
    const total = result.issues.reduce((sum, i) => sum + i.count, 0);
    const relativePath = path.relative(SRC_DIR, result.file);
    console.log(`${relativePath}: ${total} hardcoded values`);
    result.issues.forEach(issue => {
      if (issue.type === 'color') {
        console.log(`  - Colors: ${issue.count} (${issue.unique} unique)`);
        if (issue.examples.length > 0) {
          console.log(`    Examples: ${issue.examples.join(', ')}`);
        }
      } else if (issue.type === 'spacing') {
        console.log(`  - Spacing: ${issue.count}`);
      }
    });
    console.log();
  });
  
  const totalIssues = results.reduce((sum, r) => 
    sum + r.issues.reduce((s, i) => s + i.count, 0), 0
  );
  
  console.log(`\n📊 Total: ${totalIssues} hardcoded values across ${results.length} files`);
}

function migrateFile(filePath, dryRun = true) {
  let content = fs.readFileSync(filePath, 'utf8');
  const originalContent = content;
  const changes = [];
  
  // Apply color mappings
  COLOR_MAPPINGS.forEach(({ pattern, replacement, description }) => {
    const matches = content.match(pattern);
    if (matches) {
      content = content.replace(pattern, replacement);
      changes.push(`${matches.length} × ${description}`);
    }
  });
  
  // Apply spacing mappings (be careful with font-size)
  // Only replace spacing values, not font-size
  SPACING_MAPPINGS.forEach(({ pattern, replacement, description }) => {
    // Only replace if it's in padding, margin, gap, etc. (not font-size)
    const spacingContext = /(padding|margin|gap|top|bottom|left|right):\s*([^;]+)/g;
    let match;
    while ((match = spacingContext.exec(content)) !== null) {
      if (match[2].match(pattern)) {
        content = content.replace(new RegExp(`(${match[1]}:\\s*)${pattern.source}`, 'g'), `$1${replacement}`);
        changes.push(`${description} in ${match[1]}`);
      }
    }
  });
  
  if (changes.length > 0) {
    const relativePath = path.relative(SRC_DIR, filePath);
    console.log(`\n📝 ${relativePath}:`);
    changes.forEach(change => console.log(`   - ${change}`));
    
    if (!dryRun) {
      fs.writeFileSync(filePath, content, 'utf8');
      console.log(`   ✅ Migrated`);
    } else {
      console.log(`   ⚠️  Dry run (use --apply to actually migrate)`);
    }
  }
  
  return changes.length > 0;
}

function migrate(dryRun = true) {
  console.log(dryRun ? '🔍 Dry run - no files will be modified\n' : '🚀 Migrating files...\n');
  
  const files = findVueFiles(SRC_DIR);
  let migratedCount = 0;
  
  for (const file of files) {
    if (migrateFile(file, dryRun)) {
      migratedCount++;
    }
  }
  
  console.log(`\n✅ Processed ${migratedCount} files`);
  if (dryRun) {
    console.log('💡 Run with --apply to actually migrate files');
  }
}

// Main
const command = process.argv[2];
const apply = process.argv.includes('--apply');

if (command === 'analyze') {
  analyze();
} else if (command === 'migrate') {
  migrate(!apply);
} else {
  console.log(`
Usage:
  node scripts/migrate-to-tokens.js analyze    # Analyze codebase
  node scripts/migrate-to-tokens.js migrate    # Dry run migration
  node scripts/migrate-to-tokens.js migrate --apply  # Actually migrate files

Note: Always review changes before applying!
  `);
}
