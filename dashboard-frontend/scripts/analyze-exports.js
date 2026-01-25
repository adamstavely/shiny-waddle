#!/usr/bin/env node

/**
 * Export Usage Analyzer
 * 
 * Analyzes which exports are actually used across the codebase
 * 
 * Usage:
 *   node scripts/analyze-exports.js
 */

const fs = require('fs');
const path = require('path');

const SRC_DIR = path.join(__dirname, '../src');

// Track all exports and their usage
const exports = new Map(); // file -> Set of export names
const imports = new Map(); // file -> Set of imported names from other files

function findFiles(dir, ext = '.ts') {
  const files = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
      files.push(...findFiles(fullPath, ext));
    } else if (entry.isFile() && (entry.name.endsWith(ext) || entry.name.endsWith('.vue'))) {
      files.push(fullPath);
    }
  }
  
  return files;
}

function extractExports(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const fileExports = new Set();
  
  // Match export statements
  const exportPatterns = [
    /export\s+(?:default\s+)?(?:class|interface|type|enum|const|function|let|var)\s+(\w+)/g,
    /export\s*\{\s*([^}]+)\}/g,
    /export\s+default\s+/g,
  ];
  
  for (const pattern of exportPatterns) {
    let match;
    while ((match = pattern.exec(content)) !== null) {
      if (match[1]) {
        // Named exports
        const names = match[1].split(',').map(n => {
          const parts = n.trim().split(/\s+as\s+/);
          return parts[parts.length - 1].trim();
        });
        names.forEach(name => {
          if (name && !name.includes('type') && !name.includes('interface')) {
            fileExports.add(name);
          }
        });
      } else {
        // Default export
        fileExports.add('default');
      }
    }
  }
  
  return fileExports;
}

function extractImports(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const fileImports = new Map(); // importPath -> Set of imported names
  
  // Match import statements
  const importPattern = /import\s+(?:(?:\*\s+as\s+(\w+))|(?:\{([^}]+)\})|(\w+)|default\s+as\s+(\w+))\s+from\s+['"]([^'"]+)['"]/g;
  
  let match;
  while ((match = importPattern.exec(content)) !== null) {
    const namespace = match[1];
    const named = match[2];
    const defaultName = match[3] || match[4];
    const importPath = match[5];
    
    if (!fileImports.has(importPath)) {
      fileImports.set(importPath, new Set());
    }
    
    if (namespace) {
      fileImports.get(importPath).add('*');
    }
    if (named) {
      const names = named.split(',').map(n => {
        const parts = n.trim().split(/\s+as\s+/);
        return parts[0].trim();
      });
      names.forEach(name => fileImports.get(importPath).add(name));
    }
    if (defaultName) {
      fileImports.get(importPath).add('default');
    }
  }
  
  return fileImports;
}

function resolveImportPath(importPath, fromFile) {
  // Resolve relative imports
  if (importPath.startsWith('.')) {
    const dir = path.dirname(fromFile);
    const resolved = path.resolve(dir, importPath);
    
    // Try different extensions
    for (const ext of ['', '.ts', '.vue', '.js']) {
      const withExt = resolved + ext;
      if (fs.existsSync(withExt)) {
        return withExt;
      }
    }
    
    // Try index files
    for (const ext of ['', '.ts', '.vue', '.js']) {
      const indexPath = path.join(resolved, 'index' + ext);
      if (fs.existsSync(indexPath)) {
        return indexPath;
      }
    }
  }
  
  return null;
}

// Step 1: Find all exports
console.log('🔍 Analyzing exports...\n');
const files = findFiles(SRC_DIR);

files.forEach(file => {
  const fileExports = extractExports(file);
  if (fileExports.size > 0) {
    exports.set(file, fileExports);
  }
});

// Step 2: Find all imports
files.forEach(file => {
  const fileImports = extractImports(file);
  imports.set(file, fileImports);
});

// Step 3: Check which exports are used
const unusedExports = [];
const usedExports = [];

exports.forEach((exportNames, file) => {
  exportNames.forEach(exportName => {
    let isUsed = false;
    
    // Check if this export is imported anywhere
    imports.forEach((fileImports, importingFile) => {
      if (importingFile === file) return; // Skip self-imports
      
      fileImports.forEach((importedNames, importPath) => {
        const resolvedPath = resolveImportPath(importPath, importingFile);
        if (resolvedPath === file || importPath.includes(path.basename(file, path.extname(file)))) {
          if (importedNames.has(exportName) || importedNames.has('*') || exportName === 'default') {
            isUsed = true;
          }
        }
      });
    });
    
    const relativePath = path.relative(SRC_DIR, file);
    if (isUsed) {
      usedExports.push({ file: relativePath, export: exportName });
    } else {
      unusedExports.push({ file: relativePath, export: exportName });
    }
  });
});

// Report results
console.log(`📊 Export Analysis Results:\n`);
console.log(`Total exports found: ${Array.from(exports.values()).reduce((sum, exps) => sum + exps.size, 0)}`);
console.log(`Used exports: ${usedExports.length}`);
console.log(`Potentially unused exports: ${unusedExports.length}\n`);

if (unusedExports.length > 0) {
  console.log('⚠️  Potentially Unused Exports:\n');
  const byFile = {};
  unusedExports.forEach(({ file, export: exp }) => {
    if (!byFile[file]) byFile[file] = [];
    byFile[file].push(exp);
  });
  
  Object.entries(byFile)
    .sort((a, b) => b[1].length - a[1].length)
    .slice(0, 20)
    .forEach(([file, exps]) => {
      console.log(`  ${file}:`);
      exps.forEach(exp => console.log(`    - ${exp}`));
    });
  
  if (unusedExports.length > 20) {
    console.log(`\n  ... and ${unusedExports.length - 20} more`);
  }
}

console.log('\n✅ Analysis complete!');
console.log('Note: This is a heuristic analysis. Some exports may be used dynamically.');
