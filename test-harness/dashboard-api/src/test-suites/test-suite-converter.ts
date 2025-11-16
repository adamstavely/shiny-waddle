/**
 * Test Suite Converter
 * 
 * Utilities for converting between TypeScript test suite files and JSON format
 */

import { TestSuite } from '../../../core/types';
import * as fs from 'fs/promises';
import * as path from 'path';

export interface ParsedTestSuite {
  name: string;
  application: string;
  team: string;
  testTypes: string[];
  description?: string;
  fullConfig?: TestSuite;
}

/**
 * Extract TestSuite configuration from TypeScript file content
 * Handles both `export const suiteName: TestSuite = {...}` and class-based suites
 */
export function parseTypeScriptTestSuite(tsContent: string, filePath: string): ParsedTestSuite | null {
  try {
    // Try to extract exported const TestSuite
    const constExportMatch = tsContent.match(/export\s+const\s+(\w+)\s*:\s*TestSuite\s*=\s*({[\s\S]*?});/);
    if (constExportMatch) {
      const configStr = constExportMatch[2];
      // Extract basic properties using regex (simple approach)
      const nameMatch = configStr.match(/name\s*:\s*['"]([^'"]+)['"]/);
      const applicationMatch = configStr.match(/application\s*:\s*['"]([^'"]+)['"]/);
      const teamMatch = configStr.match(/team\s*:\s*['"]([^'"]+)['"]/);
      
      // Determine test types
      const testTypes: string[] = [];
      if (configStr.includes('includeAccessControlTests') && configStr.match(/includeAccessControlTests\s*:\s*true/)) {
        testTypes.push('access-control');
      }
      if (configStr.includes('includeDataBehaviorTests') && configStr.match(/includeDataBehaviorTests\s*:\s*true/)) {
        testTypes.push('data-behavior');
      }
      if (configStr.includes('includeDatasetHealthTests') && configStr.match(/includeDatasetHealthTests\s*:\s*true/)) {
        testTypes.push('dataset-health');
      }

      const name = nameMatch ? nameMatch[1] : path.basename(filePath, '.ts');
      const application = applicationMatch ? applicationMatch[1] : 'unknown';
      const team = teamMatch ? teamMatch[1] : 'unknown';

      return {
        name,
        application,
        team,
        testTypes,
        description: `TypeScript test suite from ${path.basename(filePath)}`,
      };
    }

    // Try to extract class-based test suite metadata
    const classMatch = tsContent.match(/export\s+class\s+(\w+TestSuite)\s+extends\s+BaseTestSuite/);
    if (classMatch) {
      const className = classMatch[1];
      // Extract test suite name from class name (e.g., AuthenticationTestSuite -> Authentication)
      const suiteName = className.replace(/TestSuite$/, '');
      
      // Try to extract any comments or metadata
      const commentMatch = tsContent.match(/\/\*\*[\s\S]*?\*\/\s*export\s+class/);
      let description = `${suiteName} Test Suite`;
      if (commentMatch) {
        const comment = commentMatch[0];
        const descMatch = comment.match(/\*\s*(.+?)(?:\n|$)/);
        if (descMatch) {
          description = descMatch[1].trim();
        }
      }

      // For class-based suites, we can't extract full config, but we can infer test types
      // based on the class name or file name
      const testTypes: string[] = [];
      const fileName = path.basename(filePath, '.ts').toLowerCase();
      if (fileName.includes('authentication') || fileName.includes('auth')) {
        testTypes.push('authentication');
      }
      if (fileName.includes('authorization') || fileName.includes('access')) {
        testTypes.push('authorization');
      }
      if (fileName.includes('injection')) {
        testTypes.push('injection');
      }
      if (fileName.includes('rate') || fileName.includes('limiting')) {
        testTypes.push('rate-limiting');
      }
      if (fileName.includes('security') || fileName.includes('header')) {
        testTypes.push('security-headers');
      }
      if (fileName.includes('graphql')) {
        testTypes.push('graphql');
      }
      if (fileName.includes('sensitive') || fileName.includes('data')) {
        testTypes.push('sensitive-data');
      }
      if (fileName.includes('cryptography') || fileName.includes('crypto')) {
        testTypes.push('cryptography');
      }
      if (fileName.includes('api') || fileName.includes('design')) {
        testTypes.push('api-design');
      }
      if (fileName.includes('business') || fileName.includes('logic')) {
        testTypes.push('business-logic');
      }
      if (fileName.includes('third') || fileName.includes('integration')) {
        testTypes.push('third-party-integration');
      }
      if (fileName.includes('logging') || fileName.includes('log')) {
        testTypes.push('logging');
      }
      if (fileName.includes('rls') || fileName.includes('cls')) {
        testTypes.push('rls-cls');
      }

      return {
        name: suiteName,
        application: 'api-security', // Default for class-based suites
        team: 'security-team',
        testTypes: testTypes.length > 0 ? testTypes : ['api-security'],
        description,
      };
    }

    return null;
  } catch (error) {
    console.error('Error parsing TypeScript test suite:', error);
    return null;
  }
}

/**
 * Convert TestSuite JSON to TypeScript file content
 */
export function convertJSONToTypeScript(
  json: TestSuite,
  originalPath?: string,
  originalContent?: string
): string {
  const suiteName = json.name
    .replace(/[^a-zA-Z0-9]/g, '')
    .replace(/^[a-z]/, (c) => c.toUpperCase())
    .replace(/-([a-z])/g, (_, c) => c.toUpperCase()) + 'TestSuite';

  // Try to preserve original file structure if available
  if (originalContent && originalPath) {
    // If it was a const export, try to update it
    const constExportMatch = originalContent.match(/export\s+const\s+(\w+)\s*:\s*TestSuite\s*=\s*({[\s\S]*?});/);
    if (constExportMatch) {
      const originalVarName = constExportMatch[1];
      const configStr = JSON.stringify(json, null, 2);
      return `/**
 * ${json.name}
 * ${json.description || `Test suite for ${json.application}`}
 */

import { TestSuite } from '../core/types';

export const ${originalVarName}: TestSuite = ${configStr};
`;
    }
  }

  // Generate new TypeScript file
  const configStr = JSON.stringify(json, null, 2);
  return `/**
 * ${json.name}
 * ${json.description || `Test suite for ${json.application}`}
 */

import { TestSuite } from '../core/types';

export const ${suiteName}: TestSuite = ${configStr};
`;
}

/**
 * Extract full TestSuite object from TypeScript file (for const exports)
 * Converts TypeScript object literal to JSON and parses it
 */
export async function extractTestSuiteFromTypeScript(filePath: string): Promise<TestSuite | null> {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    return extractTestSuiteFromContent(content, filePath);
  } catch (error) {
    console.error('Error extracting TestSuite from TypeScript:', error);
    return null;
  }
}

/**
 * Extract TestSuite from TypeScript content string
 */
export function extractTestSuiteFromContent(tsContent: string, filePath?: string): TestSuite | null {
  try {
    // Find the const export pattern: export const name: TestSuite = { ... };
    const constExportMatch = tsContent.match(/export\s+const\s+\w+\s*:\s*TestSuite\s*=\s*({)/);
    if (!constExportMatch) {
      return null;
    }

    // Find the matching closing brace by counting braces
    const startIndex = constExportMatch.index! + constExportMatch[0].length - 1; // Position of opening {
    let braceCount = 0;
    let i = startIndex;
    let endIndex = -1;

    while (i < tsContent.length) {
      const char = tsContent[i];
      const prevChar = i > 0 ? tsContent[i - 1] : '';

      // Check if we're in a string (simple check - doesn't handle all edge cases)
      const isInString = (() => {
        let inStr = false;
        let strChar = '';
        for (let j = startIndex; j < i; j++) {
          const c = tsContent[j];
          const p = j > 0 ? tsContent[j - 1] : '';
          if (!inStr && (c === '"' || c === "'")) {
            inStr = true;
            strChar = c;
          } else if (inStr && c === strChar && p !== '\\') {
            inStr = false;
          }
        }
        return inStr;
      })();

      if (!isInString) {
        if (char === '{') {
          braceCount++;
        } else if (char === '}') {
          braceCount--;
          if (braceCount === 0) {
            endIndex = i;
            break;
          }
        }
      }
      i++;
    }

    if (endIndex === -1) {
      // Couldn't find matching brace, try fallback
      return extractTestSuiteProperties(tsContent);
    }

    let objectStr = tsContent.substring(startIndex + 1, endIndex);
    
    // Remove comments (single-line and multi-line)
    objectStr = objectStr.replace(/\/\/.*$/gm, ''); // Single-line comments
    objectStr = objectStr.replace(/\/\*[\s\S]*?\*\//g, ''); // Multi-line comments
    
    // Convert TypeScript object to JSON-compatible string
    // Handle trailing commas
    objectStr = objectStr.replace(/,(\s*[}\]])/g, '$1');
    
    // Handle single quotes -> double quotes for JSON
    // This is tricky because we need to handle escaped quotes properly
    objectStr = convertTypeScriptObjectToJSON(objectStr);
    
    try {
      const parsed = JSON.parse(objectStr);
      return parsed as TestSuite;
    } catch (parseError) {
      console.error('Error parsing extracted object as JSON:', parseError);
      // Fallback: try to extract key properties manually
      return extractTestSuiteProperties(tsContent);
    }
  } catch (error) {
    console.error('Error extracting TestSuite from content:', error);
    return null;
  }
}

/**
 * Convert TypeScript object literal syntax to JSON
 * Handles single quotes, trailing commas, and basic TypeScript features
 */
function convertTypeScriptObjectToJSON(tsObject: string): string {
  let json = tsObject;
  let inString = false;
  let stringChar = '';
  let result = '';
  let i = 0;

  while (i < json.length) {
    const char = json[i];
    const prevChar = i > 0 ? json[i - 1] : '';
    const nextChar = i < json.length - 1 ? json[i + 1] : '';

    if (!inString) {
      if (char === '"' || char === "'") {
        inString = true;
        stringChar = char;
        result += '"'; // Always use double quotes in JSON
      } else if (char === '{' || char === '[') {
        result += char;
      } else if (char === '}' || char === ']') {
        // Remove trailing comma before closing brace/bracket
        if (result.endsWith(',')) {
          result = result.slice(0, -1);
        }
        result += char;
      } else if (char === ',' && (nextChar === '}' || nextChar === ']' || nextChar === '\n' && /^\s*[}\]]/m.test(json.slice(i + 1)))) {
        // Skip trailing comma
      } else {
        result += char;
      }
    } else {
      if (char === stringChar && prevChar !== '\\') {
        inString = false;
        result += '"';
      } else if (char === '\\' && nextChar === stringChar) {
        result += '\\' + nextChar;
        i++; // Skip next char as we've handled it
      } else if (char === '\n' && stringChar === "'") {
        // Single-quoted strings can span lines in TS, but not in JSON
        // Replace with space
        result += ' ';
      } else {
        result += char === stringChar && stringChar === "'" ? char : (char === "'" ? "\\'" : char);
      }
    }
    i++;
  }

  return result;
}

/**
 * Fallback: Extract TestSuite properties using regex when JSON parsing fails
 */
function extractTestSuiteProperties(tsContent: string): TestSuite | null {
  try {
    const suite: any = {};

    // Extract basic properties
    const nameMatch = tsContent.match(/name\s*:\s*['"]([^'"]+)['"]/);
    if (nameMatch) suite.name = nameMatch[1];

    const appMatch = tsContent.match(/application\s*:\s*['"]([^'"]+)['"]/);
    if (appMatch) suite.application = appMatch[1];

    const teamMatch = tsContent.match(/team\s*:\s*['"]([^'"]+)['"]/);
    if (teamMatch) suite.team = teamMatch[1];

    // Extract boolean flags
    suite.includeAccessControlTests = /includeAccessControlTests\s*:\s*true/.test(tsContent);
    suite.includeDataBehaviorTests = /includeDataBehaviorTests\s*:\s*true/.test(tsContent);
    suite.includeDatasetHealthTests = /includeDatasetHealthTests\s*:\s*true/.test(tsContent);

    // Extract userRoles array
    const rolesMatch = tsContent.match(/userRoles\s*:\s*\[([^\]]+)\]/);
    if (rolesMatch) {
      suite.userRoles = rolesMatch[1]
        .split(',')
        .map(r => r.trim().replace(/['"]/g, ''))
        .filter(r => r);
    }

    // For complex nested structures, we'd need a more sophisticated parser
    // This fallback provides basic structure that can be edited
    suite.resources = [];
    suite.contexts = [];
    suite.testQueries = [];
    suite.allowedFields = {};
    suite.requiredFilters = {};
    suite.contracts = [];
    suite.datasets = [];

    return suite as TestSuite;
  } catch (error) {
    console.error('Error in fallback extraction:', error);
    return null;
  }
}

