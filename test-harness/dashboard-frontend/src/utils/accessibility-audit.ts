/**
 * Accessibility Audit Utility
 * Checks for WCAG 2.1 Level AA compliance issues
 */

export interface AccessibilityIssue {
  type: 'error' | 'warning' | 'info';
  element: HTMLElement;
  message: string;
  wcagCriteria?: string;
  suggestion?: string;
}

/**
 * Run accessibility audit on the page
 */
export function runAccessibilityAudit(): AccessibilityIssue[] {
  const issues: AccessibilityIssue[] = [];

  // Check for images without alt text
  const images = document.querySelectorAll('img');
  images.forEach((img) => {
    if (!img.hasAttribute('alt')) {
      issues.push({
        type: 'error',
        element: img as HTMLElement,
        message: 'Image missing alt text',
        wcagCriteria: '1.1.1',
        suggestion: 'Add alt attribute describing the image content',
      });
    } else if (img.getAttribute('alt') === '' && !img.hasAttribute('aria-hidden')) {
      // Decorative images should have aria-hidden="true"
      issues.push({
        type: 'warning',
        element: img as HTMLElement,
        message: 'Image with empty alt should have aria-hidden="true"',
        wcagCriteria: '1.1.1',
        suggestion: 'Add aria-hidden="true" for decorative images',
      });
    }
  });

  // Check for buttons without accessible names
  const buttons = document.querySelectorAll('button');
  buttons.forEach((button) => {
    const accessibleName = getAccessibleName(button);
    if (!accessibleName && !button.hasAttribute('aria-label') && !button.hasAttribute('aria-labelledby')) {
      issues.push({
        type: 'error',
        element: button as HTMLElement,
        message: 'Button missing accessible name',
        wcagCriteria: '4.1.2',
        suggestion: 'Add aria-label, aria-labelledby, or visible text content',
      });
    }
  });

  // Check for form inputs without labels
  const inputs = document.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"]), select, textarea');
  inputs.forEach((input) => {
    const id = input.getAttribute('id');
    const ariaLabel = input.getAttribute('aria-label');
    const ariaLabelledBy = input.getAttribute('aria-labelledby');
    const label = id ? document.querySelector(`label[for="${id}"]`) : null;
    
    if (!ariaLabel && !ariaLabelledBy && !label) {
      issues.push({
        type: 'error',
        element: input as HTMLElement,
        message: 'Form input missing label',
        wcagCriteria: '3.3.2',
        suggestion: 'Add a label element or aria-label attribute',
      });
    }
  });

  // Check for headings hierarchy
  const headings = document.querySelectorAll('h1, h2, h3, h4, h5, h6');
  let previousLevel = 0;
  headings.forEach((heading) => {
    const level = parseInt(heading.tagName.charAt(1));
    if (previousLevel > 0 && level > previousLevel + 1) {
      issues.push({
        type: 'warning',
        element: heading as HTMLElement,
        message: `Heading level skipped from h${previousLevel} to h${level}`,
        wcagCriteria: '1.3.1',
        suggestion: 'Maintain proper heading hierarchy',
      });
    }
    previousLevel = level;
  });

  // Check for tables without headers
  const tables = document.querySelectorAll('table');
  tables.forEach((table) => {
    const hasHeaders = table.querySelectorAll('th').length > 0;
    if (!hasHeaders) {
      issues.push({
        type: 'error',
        element: table as HTMLElement,
        message: 'Table missing header cells',
        wcagCriteria: '1.3.1',
        suggestion: 'Add th elements for table headers',
      });
    }

    // Check for proper scope attributes
    const ths = table.querySelectorAll('th');
    ths.forEach((th) => {
      if (!th.hasAttribute('scope')) {
        issues.push({
          type: 'warning',
          element: th as HTMLElement,
          message: 'Table header missing scope attribute',
          wcagCriteria: '1.3.1',
          suggestion: 'Add scope="col" or scope="row" to th elements',
        });
      }
    });
  });

  // Check for links without accessible names
  const links = document.querySelectorAll('a[href]');
  links.forEach((link) => {
    const accessibleName = getAccessibleName(link);
    if (!accessibleName || accessibleName.trim() === '') {
      issues.push({
        type: 'error',
        element: link as HTMLElement,
        message: 'Link missing accessible name',
        wcagCriteria: '4.1.2',
        suggestion: 'Add text content or aria-label',
      });
    }
  });

  // Check for color contrast (basic check)
  const textElements = document.querySelectorAll('p, span, div, a, button, label');
  textElements.forEach((element) => {
    const style = window.getComputedStyle(element);
    const color = style.color;
    const bgColor = style.backgroundColor;
    
    // This is a simplified check - full contrast checking would require more complex logic
    if (color === bgColor || (color === 'rgba(0, 0, 0, 0)' && bgColor === 'rgba(0, 0, 0, 0)')) {
      issues.push({
        type: 'warning',
        element: element as HTMLElement,
        message: 'Potential color contrast issue',
        wcagCriteria: '1.4.3',
        suggestion: 'Ensure text has sufficient contrast (4.5:1 for normal text, 3:1 for large text)',
      });
    }
  });

  // Check for focusable elements without focus indicators
  const focusableElements = document.querySelectorAll('a, button, input, select, textarea, [tabindex]:not([tabindex="-1"])');
  focusableElements.forEach((element) => {
    const style = window.getComputedStyle(element, ':focus');
    const outline = style.outline;
    const outlineWidth = style.outlineWidth;
    
    if (outline === 'none' || outlineWidth === '0px') {
      issues.push({
        type: 'warning',
        element: element as HTMLElement,
        message: 'Focusable element may lack visible focus indicator',
        wcagCriteria: '2.4.7',
        suggestion: 'Ensure focus is visible with outline or other indicator',
      });
    }
  });

  // Check for landmarks
  const hasMain = document.querySelector('main, [role="main"]');
  if (!hasMain) {
    issues.push({
      type: 'warning',
      element: document.body,
      message: 'Page missing main landmark',
      wcagCriteria: '1.3.1',
      suggestion: 'Add <main> or role="main" to main content area',
    });
  }

  const hasNav = document.querySelector('nav, [role="navigation"]');
  if (!hasNav) {
    issues.push({
      type: 'info',
      element: document.body,
      message: 'Page missing navigation landmark',
      wcagCriteria: '1.3.1',
      suggestion: 'Consider adding <nav> or role="navigation" for navigation areas',
    });
  }

  return issues;
}

/**
 * Get accessible name for an element
 */
function getAccessibleName(element: HTMLElement): string {
  // Check aria-label first
  const ariaLabel = element.getAttribute('aria-label');
  if (ariaLabel) return ariaLabel;
  
  // Check aria-labelledby
  const ariaLabelledBy = element.getAttribute('aria-labelledby');
  if (ariaLabelledBy) {
    const labelElement = document.getElementById(ariaLabelledBy);
    if (labelElement) return labelElement.textContent || '';
  }
  
  // Check associated label
  if (element.id) {
    const label = document.querySelector(`label[for="${element.id}"]`);
    if (label) return label.textContent || '';
  }
  
  // Check title attribute
  const title = element.getAttribute('title');
  if (title) return title;
  
  // Fallback to text content
  return element.textContent?.trim() || '';
}

/**
 * Generate accessibility report
 */
export function generateAccessibilityReport(issues: AccessibilityIssue[]): string {
  const errors = issues.filter(i => i.type === 'error');
  const warnings = issues.filter(i => i.type === 'warning');
  const infos = issues.filter(i => i.type === 'info');

  let report = `# Accessibility Audit Report\n\n`;
  report += `**Summary:**\n`;
  report += `- Errors: ${errors.length}\n`;
  report += `- Warnings: ${warnings.length}\n`;
  report += `- Info: ${infos.length}\n\n`;

  if (errors.length > 0) {
    report += `## Errors (Must Fix)\n\n`;
    errors.forEach((issue, index) => {
      report += `${index + 1}. **${issue.message}**\n`;
      report += `   - Element: ${issue.element.tagName.toLowerCase()}\n`;
      if (issue.wcagCriteria) {
        report += `   - WCAG: ${issue.wcagCriteria}\n`;
      }
      if (issue.suggestion) {
        report += `   - Suggestion: ${issue.suggestion}\n`;
      }
      report += `\n`;
    });
  }

  if (warnings.length > 0) {
    report += `## Warnings (Should Fix)\n\n`;
    warnings.forEach((issue, index) => {
      report += `${index + 1}. **${issue.message}**\n`;
      report += `   - Element: ${issue.element.tagName.toLowerCase()}\n`;
      if (issue.wcagCriteria) {
        report += `   - WCAG: ${issue.wcagCriteria}\n`;
      }
      if (issue.suggestion) {
        report += `   - Suggestion: ${issue.suggestion}\n`;
      }
      report += `\n`;
    });
  }

  return report;
}

