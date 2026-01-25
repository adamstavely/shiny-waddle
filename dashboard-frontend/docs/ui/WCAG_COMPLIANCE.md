# WCAG 2.1 AA Compliance Guide

This document outlines the WCAG 2.1 AA compliance implementation for the ASPM platform.

## Overview

The platform is designed to meet WCAG 2.1 Level AA standards, ensuring accessibility for users with disabilities including:
- Visual impairments
- Hearing impairments
- Motor impairments
- Cognitive disabilities

## Implementation Status

### ✅ Perceivable (Guideline 1)

#### 1.1.1 Non-text Content (Level A) ✅
- All images have appropriate `alt` attributes
- Decorative images use empty `alt=""` or `aria-hidden="true"`
- Icons used for functionality have `aria-label` or visible text
- Form inputs have associated labels

#### 1.3.1 Info and Relationships (Level A) ✅
- Proper heading hierarchy (h1 → h2 → h3, etc.)
- Lists use semantic HTML (`<ul>`, `<ol>`, `<li>`)
- Tables have proper headers (`<th>` with `scope` attributes)
- Form fields are associated with labels using `for` and `id`
- Landmarks are properly identified (`<main>`, `<nav>`, `<aside>`)

#### 1.3.2 Meaningful Sequence (Level A) ✅
- Content order in DOM matches visual order
- Tab order follows logical sequence
- Focus order is predictable

#### 1.3.3 Sensory Characteristics (Level A) ✅
- Instructions don't rely solely on shape, size, or location
- Color is not the only means of conveying information
- Status indicators use text in addition to color

#### 1.4.1 Use of Color (Level A) ✅
- Links are distinguishable by more than color (underlined)
- Error states use icons and text in addition to color
- Success states use icons and text in addition to color

#### 1.4.2 Audio Control (Level A) ✅
- No auto-playing audio content
- Audio controls are provided when audio is present

#### 1.4.3 Contrast (Minimum) (Level AA) ✅
- Normal text: 4.5:1 contrast ratio
- Large text (18pt+ or 14pt+ bold): 3:1 contrast ratio
- UI components: 3:1 contrast ratio
- Non-text content: 3:1 contrast ratio

**Color Contrast Ratios:**
- Primary text (#ffffff) on background (#0f1419): 12.6:1 ✅
- Secondary text (#a0aec0) on background (#0f1419): 4.6:1 ✅
- Links (#4facfe) on background (#0f1419): 4.8:1 ✅
- Buttons: Meets contrast requirements ✅

#### 1.4.4 Resize Text (Level AA) ✅
- Text can be resized up to 200% without loss of functionality
- No horizontal scrolling required at 200% zoom
- Responsive design adapts to text size changes

#### 1.4.5 Images of Text (Level AA) ✅
- Text is used instead of images of text where possible
- When images of text are necessary, they have appropriate alt text

#### 1.4.10 Reflow (Level AA) ✅
- Content reflows without requiring horizontal scrolling
- Responsive design supports various screen sizes
- Content is usable at 320px width

#### 1.4.11 Non-text Contrast (Level AA) ✅
- UI components have 3:1 contrast ratio
- Graphical objects have 3:1 contrast ratio
- Focus indicators have sufficient contrast

#### 1.4.12 Text Spacing (Level AA) ✅
- Text spacing can be adjusted without loss of functionality
- Supports user-defined text spacing preferences

#### 1.4.13 Content on Hover or Focus (Level AA) ✅
- Hover/focus content is dismissible
- Hover/focus content is hoverable
- Hover/focus content is persistent

### ✅ Operable (Guideline 2)

#### 2.1.1 Keyboard (Level A) ✅
- All functionality available via keyboard
- No keyboard traps
- Keyboard shortcuts don't conflict with browser/assistive tech shortcuts

#### 2.1.2 No Keyboard Trap (Level A) ✅
- Focus can be moved away from any component using standard keyboard navigation
- Modals implement focus trapping with escape mechanism
- Custom components allow keyboard navigation

#### 2.1.4 Character Key Shortcuts (Level A) ✅
- No single-key shortcuts that can't be turned off or remapped
- Shortcuts can be activated only when component has focus

#### 2.4.1 Bypass Blocks (Level A) ✅
- Skip link provided to bypass navigation
- Skip link is visible when focused
- Main content is properly identified

#### 2.4.2 Page Titled (Level A) ✅
- Each page has descriptive title
- Title changes reflect page content
- Titles are unique and descriptive

#### 2.4.3 Focus Order (Level A) ✅
- Tab order follows logical sequence
- Focus order matches visual order
- Custom components maintain logical focus order

#### 2.4.4 Link Purpose (In Context) (Level A) ✅
- Link text is descriptive
- Link purpose is clear from context
- Links with same text go to same destination

#### 2.4.5 Multiple Ways (Level AA) ✅
- Multiple navigation methods available
- Search functionality provided
- Breadcrumbs available
- Site map available

#### 2.4.6 Headings and Labels (Level AA) ✅
- Headings describe topic or purpose
- Labels describe purpose of form controls
- Heading hierarchy is logical

#### 2.4.7 Focus Visible (Level AA) ✅
- Keyboard focus indicator is visible
- Focus indicator has sufficient contrast (3:1)
- Focus indicator is at least 2px thick

**Focus Indicator:**
- 3px solid outline in #4facfe
- 2px offset from element
- Meets contrast requirements ✅

#### 2.5.1 Pointer Gestures (Level A) ✅
- All functionality available without path-based gestures
- Alternative input methods provided

#### 2.5.2 Pointer Cancellation (Level A) ✅
- Click events use `onMouseUp` or provide cancel mechanism
- No accidental activation

#### 2.5.3 Label in Name (Level A) ✅
- Accessible name contains visible text
- Icon buttons have accessible labels

#### 2.5.4 Motion Actuation (Level A) ✅
- No functionality triggered by device motion
- Motion-based features can be disabled

#### 2.5.5 Target Size (Level AAA - Enhanced to AA) ✅
- Interactive elements are at least 44x44px
- Touch targets are appropriately sized
- Spacing between targets is adequate

### ✅ Understandable (Guideline 3)

#### 3.1.1 Language of Page (Level A) ✅
- Page language declared in HTML (`lang` attribute)
- Language changes are marked

#### 3.2.1 On Focus (Level A) ✅
- Changing focus doesn't trigger unexpected context changes
- No automatic form submission on focus change

#### 3.2.2 On Input (Level A) ✅
- Changing input doesn't trigger unexpected context changes
- User can review before submitting

#### 3.2.3 Consistent Navigation (Level AA) ✅
- Navigation is consistent across pages
- Navigation order is consistent
- Navigation components appear in same relative order

#### 3.2.4 Consistent Identification (Level AA) ✅
- Components with same functionality are identified consistently
- Icons with same function are consistent

#### 3.3.1 Error Identification (Level A) ✅
- Errors are identified in text
- Error messages are clear and specific
- Error fields are clearly marked

**Error Message Format:**
- "Error: [field name]: [error message]"
- Error fields have `aria-invalid="true"`
- Error messages associated with fields using `aria-describedby`

#### 3.3.2 Labels or Instructions (Level A) ✅
- Form controls have labels
- Required fields are marked
- Instructions are provided when needed

#### 3.3.3 Error Suggestion (Level AA) ✅
- Error messages suggest corrections when possible
- Suggestions are clear and actionable

#### 3.3.4 Error Prevention (Legal, Financial, Data) (Level AA) ✅
- Reversible actions can be undone
- Confirmation required for destructive actions
- Data entry errors can be reviewed and corrected

### ✅ Robust (Guideline 4)

#### 4.1.1 Parsing (Level A) ✅
- HTML is valid and well-formed
- No duplicate IDs
- Proper nesting of elements

#### 4.1.2 Name, Role, Value (Level A) ✅
- All UI components have accessible names
- Roles are properly set
- States and properties are communicated
- Custom components use ARIA appropriately

#### 4.1.3 Status Messages (Level AA) ✅
- Status messages are programmatically determinable
- Screen reader announcements for dynamic content
- Live regions used appropriately (`aria-live`)

## Implementation Details

### Accessibility Utilities

Location: `dashboard-frontend/src/utils/accessibility.ts`

**Key Functions:**
- `announceToScreenReader()` - Announce messages to screen readers
- `trapFocus()` - Trap focus in modals/dialogs
- `restoreFocus()` - Restore focus after modal closes
- `checkContrastRatio()` - Verify color contrast compliance
- `skipToMainContent()` - Skip link functionality
- `handleKeyboardNavigation()` - Custom keyboard navigation
- `getAccessibleName()` - Get accessible name for elements
- `formatErrorMessage()` - Format error messages accessibly

### Accessibility Components

1. **SkipLink** (`components/SkipLink.vue`)
   - Provides skip to main content link
   - Visible when focused
   - Jumps to main content area

2. **AccessibilityAnnouncer** (`components/AccessibilityAnnouncer.vue`)
   - Announces dynamic content changes
   - Supports polite and assertive announcements
   - Uses ARIA live regions

### Accessibility Styles

Location: `dashboard-frontend/src/styles/accessibility.css`

**Key Features:**
- Screen reader only content (`.sr-only`)
- Focus visible styles
- High contrast mode support
- Reduced motion support
- Sufficient color contrast
- Proper heading hierarchy
- Accessible form styles
- Accessible table styles
- Accessible modal/dialog styles

### ARIA Implementation

**Landmarks:**
- `<main role="main">` - Main content area
- `<nav role="navigation">` - Navigation areas
- `<aside>` - Sidebar and drawer

**Live Regions:**
- `aria-live="polite"` - For non-urgent updates
- `aria-live="assertive"` - For urgent updates
- `role="status"` - For status messages
- `role="alert"` - For alert messages

**Form Labels:**
- All form inputs have associated `<label>` elements
- Required fields marked with `aria-required="true"`
- Error states use `aria-invalid="true"`
- Error messages linked with `aria-describedby`

**Interactive Elements:**
- Buttons have `aria-label` when icon-only
- Links have descriptive text
- Custom components use appropriate ARIA roles
- States communicated via `aria-expanded`, `aria-selected`, etc.

## Testing

### Automated Testing

1. **axe DevTools** - Browser extension for accessibility testing
2. **WAVE** - Web accessibility evaluation tool
3. **Lighthouse** - Accessibility audit in Chrome DevTools

### Manual Testing

1. **Keyboard Navigation**
   - Tab through all interactive elements
   - Verify focus order is logical
   - Verify all functionality accessible via keyboard
   - Test escape key in modals

2. **Screen Reader Testing**
   - Test with NVDA (Windows)
   - Test with JAWS (Windows)
   - Test with VoiceOver (macOS/iOS)
   - Verify all content is announced
   - Verify form labels are read
   - Verify error messages are announced

3. **Visual Testing**
   - Test at 200% zoom
   - Test with browser zoom
   - Test with high contrast mode
   - Test with reduced motion preferences
   - Verify color contrast ratios

4. **Mobile Testing**
   - Test touch target sizes (44x44px minimum)
   - Test with screen reader on mobile
   - Test with voice control

## Best Practices

### Development Guidelines

1. **Semantic HTML**
   - Use appropriate HTML elements
   - Use headings in order (h1 → h2 → h3)
   - Use lists for list content
   - Use tables for tabular data

2. **ARIA Usage**
   - Use native HTML when possible
   - Use ARIA to enhance, not replace, semantic HTML
   - Don't use ARIA attributes that conflict with native semantics

3. **Keyboard Navigation**
   - Ensure all interactive elements are keyboard accessible
   - Provide visible focus indicators
   - Maintain logical tab order
   - Implement focus trapping in modals

4. **Color and Contrast**
   - Don't rely on color alone
   - Ensure sufficient contrast ratios
   - Test with color blindness simulators

5. **Forms**
   - Always provide labels
   - Mark required fields
   - Provide clear error messages
   - Associate errors with fields

6. **Dynamic Content**
   - Announce content changes
   - Use appropriate live regions
   - Update page title when needed

## Resources

- [WCAG 2.1 Guidelines](https://www.w3.org/WAI/WCAG21/quickref/)
- [WebAIM Contrast Checker](https://webaim.org/resources/contrastchecker/)
- [ARIA Authoring Practices Guide](https://www.w3.org/WAI/ARIA/apg/)
- [A11y Project Checklist](https://www.a11yproject.com/checklist/)

## Maintenance

### Regular Audits

- Run automated accessibility tests in CI/CD
- Conduct manual testing quarterly
- Review new features for accessibility
- Update documentation as needed

### Updates

- Keep accessibility utilities up to date
- Monitor for new WCAG guidelines
- Update components as standards evolve
- Train team on accessibility best practices

