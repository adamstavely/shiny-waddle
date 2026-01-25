# WCAG 2.1 AA Accessibility Checklist

This checklist helps ensure all components and pages meet WCAG 2.1 AA standards.

## Perceivable

### Text Alternatives
- [ ] All images have appropriate `alt` attributes
- [ ] Decorative images use `alt=""` or `aria-hidden="true"`
- [ ] Icons used for functionality have `aria-label` or visible text
- [ ] Complex images have detailed descriptions

### Time-based Media
- [ ] Audio content has transcripts
- [ ] Video content has captions
- [ ] No auto-playing audio

### Adaptable
- [ ] Content can be presented without losing information
- [ ] Proper heading hierarchy (h1 → h2 → h3)
- [ ] Lists use semantic HTML (`<ul>`, `<ol>`)
- [ ] Tables have proper headers
- [ ] Form fields are associated with labels

### Distinguishable
- [ ] Color contrast meets 4.5:1 for normal text
- [ ] Color contrast meets 3:1 for large text
- [ ] Color is not the only means of conveying information
- [ ] Text can be resized up to 200% without loss of functionality
- [ ] No horizontal scrolling at 200% zoom
- [ ] Images of text are avoided where possible

## Operable

### Keyboard Accessible
- [ ] All functionality available via keyboard
- [ ] No keyboard traps
- [ ] Tab order is logical
- [ ] Focus order matches visual order
- [ ] Custom components support keyboard navigation

### Enough Time
- [ ] No time limits (or can be extended)
- [ ] Moving content can be paused
- [ ] Auto-updating content can be paused

### Seizures and Physical Reactions
- [ ] No flashing content (more than 3 flashes per second)
- [ ] No motion animation triggers (or can be disabled)

### Navigable
- [ ] Skip link provided
- [ ] Page titles are descriptive
- [ ] Focus order is logical
- [ ] Link purpose is clear from context
- [ ] Multiple ways to navigate (search, breadcrumbs, etc.)
- [ ] Headings and labels are descriptive
- [ ] Focus indicator is visible (3px, sufficient contrast)

### Input Modalities
- [ ] All functionality available without path-based gestures
- [ ] Touch targets are at least 44x44px
- [ ] No functionality triggered by device motion

## Understandable

### Readable
- [ ] Page language is declared (`lang` attribute)
- [ ] Language changes are marked

### Predictable
- [ ] Changing focus doesn't trigger context changes
- [ ] Changing input doesn't trigger context changes
- [ ] Navigation is consistent
- [ ] Components are identified consistently

### Input Assistance
- [ ] Errors are identified in text
- [ ] Error messages are clear and specific
- [ ] Labels or instructions are provided
- [ ] Error suggestions are provided when possible
- [ ] Confirmation required for destructive actions

## Robust

### Compatible
- [ ] HTML is valid
- [ ] No duplicate IDs
- [ ] Proper element nesting
- [ ] All UI components have accessible names
- [ ] Roles are properly set
- [ ] States and properties are communicated
- [ ] Status messages are programmatically determinable

## Component-Specific Checklist

### Forms
- [ ] All inputs have associated `<label>` elements
- [ ] Required fields are marked (`aria-required="true"`)
- [ ] Error states use `aria-invalid="true"`
- [ ] Error messages linked with `aria-describedby`
- [ ] Fieldset and legend used for groups
- [ ] Placeholder text is not used as label

### Buttons
- [ ] Buttons have descriptive text or `aria-label`
- [ ] Icon-only buttons have `aria-label`
- [ ] Buttons are at least 44x44px
- [ ] Button state is communicated (`aria-pressed`, `aria-expanded`)

### Links
- [ ] Link text is descriptive
- [ ] Links are distinguishable (underlined)
- [ ] Links with same text go to same destination
- [ ] External links are indicated

### Modals/Dialogs
- [ ] Modal has `role="dialog"` or `role="alertdialog"`
- [ ] Modal has `aria-modal="true"`
- [ ] Modal has `aria-labelledby` pointing to title
- [ ] Modal has `aria-describedby` pointing to description
- [ ] Focus is trapped in modal
- [ ] Focus is restored when modal closes
- [ ] Escape key closes modal
- [ ] Overlay click closes modal (if appropriate)

### Tables
- [ ] Tables have `<caption>` or `aria-label`
- [ ] Headers use `<th>` with `scope` attribute
- [ ] Complex tables use `aria-labelledby` or `aria-describedby`
- [ ] Tables are responsive

### Navigation
- [ ] Navigation has `role="navigation"`
- [ ] Navigation has `aria-label`
- [ ] Current page is indicated (`aria-current="page"`)
- [ ] Skip link is provided

### Images
- [ ] All images have `alt` attributes
- [ ] Decorative images have `alt=""`
- [ ] Complex images have detailed descriptions
- [ ] Images don't use text (use actual text instead)

### Status Messages
- [ ] Status messages use `role="status"` or `role="alert"`
- [ ] Status messages use `aria-live` appropriately
- [ ] Dynamic content changes are announced

## Testing Tools

### Automated
- [ ] axe DevTools (browser extension)
- [ ] WAVE (Web Accessibility Evaluation Tool)
- [ ] Lighthouse accessibility audit
- [ ] Pa11y (command line tool)

### Manual
- [ ] Keyboard navigation (Tab, Shift+Tab, Enter, Space, Escape, Arrow keys)
- [ ] Screen reader testing (NVDA, JAWS, VoiceOver)
- [ ] Zoom testing (200% browser zoom)
- [ ] High contrast mode testing
- [ ] Color blindness simulation
- [ ] Mobile screen reader testing

## Quick Reference

### ARIA Attributes
- `aria-label` - Accessible name
- `aria-labelledby` - Reference to element providing name
- `aria-describedby` - Reference to element providing description
- `aria-hidden="true"` - Hide decorative elements
- `aria-live="polite"` - Announce non-urgent updates
- `aria-live="assertive"` - Announce urgent updates
- `aria-required="true"` - Required field
- `aria-invalid="true"` - Invalid field
- `aria-expanded` - Expanded/collapsed state
- `aria-selected` - Selected state
- `aria-current="page"` - Current page indicator
- `role="status"` - Status message
- `role="alert"` - Alert message
- `role="dialog"` - Modal dialog
- `role="navigation"` - Navigation area
- `role="main"` - Main content
- `role="banner"` - Site header
- `role="contentinfo"` - Site footer

### Keyboard Shortcuts
- `Tab` - Move forward through interactive elements
- `Shift+Tab` - Move backward through interactive elements
- `Enter` / `Space` - Activate button or link
- `Escape` - Close modal or cancel action
- `Arrow keys` - Navigate within components (menus, lists, etc.)
- `Home` / `End` - Jump to first/last item
- `Page Up` / `Page Down` - Scroll page

### Color Contrast Ratios
- Normal text: **4.5:1** minimum
- Large text (18pt+ or 14pt+ bold): **3:1** minimum
- UI components: **3:1** minimum
- Non-text content: **3:1** minimum

### Target Sizes
- Interactive elements: **44x44px** minimum
- Touch targets: **44x44px** minimum
- Spacing between targets: Adequate to prevent accidental activation

## Common Issues to Avoid

1. **Missing alt text** - All images need alt attributes
2. **Poor color contrast** - Text must meet contrast ratios
3. **Missing labels** - Form inputs must have labels
4. **Keyboard traps** - All functionality must be keyboard accessible
5. **Missing focus indicators** - Focus must be visible
6. **Poor heading hierarchy** - Headings must be in order
7. **Color-only indicators** - Don't rely on color alone
8. **Missing ARIA labels** - Icon-only buttons need labels
9. **Auto-playing media** - No auto-playing audio/video
10. **Small touch targets** - Ensure 44x44px minimum

## Resources

- [WCAG 2.1 Quick Reference](https://www.w3.org/WAI/WCAG21/quickref/)
- [WebAIM Contrast Checker](https://webaim.org/resources/contrastchecker/)
- [ARIA Authoring Practices Guide](https://www.w3.org/WAI/ARIA/apg/)
- [A11y Project Checklist](https://www.a11yproject.com/checklist/)
- [axe DevTools](https://www.deque.com/axe/devtools/)
- [WAVE](https://wave.webaim.org/)

