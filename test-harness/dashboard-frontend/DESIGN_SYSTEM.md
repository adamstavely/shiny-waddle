# Design System Documentation

This document describes the design token system used throughout the dashboard frontend application.

## Overview

The design system is built on CSS custom properties (CSS variables) defined in `src/styles/design-tokens.css`. This provides a single source of truth for all design values, ensuring consistency and enabling easy theming.

## Design Tokens

### Colors

#### Primary Colors
- `--color-primary`: #4facfe (Primary blue)
- `--color-primary-dark`: #3d8bfe
- `--color-primary-light`: #6bb6fe
- `--color-secondary`: #00f2fe (Cyan)

#### Text Colors
- `--color-text-primary`: #ffffff (White)
- `--color-text-secondary`: #a0aec0 (Light gray)
- `--color-text-muted`: #718096 (Medium gray)
- `--color-text-disabled`: #4a5568 (Dark gray)

#### Background Colors
- `--color-bg-primary`: #0f1419 (Darkest)
- `--color-bg-secondary`: #1a1f2e (Dark)
- `--color-bg-tertiary`: #2d3748 (Medium dark)
- `--color-bg-card`: #1a2332 (Card background)
- `--color-bg-overlay`: rgba(15, 20, 25, 0.4)
- `--color-bg-overlay-light`: rgba(15, 20, 25, 0.6)
- `--color-bg-overlay-dark`: rgba(15, 20, 25, 0.8)

#### Status Colors
- `--color-success`: #22c55e (Green)
- `--color-warning`: #fbbf24 (Yellow)
- `--color-error`: #fc8181 (Red)
- `--color-info`: #4facfe (Blue)

Each status color has corresponding `-bg` variants for backgrounds with opacity.

#### Sensitivity/Classification Colors
- `--color-sensitivity-public`: #22c55e
- `--color-sensitivity-internal`: #4facfe
- `--color-sensitivity-confidential`: #fbbf24
- `--color-sensitivity-restricted`: #fc8181

Each has a corresponding `-bg` variant.

### Gradients

- `--gradient-primary`: Primary gradient (blue to cyan)
- `--gradient-card`: Card background gradient
- `--gradient-card-alt`: Alternative card gradient
- `--gradient-card-full`: Full card gradient with repeat

### Borders

#### Border Colors
- `--border-color-primary`: rgba(79, 172, 254, 0.2)
- `--border-color-primary-hover`: rgba(79, 172, 254, 0.4)
- `--border-color-primary-active`: rgba(79, 172, 254, 0.5)
- `--border-color-secondary`: rgba(79, 172, 254, 0.3)
- `--border-color-muted`: rgba(79, 172, 254, 0.1)

#### Border Widths
- `--border-width-thin`: 1px
- `--border-width-medium`: 2px
- `--border-width-thick`: 3px

#### Border Radius
- `--border-radius-xs`: 4px
- `--border-radius-sm`: 6px
- `--border-radius-md`: 8px
- `--border-radius-lg`: 12px
- `--border-radius-xl`: 16px
- `--border-radius-full`: 9999px

### Shadows

- `--shadow-xs`: Smallest shadow
- `--shadow-sm`: Small shadow
- `--shadow-md`: Medium shadow
- `--shadow-lg`: Large shadow
- `--shadow-xl`: Extra large shadow
- `--shadow-primary`: Primary color shadow
- `--shadow-primary-hover`: Primary color shadow (hover state)

### Typography

#### Font Sizes
- `--font-size-xs`: 0.75rem (12px)
- `--font-size-sm`: 0.875rem (14px)
- `--font-size-base`: 1rem (16px)
- `--font-size-lg`: 1.125rem (18px)
- `--font-size-xl`: 1.25rem (20px)
- `--font-size-2xl`: 1.5rem (24px)
- `--font-size-3xl`: 1.875rem (30px)
- `--font-size-4xl`: 2.25rem (36px)
- `--font-size-5xl`: 3rem (48px)
- `--font-size-6xl`: 5em (80px - for large displays)

#### Font Weights
- `--font-weight-normal`: 400
- `--font-weight-medium`: 500
- `--font-weight-semibold`: 600
- `--font-weight-bold`: 700

#### Line Heights
- `--line-height-tight`: 1.25
- `--line-height-normal`: 1.5
- `--line-height-relaxed`: 1.75

#### Letter Spacing
- `--letter-spacing-tight`: -0.025em
- `--letter-spacing-normal`: 0
- `--letter-spacing-wide`: 0.025em
- `--letter-spacing-wider`: 0.05em
- `--letter-spacing-widest`: 2px

### Spacing

Defined in `responsive.css`:
- `--spacing-xs`: 4px
- `--spacing-sm`: 8px
- `--spacing-md`: 16px
- `--spacing-lg`: 24px
- `--spacing-xl`: 32px
- `--spacing-2xl`: 48px

### Transitions

- `--transition-fast`: 0.15s ease
- `--transition-base`: 0.2s ease
- `--transition-slow`: 0.3s ease
- `--transition-all`: all 0.2s ease

### Z-Index Layers

- `--z-index-base`: 0
- `--z-index-dropdown`: 1000
- `--z-index-sticky`: 1020
- `--z-index-fixed`: 1030
- `--z-index-modal-backdrop`: 1040
- `--z-index-modal`: 1050
- `--z-index-popover`: 1060
- `--z-index-tooltip`: 1070
- `--z-index-skip-link`: 10000

## Utility Classes

Utility classes are defined in `src/styles/utilities.css` for common patterns:

### Background Utilities
- `.bg-primary`, `.bg-secondary`, `.bg-card`, `.bg-overlay`
- `.bg-success`, `.bg-warning`, `.bg-error`, `.bg-info`
- `.bg-success-alpha`, `.bg-warning-alpha`, etc. (with opacity)

### Text Color Utilities
- `.text-primary`, `.text-secondary`, `.text-muted`, `.text-disabled`
- `.text-brand`, `.text-success`, `.text-warning`, `.text-error`, `.text-info`

### Gradient Utilities
- `.gradient-primary`, `.gradient-card`, `.gradient-text`

### Border Utilities
- `.border-primary`, `.border-primary-hover`, `.border-secondary`
- `.border-radius-sm`, `.border-radius-md`, `.border-radius-lg`, etc.

### Shadow Utilities
- `.shadow-xs`, `.shadow-sm`, `.shadow-md`, `.shadow-lg`, `.shadow-xl`
- `.shadow-primary`, `.shadow-primary-hover`

### Button Utilities
- `.btn-base`, `.btn-primary`, `.btn-secondary`, `.btn-ghost`

### Card Utilities
- `.card`, `.card-alt`

### Badge Utilities
- `.badge`, `.badge-success`, `.badge-warning`, `.badge-error`, `.badge-info`
- `.badge-public`, `.badge-internal`, `.badge-confidential`, `.badge-restricted`

## Usage Guidelines

### In Vue Components

#### Scoped Styles
```vue
<style scoped>
.my-component {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
  color: var(--color-text-primary);
}
</style>
```

#### Template (Use Utility Classes)
```vue
<template>
  <div class="card text-primary">
    <h2 class="text-xl">Title</h2>
    <p class="text-secondary">Description</p>
  </div>
</template>
```

### Avoiding Inline Styles

**Don't:**
```vue
<div style="padding: 12px; background: #1a1f2e; color: #ffffff;">
```

**Do:**
```vue
<div class="px-md py-md bg-card text-primary">
```

Or in scoped styles:
```vue
<div class="my-component">
```

```css
.my-component {
  padding: var(--spacing-md);
  background: var(--color-bg-secondary);
  color: var(--color-text-primary);
}
```

### Dynamic Styles

For dynamic styles that need to change based on component state:

**Don't:**
```vue
<div :style="{ color: status === 'error' ? '#fc8181' : '#4facfe' }">
```

**Do:**
```vue
<div :class="{ 'text-error': status === 'error', 'text-info': status !== 'error' }">
```

Or use CSS variables in style binding:
```vue
<div :style="{ '--dynamic-color': statusColor }">
```

```css
.dynamic-element {
  color: var(--dynamic-color, var(--color-primary));
}
```

### SVG Gradients

For SVG elements, use CSS variables in the SVG attributes or define reusable gradients:

```vue
<svg>
  <defs>
    <linearGradient id="myGradient">
      <stop offset="0%" :style="{ stopColor: 'var(--color-primary)' }" />
      <stop offset="100%" :style="{ stopColor: 'var(--color-secondary)' }" />
    </linearGradient>
  </defs>
  <rect fill="url(#myGradient)" />
</svg>
```

## Migration Guide

When refactoring existing components:

1. **Identify hardcoded values**: Look for hex colors, rgba values, pixel values
2. **Find matching tokens**: Check `design-tokens.css` for appropriate tokens
3. **Replace in styles**: Replace hardcoded values with `var(--token-name)`
4. **Remove inline styles**: Move inline styles to CSS classes
5. **Use utility classes**: Where appropriate, use utility classes from `utilities.css`
6. **Test**: Ensure visual appearance remains consistent

### Common Replacements

| Old Value | New Token |
|-----------|-----------|
| `#4facfe` | `var(--color-primary)` |
| `#00f2fe` | `var(--color-secondary)` |
| `#ffffff` | `var(--color-text-primary)` |
| `#a0aec0` | `var(--color-text-secondary)` |
| `#718096` | `var(--color-text-muted)` |
| `#1a1f2e` | `var(--color-bg-secondary)` |
| `rgba(79, 172, 254, 0.2)` | `var(--border-color-primary)` |
| `linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)` | `var(--gradient-primary)` |
| `12px` | `var(--spacing-sm)` or `var(--font-size-xs)` |
| `16px` | `var(--spacing-md)` |
| `24px` | `var(--spacing-lg)` |
| `8px` | `var(--border-radius-md)` |

## Accessibility

All color tokens maintain WCAG 2.1 AA contrast ratios:
- Normal text: 4.5:1 minimum
- Large text: 3:1 minimum

The design system includes accessibility utilities in `accessibility.css` that use design tokens.

## Future Enhancements

- Dark/light mode support (tokens are ready for this)
- Theme customization
- Component-specific token overrides
- Design token documentation generation

## Files

- `src/styles/design-tokens.css` - All design tokens
- `src/styles/utilities.css` - Utility classes
- `src/styles/accessibility.css` - Accessibility styles (uses tokens)
- `src/styles/responsive.css` - Responsive utilities and spacing tokens
