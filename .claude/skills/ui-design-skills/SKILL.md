---
name: ui-design-skills
description: UI/UX design expertise for usability, accessibility (WCAG), design systems, and user-friendly interface patterns
allowed-tools: Read, Grep, Glob, WebSearch
---

# UI Design Skills

> User-centered design expertise for creating accessible, usable, and delightful interfaces
> Supports usability heuristics, WCAG compliance, design systems, and interaction patterns

## Quick Reference
**Index:** "usability", "accessibility", "wcag", "design_system", "ux" | **Docs:** references/usability-heuristics.md, references/accessibility-wcag.md, references/component-patterns.md

## Core Capabilities

### Usability Heuristics
Nielsen's 10 heuristics: Visibility, Match real world, User control, Consistency, Error prevention, Recognition over recall, Flexibility, Aesthetics, Error recovery, Help.
**Reference:** references/usability-heuristics.md

### Accessibility (WCAG 2.1 AA)
Perceivable (alt text, contrast 4.5:1), Operable (keyboard, no traps), Understandable (clear language), Robust (valid HTML, ARIA).
**Reference:** references/accessibility-wcag.md

### Design Systems
Component architecture, design tokens (spacing: 4/8/16/24/32px, typography: 12-64px scale), consistent patterns, documentation.
**Reference:** references/component-patterns.md

### Interaction Patterns
Progressive disclosure, responsive mobile-first, touch targets (44px min), state management (default/hover/focus/active/disabled/error).

## Essential Checklists

### Component Checklist
- [ ] All states defined (default, hover, focus, active, disabled, error, loading)
- [ ] Keyboard navigation works
- [ ] Focus ring visible (2px solid, 3:1 contrast)
- [ ] Touch target 44x44px minimum
- [ ] Screen reader accessible

### Accessibility Checklist
- [ ] Color contrast 4.5:1 (text), 3:1 (UI)
- [ ] No color-only indicators
- [ ] Labels associated with inputs
- [ ] Skip links present
- [ ] Alt text on images
- [ ] Error messages specific and helpful

### Form Checklist
- [ ] Labels visible (not placeholder-only)
- [ ] Required fields marked
- [ ] Error shown near field
- [ ] Success confirmation provided
- [ ] Validation timing appropriate (on blur)

## Key Principles

**User-Centered:** Design for real needs, prioritize clarity, reduce cognitive load
**Progressive Enhancement:** Core works without JS, enhance for capable browsers
**Mobile-First:** Design small first, touch-friendly default, efficient space use
**Inclusive:** Design for extremes, multiple paths to complete tasks

## Anti-Patterns to Avoid

| Pattern | Issue | Alternative |
|---------|-------|-------------|
| Icon-only buttons | Ambiguous | Add text labels |
| Placeholder as label | Disappears | Persistent labels |
| Carousel-only | Low visibility | Grid with navigation |
| Auto-play media | Surprise/a11y | Explicit play |
| Modal for info | Interrupts | Inline/expandable |

## Error Message Formula

1. **What happened:** "Password is too short"
2. **Why:** "Must be 8+ characters"
3. **How to fix:** "Add 3 more characters"
