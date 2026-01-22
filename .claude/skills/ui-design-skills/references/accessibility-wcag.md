# WCAG 2.1 Accessibility Guidelines - Complete Reference

## Quick Compliance Check

### Level A (Must Have)
- [ ] All images have alt text
- [ ] All form inputs have labels
- [ ] Color is not the only indicator
- [ ] All functionality via keyboard
- [ ] No keyboard traps
- [ ] Page has descriptive title

### Level AA (Should Have)
- [ ] Color contrast 4.5:1 for text
- [ ] Text resizable to 200%
- [ ] Skip navigation links
- [ ] Consistent navigation
- [ ] Error identification and suggestions

---

## Principle 1: Perceivable

### 1.1 Text Alternatives (Level A)

```html
<!-- Informative image -->
<img src="chart.png" alt="Sales increased 25% from Q1 to Q2">

<!-- Decorative image -->
<img src="border.png" alt="" role="presentation">

<!-- Icon button -->
<button aria-label="Close dialog">
  <svg aria-hidden="true"><!-- icon --></svg>
</button>
```

### 1.3 Adaptable (Level A)

```html
<!-- Proper heading hierarchy -->
<h1>Page Title</h1>
  <h2>Section</h2>
    <h3>Subsection</h3>

<!-- Data table with headers -->
<table>
  <caption>Monthly Sales</caption>
  <thead>
    <tr>
      <th scope="col">Month</th>
      <th scope="col">Revenue</th>
    </tr>
  </thead>
</table>

<!-- Form with proper association -->
<label for="email">Email</label>
<input type="email" id="email" aria-describedby="email-hint">
<span id="email-hint">We'll never share your email</span>
```

### 1.4 Distinguishable

**Contrast Requirements (Level AA):**
| Element | Minimum Ratio |
|---------|---------------|
| Normal text | 4.5:1 |
| Large text (18px+ or 14px+ bold) | 3:1 |
| UI components | 3:1 |

**Use of Color (Level A):**
```html
<!-- Bad: Color only -->
<span style="color: red;">Invalid</span>

<!-- Good: Color + icon + text -->
<span style="color: red;">
  <svg aria-hidden="true"><!-- error icon --></svg>
  Error: Invalid email format
</span>
```

---

## Principle 2: Operable

### 2.1 Keyboard Accessible (Level A)

```html
<!-- Keyboard-accessible custom control -->
<div role="button" tabindex="0"
     onkeydown="handleKeydown(event)"
     onclick="handleClick()">
  Custom Button
</div>
```

**Key requirements:**
- All functionality available via keyboard
- No keyboard traps
- Focus can always be moved away

### 2.4 Navigable

**Skip Links (Level A):**
```html
<body>
  <a href="#main" class="skip-link">Skip to main content</a>
  <nav><!-- Navigation --></nav>
  <main id="main"><!-- Content --></main>
</body>

<style>
.skip-link {
  position: absolute;
  top: -40px;
}
.skip-link:focus {
  top: 0;
}
</style>
```

**Focus Visible (Level AA):**
```css
:focus-visible {
  outline: 2px solid #0066cc;
  outline-offset: 2px;
}
```

---

## Principle 3: Understandable

### 3.1 Readable

```html
<html lang="en">
<p>The French phrase <span lang="fr">c'est la vie</span> means "that's life".</p>
```

### 3.2 Predictable

- Focus doesn't trigger unexpected changes
- Input doesn't auto-submit without warning
- Navigation is consistent across pages

### 3.3 Input Assistance

```html
<label for="email">Email</label>
<input type="email" id="email"
       aria-invalid="true"
       aria-describedby="email-error">
<span id="email-error" role="alert">
  Please enter a valid email address
</span>
```

---

## Principle 4: Robust

### 4.1 Compatible

```html
<!-- Custom checkbox with ARIA -->
<div role="checkbox"
     aria-checked="false"
     tabindex="0"
     aria-labelledby="checkbox-label">
  <span id="checkbox-label">Accept terms</span>
</div>

<!-- Live region for status -->
<div role="status" aria-live="polite">
  3 items added to cart
</div>
```

---

## Common ARIA Patterns

### Modal Dialog
```html
<dialog aria-labelledby="title" aria-describedby="desc">
  <h2 id="title">Confirm</h2>
  <p id="desc">Are you sure?</p>
  <button>Cancel</button>
  <button>Confirm</button>
</dialog>
```

### Tab Panel
```html
<div role="tablist" aria-label="Settings">
  <button role="tab" aria-selected="true" aria-controls="panel-1">General</button>
  <button role="tab" aria-selected="false" aria-controls="panel-2" tabindex="-1">Privacy</button>
</div>
<div role="tabpanel" id="panel-1" aria-labelledby="tab-1"><!-- Content --></div>
<div role="tabpanel" id="panel-2" aria-labelledby="tab-2" hidden><!-- Content --></div>
```

---

## Testing Tools

**Automated:**
- axe DevTools
- WAVE
- Lighthouse

**Manual:**
- Keyboard-only navigation
- Screen reader (NVDA, VoiceOver, JAWS)
- Color contrast analyzers
- Browser zoom to 200%

**Screen Reader Commands:**
| Action | NVDA | VoiceOver |
|--------|------|-----------|
| Read all | Insert + Down | VO + A |
| Stop | Ctrl | Ctrl |
| Next heading | H | VO + Cmd + H |
| Form fields | F | VO + Cmd + J |
