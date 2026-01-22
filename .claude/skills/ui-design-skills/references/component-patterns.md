# UI Component Patterns - Complete Reference

## Universal Component Requirements

Every interactive component must have:

### States
- **Default** - Initial appearance
- **Hover** - Mouse over (desktop)
- **Focus** - Keyboard focus (visible 2px ring)
- **Active** - Being pressed
- **Disabled** - Not interactive
- **Loading** - Processing
- **Error** - Invalid state

### Accessibility
- Keyboard accessible
- Focus visible (3:1 contrast)
- Screen reader labels
- Color contrast (4.5:1 text, 3:1 UI)
- Touch target 44x44px minimum

---

## Button Component

### Variants
| Variant | Use |
|---------|-----|
| Primary | Main action, one per view |
| Secondary | Supporting actions |
| Tertiary/Ghost | Low emphasis |
| Danger | Destructive actions |

### Implementation
```html
<!-- Standard button -->
<button type="button" class="btn btn-primary">Submit</button>

<!-- Loading state -->
<button type="button" class="btn loading" disabled>
  <span class="spinner" aria-hidden="true"></span>
  Submitting...
</button>

<!-- Icon button -->
<button type="button" aria-label="Close">
  <svg aria-hidden="true"><!-- icon --></svg>
</button>
```

### CSS
```css
.btn {
  min-height: 44px;
  min-width: 44px;
  padding: 12px 24px;
}
.btn:focus-visible {
  outline: 2px solid var(--focus-color);
  outline-offset: 2px;
}
.btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
```

---

## Input Field Component

### Implementation
```html
<div class="form-field">
  <label for="email">Email address</label>
  <input type="email" id="email" required
         aria-describedby="email-hint email-error"
         aria-invalid="false">
  <span id="email-hint" class="hint">We'll never share your email</span>
  <span id="email-error" class="error" role="alert" hidden>
    Please enter a valid email
  </span>
</div>
```

### Validation Timing
- Validate on blur (after leaving field)
- Show success on valid input
- Show errors on invalid + blur
- Revalidate on input after error

### CSS
```css
.input {
  font-size: 16px; /* Prevents iOS zoom */
  min-height: 44px;
  border: 1px solid var(--border-color);
}
.input:focus {
  border-color: var(--primary);
  box-shadow: 0 0 0 3px var(--primary-light);
}
.input[aria-invalid="true"] {
  border-color: var(--error);
}
```

---

## Modal Dialog Component

### Implementation
```html
<dialog id="modal" aria-labelledby="modal-title">
  <header>
    <h2 id="modal-title">Confirm Action</h2>
    <button aria-label="Close" onclick="modal.close()">×</button>
  </header>
  <div class="dialog-body">
    <p>Are you sure you want to proceed?</p>
  </div>
  <footer class="dialog-actions">
    <button onclick="modal.close()">Cancel</button>
    <button class="btn-primary" onclick="confirm()">Confirm</button>
  </footer>
</dialog>
```

### Focus Management
1. **On open:** Focus first focusable element
2. **During:** Trap focus within modal
3. **On close:** Return focus to trigger element

### Requirements
- Uses `<dialog>` or equivalent ARIA
- Has accessible name (title)
- Focus trapped inside
- Close button visible
- Escape key closes
- Focus returns on close

---

## Tab Component

### Implementation
```html
<div class="tabs">
  <div role="tablist" aria-label="Settings">
    <button role="tab" aria-selected="true" aria-controls="panel-1" id="tab-1">
      General
    </button>
    <button role="tab" aria-selected="false" aria-controls="panel-2" id="tab-2" tabindex="-1">
      Privacy
    </button>
  </div>
  <div role="tabpanel" id="panel-1" aria-labelledby="tab-1" tabindex="0">
    <!-- General content -->
  </div>
  <div role="tabpanel" id="panel-2" aria-labelledby="tab-2" tabindex="0" hidden>
    <!-- Privacy content -->
  </div>
</div>
```

### Keyboard Navigation
- **Arrow Left/Right:** Switch tabs
- **Tab:** Into active panel
- **Home:** First tab
- **End:** Last tab

---

## Navigation Patterns

### Top Navigation
```html
<nav aria-label="Main navigation">
  <a href="/" aria-current="page">Home</a>
  <a href="/products">Products</a>
  <a href="/about">About</a>
</nav>
```

### Mobile Navigation (Hamburger)
```html
<button aria-expanded="false" aria-controls="menu" aria-label="Open menu">
  <svg aria-hidden="true"><!-- hamburger --></svg>
</button>
<nav id="menu" hidden><!-- Items --></nav>
```

### Breadcrumbs
```html
<nav aria-label="Breadcrumb">
  <ol>
    <li><a href="/">Home</a></li>
    <li><a href="/products">Products</a></li>
    <li aria-current="page">Laptops</li>
  </ol>
</nav>
```

---

## Feedback Patterns

### Toast Notification
```html
<div role="status" aria-live="polite" class="toast-container">
  <div class="toast success">
    <svg aria-hidden="true"><!-- icon --></svg>
    <span>Changes saved</span>
    <button aria-label="Dismiss">×</button>
  </div>
</div>
```

**Auto-dismiss rules:**
- Success/Info: Yes (5-8 seconds)
- Warning: Optional
- Error: Never (user must dismiss)

### Progress Indicator
```html
<!-- Determinate -->
<div role="progressbar" aria-valuenow="45" aria-valuemin="0" aria-valuemax="100">
  <div class="bar" style="width: 45%"></div>
</div>

<!-- Indeterminate -->
<div role="status" aria-label="Loading">
  <svg class="spinner" aria-hidden="true"><!-- spinner --></svg>
</div>
```

---

## Data Table Component

```html
<div class="table-container" tabindex="0" role="region" aria-label="User data">
  <table>
    <caption>Active users</caption>
    <thead>
      <tr>
        <th scope="col"><button aria-sort="ascending">Name</button></th>
        <th scope="col">Email</th>
        <th scope="col"><span class="sr-only">Actions</span></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>John Doe</td>
        <td>john@example.com</td>
        <td>
          <button aria-label="Edit John Doe">Edit</button>
          <button aria-label="Delete John Doe">Delete</button>
        </td>
      </tr>
    </tbody>
  </table>
</div>
```

---

## Design Token Scales

### Spacing
```
4px  (xs)  - Tight grouping
8px  (sm)  - Related elements
16px (md)  - Standard spacing
24px (lg)  - Section separation
32px (xl)  - Major sections
48px (2xl) - Page sections
```

### Typography
```
12px - Caption
14px - Body small
16px - Body (base, minimum for readability)
18px - Body large
24px - Heading 5
32px - Heading 4
40px - Heading 3
48px - Heading 2
64px - Heading 1
```

### Colors (Semantic)
```
--color-primary: Main brand/action
--color-secondary: Supporting actions
--color-success: Confirmations (#22c55e)
--color-warning: Cautions (#f59e0b)
--color-error: Errors (#ef4444)
--color-info: Information (#3b82f6)
```

---

## Responsive Breakpoints

```css
/* Mobile first */
.container { padding: 16px; }

/* Tablet (768px+) */
@media (min-width: 768px) {
  .container { padding: 24px; }
}

/* Desktop (1024px+) */
@media (min-width: 1024px) {
  .container { padding: 32px; max-width: 1200px; }
}
```
