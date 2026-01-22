# CSS Patterns Reference

## Tailwind CSS Patterns

### Responsive Design
```tsx
// Mobile-first breakpoints
<div className="
  p-4 md:p-6 lg:p-8
  grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3
  gap-4 md:gap-6
">
  {items.map(item => <Card key={item.id} item={item} />)}
</div>

// Container with responsive padding
<div className="container mx-auto px-4 sm:px-6 lg:px-8">
  {children}
</div>
```

### Component Variants with CVA
```tsx
import { cva, type VariantProps } from 'class-variance-authority';

const button = cva(
  // Base styles
  'inline-flex items-center justify-center rounded-md font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50',
  {
    variants: {
      variant: {
        default: 'bg-primary text-white hover:bg-primary/90',
        destructive: 'bg-destructive text-white hover:bg-destructive/90',
        outline: 'border border-input bg-background hover:bg-accent',
        secondary: 'bg-secondary text-secondary-foreground hover:bg-secondary/80',
        ghost: 'hover:bg-accent hover:text-accent-foreground',
        link: 'text-primary underline-offset-4 hover:underline',
      },
      size: {
        default: 'h-10 px-4 py-2',
        sm: 'h-9 rounded-md px-3',
        lg: 'h-11 rounded-md px-8',
        icon: 'h-10 w-10',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  }
);

interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof button> {}

function Button({ className, variant, size, ...props }: ButtonProps) {
  return (
    <button className={cn(button({ variant, size }), className)} {...props} />
  );
}
```

### Utility Composition with cn()
```tsx
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// Usage - handles conflicts properly
<div className={cn(
  'p-4 bg-blue-500',
  isActive && 'bg-green-500', // Overrides bg-blue-500
  className
)}>
```

---

## Modern CSS Patterns

### CSS Grid Layouts
```css
/* Responsive grid with auto-fit */
.grid-auto {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 1.5rem;
}

/* Holy Grail layout */
.layout {
  display: grid;
  grid-template-rows: auto 1fr auto;
  grid-template-columns: 200px 1fr 200px;
  grid-template-areas:
    "header header header"
    "nav    main   aside"
    "footer footer footer";
  min-height: 100vh;
}

/* Subgrid for aligned children */
.card-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1rem;
}

.card {
  display: grid;
  grid-template-rows: subgrid;
  grid-row: span 3;
}
```

### Flexbox Patterns
```css
/* Center everything */
.center {
  display: flex;
  justify-content: center;
  align-items: center;
}

/* Space between with wrapping */
.toolbar {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: center;
  gap: 1rem;
}

/* Sticky footer */
.page {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
}

.page main {
  flex: 1;
}
```

### Container Queries
```css
/* Define container */
.card-container {
  container-type: inline-size;
  container-name: card;
}

/* Query based on container size */
@container card (min-width: 400px) {
  .card {
    flex-direction: row;
  }
}

@container card (min-width: 600px) {
  .card {
    grid-template-columns: 1fr 2fr;
  }
}
```

### Custom Properties (CSS Variables)
```css
:root {
  /* Colors */
  --color-primary: hsl(220 90% 56%);
  --color-primary-dark: hsl(220 90% 46%);
  --color-secondary: hsl(260 60% 50%);

  --color-success: hsl(142 76% 36%);
  --color-warning: hsl(38 92% 50%);
  --color-error: hsl(0 84% 60%);

  /* Spacing scale */
  --space-1: 0.25rem;
  --space-2: 0.5rem;
  --space-3: 0.75rem;
  --space-4: 1rem;
  --space-6: 1.5rem;
  --space-8: 2rem;

  /* Typography */
  --font-sans: 'Inter', system-ui, sans-serif;
  --font-mono: 'JetBrains Mono', monospace;

  /* Shadows */
  --shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.05);
  --shadow-md: 0 4px 6px rgba(0, 0, 0, 0.1);
  --shadow-lg: 0 10px 15px rgba(0, 0, 0, 0.1);

  /* Transitions */
  --transition-fast: 150ms ease;
  --transition-normal: 200ms ease;
}

/* Dark mode */
[data-theme="dark"] {
  --color-primary: hsl(220 90% 66%);
  --color-bg: hsl(220 20% 10%);
  --color-text: hsl(220 10% 90%);
}
```

---

## Animation Patterns

### CSS Transitions
```css
.button {
  transition: transform var(--transition-fast),
              background-color var(--transition-normal);
}

.button:hover {
  background-color: var(--color-primary-dark);
}

.button:active {
  transform: scale(0.98);
}
```

### CSS Keyframe Animations
```css
@keyframes fade-in {
  from { opacity: 0; }
  to { opacity: 1; }
}

@keyframes slide-up {
  from {
    opacity: 0;
    transform: translateY(20px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.fade-in {
  animation: fade-in 200ms ease-out;
}

.slide-up {
  animation: slide-up 300ms ease-out;
}

.spinner {
  animation: spin 1s linear infinite;
}
```

### Staggered Animations
```css
.list-item {
  animation: slide-up 300ms ease-out forwards;
  opacity: 0;
}

.list-item:nth-child(1) { animation-delay: 0ms; }
.list-item:nth-child(2) { animation-delay: 50ms; }
.list-item:nth-child(3) { animation-delay: 100ms; }
.list-item:nth-child(4) { animation-delay: 150ms; }

/* Or use CSS custom property */
.list-item {
  animation-delay: calc(var(--index) * 50ms);
}
```

---

## Accessibility Patterns

### Focus Styles
```css
/* Remove default, add custom */
:focus {
  outline: none;
}

:focus-visible {
  outline: 2px solid var(--color-primary);
  outline-offset: 2px;
}

/* Skip link */
.skip-link {
  position: absolute;
  top: -40px;
  left: 0;
  padding: 8px 16px;
  background: var(--color-primary);
  color: white;
  z-index: 9999;
}

.skip-link:focus {
  top: 0;
}
```

### Reduced Motion
```css
@media (prefers-reduced-motion: reduce) {
  *,
  *::before,
  *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}
```

### Screen Reader Only
```css
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}
```

---

## Component Patterns

### Card
```css
.card {
  background: var(--color-bg);
  border-radius: 0.5rem;
  padding: var(--space-4);
  box-shadow: var(--shadow-md);
  transition: box-shadow var(--transition-normal);
}

.card:hover {
  box-shadow: var(--shadow-lg);
}
```

### Input
```css
.input {
  width: 100%;
  padding: 0.75rem 1rem;
  border: 1px solid var(--color-border);
  border-radius: 0.375rem;
  font-size: 1rem;
  line-height: 1.5;
  transition: border-color var(--transition-fast),
              box-shadow var(--transition-fast);
}

.input:focus {
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px var(--color-primary-light);
}

.input[aria-invalid="true"] {
  border-color: var(--color-error);
}
```

### Modal Overlay
```css
.overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.5);
  backdrop-filter: blur(4px);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 50;
}

.modal {
  background: var(--color-bg);
  border-radius: 0.5rem;
  padding: var(--space-6);
  max-width: 500px;
  width: 90%;
  max-height: 90vh;
  overflow-y: auto;
}
```
