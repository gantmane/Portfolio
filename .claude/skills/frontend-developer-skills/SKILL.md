---
name: frontend-developer-skills
description: Frontend development expertise for React, Vue, TypeScript, CSS/Tailwind, state management, testing, and performance optimization
allowed-tools: Read, Write, Grep, Glob, Bash
---

# Frontend Developer Skills

> Modern frontend development with React, TypeScript, and CSS frameworks
> Supports component architecture, state management, testing, and performance optimization

## Quick Reference
**Index:** "react", "vue", "typescript", "tailwind", "testing" | **Docs:** references/react-patterns.md, references/typescript-patterns.md, references/css-patterns.md

## Core Capabilities

### React Development
Hooks (useState, useEffect, useMemo, useCallback), Context, Server Components, Next.js App Router, React Query/TanStack.
**Reference:** references/react-patterns.md

### TypeScript
Strict typing, generics, utility types (Partial, Pick, Omit), discriminated unions, type guards.
**Reference:** references/typescript-patterns.md

### Styling
Tailwind CSS utilities, CSS-in-JS (Styled Components), CSS Modules, modern CSS (Grid, Flexbox, Container Queries).
**Reference:** references/css-patterns.md

### Testing
Jest/Vitest unit tests, React Testing Library, Playwright E2E, MSW for mocking.

## Essential Patterns

### React Component Structure
```tsx
interface Props {
  title: string;
  variant?: 'default' | 'outlined';
  children: React.ReactNode;
}

export function Card({ title, variant = 'default', children }: Props) {
  return (
    <article className={cn('card', variant)}>
      <h2>{title}</h2>
      {children}
    </article>
  );
}
```

### Custom Hook Pattern
```tsx
function useAsync<T>(asyncFn: () => Promise<T>, deps: unknown[]) {
  const [state, setState] = useState<{
    data: T | null;
    loading: boolean;
    error: Error | null;
  }>({ data: null, loading: true, error: null });

  useEffect(() => {
    let cancelled = false;
    asyncFn()
      .then(data => !cancelled && setState({ data, loading: false, error: null }))
      .catch(error => !cancelled && setState({ data: null, loading: false, error }));
    return () => { cancelled = true; };
  }, deps);

  return state;
}
```

### Memoization
```tsx
// Expensive computation
const filtered = useMemo(() => items.filter(predicate), [items, predicate]);

// Stable callback
const handleClick = useCallback(() => onClick(id), [onClick, id]);

// Memoized component
const MemoizedList = memo(List);
```

## Performance Checklist

- [ ] Use `useMemo` for expensive computations
- [ ] Use `useCallback` for callbacks passed to children
- [ ] Lazy load heavy components with `React.lazy`
- [ ] Use virtualization for long lists (react-window)
- [ ] Optimize images (next/image, responsive srcset)
- [ ] Minimize bundle size (tree shaking, code splitting)

## Testing Checklist

- [ ] Test component renders correctly
- [ ] Test user interactions (click, type, submit)
- [ ] Test loading and error states
- [ ] Test accessibility (keyboard, screen reader)
- [ ] Mock API calls with MSW
- [ ] E2E for critical user flows

## Collaboration with UI Designer

**UI Designer provides:** Usability specs, accessibility requirements, design tokens
**Frontend Developer implements:** Working code, responsive behavior, tests

## Anti-Patterns to Avoid

| Pattern | Problem | Solution |
|---------|---------|----------|
| Prop drilling | Hard to maintain | Context or state management |
| useEffect for derivation | Unnecessary renders | useMemo |
| Index as key | Bugs with reordering | Stable unique ID |
| Inline objects in JSX | New reference each render | Memoize or extract |
| No error boundaries | Crashes break app | Add ErrorBoundary |
