# TypeScript Patterns Reference

## Type Utilities

### Built-in Utilities
```tsx
// Partial - all properties optional
type PartialUser = Partial<User>;

// Required - all properties required
type RequiredUser = Required<User>;

// Pick - select properties
type UserName = Pick<User, 'firstName' | 'lastName'>;

// Omit - exclude properties
type UserWithoutId = Omit<User, 'id'>;

// Record - object type with specific keys
type UserRoles = Record<string, 'admin' | 'user' | 'guest'>;

// ReturnType - get function return type
type ApiResult = ReturnType<typeof fetchUser>;

// Parameters - get function parameter types
type FetchParams = Parameters<typeof fetchUser>;

// Awaited - unwrap Promise type
type User = Awaited<ReturnType<typeof fetchUser>>;
```

### Custom Utilities
```tsx
// DeepPartial
type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

// NonNullable recursive
type DeepNonNullable<T> = {
  [P in keyof T]-?: NonNullable<T[P]>;
};

// Get property type
type PropType<T, K extends keyof T> = T[K];
```

---

## Discriminated Unions

```tsx
// State machine pattern
type LoadingState<T> =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'success'; data: T }
  | { status: 'error'; error: Error };

function useData<T>(fetcher: () => Promise<T>) {
  const [state, setState] = useState<LoadingState<T>>({ status: 'idle' });

  const load = async () => {
    setState({ status: 'loading' });
    try {
      const data = await fetcher();
      setState({ status: 'success', data });
    } catch (error) {
      setState({ status: 'error', error: error as Error });
    }
  };

  return { state, load };
}

// Usage with exhaustive check
function render(state: LoadingState<User>) {
  switch (state.status) {
    case 'idle':
      return <p>Click to load</p>;
    case 'loading':
      return <Spinner />;
    case 'success':
      return <UserProfile user={state.data} />;
    case 'error':
      return <Error message={state.error.message} />;
    default:
      const _exhaustive: never = state;
      return _exhaustive;
  }
}
```

---

## Generic Patterns

### Generic Components
```tsx
interface ListProps<T> {
  items: T[];
  renderItem: (item: T, index: number) => React.ReactNode;
  keyExtractor: (item: T) => string;
  emptyMessage?: string;
}

function List<T>({ items, renderItem, keyExtractor, emptyMessage }: ListProps<T>) {
  if (items.length === 0) {
    return <p>{emptyMessage ?? 'No items'}</p>;
  }

  return (
    <ul>
      {items.map((item, index) => (
        <li key={keyExtractor(item)}>{renderItem(item, index)}</li>
      ))}
    </ul>
  );
}

// Usage with type inference
<List
  items={users}
  renderItem={(user) => <span>{user.name}</span>}
  keyExtractor={(user) => user.id}
/>
```

### Generic Hooks
```tsx
function useArray<T>(initial: T[]) {
  const [items, setItems] = useState(initial);

  const push = useCallback((item: T) => {
    setItems(prev => [...prev, item]);
  }, []);

  const remove = useCallback((predicate: (item: T) => boolean) => {
    setItems(prev => prev.filter(item => !predicate(item)));
  }, []);

  const update = useCallback((predicate: (item: T) => boolean, newItem: T) => {
    setItems(prev => prev.map(item => predicate(item) ? newItem : item));
  }, []);

  return { items, setItems, push, remove, update };
}
```

---

## Type Guards

```tsx
// Type predicate
function isUser(value: unknown): value is User {
  return (
    typeof value === 'object' &&
    value !== null &&
    'id' in value &&
    'email' in value
  );
}

// Assertion function
function assertNonNull<T>(value: T, message?: string): asserts value is NonNullable<T> {
  if (value === null || value === undefined) {
    throw new Error(message ?? 'Value is null or undefined');
  }
}

// In narrowing
function processValue(value: string | number | null) {
  if (value === null) {
    return 'null';
  }
  if (typeof value === 'string') {
    return value.toUpperCase();
  }
  return value.toFixed(2);
}

// Array filter with type guard
const users: (User | null)[] = [/* ... */];
const validUsers = users.filter((u): u is User => u !== null);
```

---

## Branded Types

```tsx
// Prevent mixing IDs
type UserId = string & { readonly brand: unique symbol };
type PostId = string & { readonly brand: unique symbol };

function createUserId(id: string): UserId {
  return id as UserId;
}

function getUser(id: UserId): User {
  // ...
}

function getPost(id: PostId): Post {
  // ...
}

const userId = createUserId('123');
getUser(userId); // OK
// getUser('123'); // Error: string is not assignable to UserId
```

---

## React Component Types

```tsx
// Props with children
interface CardProps {
  title: string;
  children: React.ReactNode;
}

// Props extending HTML attributes
interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary';
  loading?: boolean;
}

// Forward ref component
interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label: string;
  error?: string;
}

const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ label, error, ...props }, ref) => (
    <div>
      <label>{label}</label>
      <input ref={ref} {...props} />
      {error && <span>{error}</span>}
    </div>
  )
);

// Polymorphic component
type PolymorphicProps<E extends React.ElementType, P = {}> = P & {
  as?: E;
} & Omit<React.ComponentPropsWithoutRef<E>, keyof P | 'as'>;

function Box<E extends React.ElementType = 'div'>({
  as,
  children,
  ...props
}: PolymorphicProps<E, { children: React.ReactNode }>) {
  const Component = as || 'div';
  return <Component {...props}>{children}</Component>;
}

// Usage
<Box as="section" id="main">Content</Box>
<Box as="a" href="/about">Link</Box>
```

---

## API Types

```tsx
// API response types
interface ApiResponse<T> {
  data: T;
  meta: {
    page: number;
    total: number;
  };
}

interface ApiError {
  code: string;
  message: string;
  details?: Record<string, string[]>;
}

type ApiResult<T> =
  | { success: true; data: T }
  | { success: false; error: ApiError };

// Type-safe fetch wrapper
async function apiFetch<T>(
  url: string,
  options?: RequestInit
): Promise<ApiResult<T>> {
  try {
    const response = await fetch(url, options);
    if (!response.ok) {
      const error = await response.json();
      return { success: false, error };
    }
    const data = await response.json();
    return { success: true, data };
  } catch (error) {
    return {
      success: false,
      error: {
        code: 'NETWORK_ERROR',
        message: 'Failed to fetch',
      },
    };
  }
}
```

---

## Event Types

```tsx
// Form events
const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
  setValue(e.target.value);
};

const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
  e.preventDefault();
  // ...
};

// Mouse events
const handleClick = (e: React.MouseEvent<HTMLButtonElement>) => {
  console.log(e.clientX, e.clientY);
};

// Keyboard events
const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
  if (e.key === 'Enter') {
    submit();
  }
};

// Custom event handler type
type InputHandler = React.ChangeEventHandler<HTMLInputElement>;
type ButtonHandler = React.MouseEventHandler<HTMLButtonElement>;
```
