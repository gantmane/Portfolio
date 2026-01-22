# Qwen3-Coder-30B Tools Reference

Model: `danielsheep/Qwen3-Coder-30B-A3B-Instruct-1M-Unsloth:UD-Q5_K_XL`

This document defines tool schemas for function calling with Qwen3-Coder-30B. These can be used with Ollama's tool/function calling API or as prompt-based tool definitions.

---

## Tool Calling Format

### Ollama API (tools parameter)
```json
{
  "model": "danielsheep/Qwen3-Coder-30B-A3B-Instruct-1M-Unsloth:UD-Q5_K_XL",
  "messages": [...],
  "tools": [...]
}
```

### Prompt-Based (fallback)
When tool calling isn't available, include tool descriptions in the system prompt and parse structured output.

---

## Core Tools

### 1. Read

Read file contents from the filesystem.

```json
{
  "type": "function",
  "function": {
    "name": "read_file",
    "description": "Read contents of a file. Always use before editing a file.",
    "parameters": {
      "type": "object",
      "properties": {
        "file_path": {
          "type": "string",
          "description": "Absolute path to the file"
        },
        "offset": {
          "type": "integer",
          "description": "Line number to start reading from (optional)"
        },
        "limit": {
          "type": "integer",
          "description": "Number of lines to read (optional)"
        }
      },
      "required": ["file_path"]
    }
  }
}
```

**Usage Rules:**
- MUST read a file before editing it
- Use absolute paths, not relative
- Returns content with line numbers (cat -n format)

---

### 2. Write

Write content to a file (creates or overwrites).

```json
{
  "type": "function",
  "function": {
    "name": "write_file",
    "description": "Write content to a file. Overwrites existing content.",
    "parameters": {
      "type": "object",
      "properties": {
        "file_path": {
          "type": "string",
          "description": "Absolute path to the file"
        },
        "content": {
          "type": "string",
          "description": "Content to write"
        }
      },
      "required": ["file_path", "content"]
    }
  }
}
```

**Usage Rules:**
- MUST read existing files before overwriting
- Prefer Edit over Write for modifications
- Never create documentation files unless asked

---

### 3. Edit

Perform string replacement in a file.

```json
{
  "type": "function",
  "function": {
    "name": "edit_file",
    "description": "Replace text in a file. Must read file first.",
    "parameters": {
      "type": "object",
      "properties": {
        "file_path": {
          "type": "string",
          "description": "Absolute path to the file"
        },
        "old_string": {
          "type": "string",
          "description": "Exact text to replace (must be unique in file)"
        },
        "new_string": {
          "type": "string",
          "description": "Replacement text"
        },
        "replace_all": {
          "type": "boolean",
          "description": "Replace all occurrences (default: false)"
        }
      },
      "required": ["file_path", "old_string", "new_string"]
    }
  }
}
```

**Usage Rules:**
- MUST read file before editing
- old_string must be unique or use replace_all
- Preserve exact indentation

---

### 4. Glob

Find files by pattern.

```json
{
  "type": "function",
  "function": {
    "name": "glob",
    "description": "Find files matching a glob pattern.",
    "parameters": {
      "type": "object",
      "properties": {
        "pattern": {
          "type": "string",
          "description": "Glob pattern (e.g., '**/*.py', 'src/**/*.ts')"
        },
        "path": {
          "type": "string",
          "description": "Directory to search in (optional, defaults to cwd)"
        }
      },
      "required": ["pattern"]
    }
  }
}
```

**Usage Rules:**
- Use for finding files by name/extension
- Returns paths sorted by modification time

---

### 5. Grep

Search file contents with regex.

```json
{
  "type": "function",
  "function": {
    "name": "grep",
    "description": "Search file contents using regex (ripgrep).",
    "parameters": {
      "type": "object",
      "properties": {
        "pattern": {
          "type": "string",
          "description": "Regex pattern to search"
        },
        "path": {
          "type": "string",
          "description": "File or directory to search (optional)"
        },
        "glob": {
          "type": "string",
          "description": "Filter files by glob (e.g., '*.py')"
        },
        "output_mode": {
          "type": "string",
          "enum": ["content", "files_with_matches", "count"],
          "description": "Output format (default: files_with_matches)"
        },
        "context_lines": {
          "type": "integer",
          "description": "Lines of context around matches"
        },
        "case_insensitive": {
          "type": "boolean",
          "description": "Case insensitive search"
        }
      },
      "required": ["pattern"]
    }
  }
}
```

**Usage Rules:**
- Use for searching code/content
- Supports ripgrep regex syntax
- Escape literal braces: `interface\{\}`

---

### 6. Bash

Execute shell commands.

```json
{
  "type": "function",
  "function": {
    "name": "bash",
    "description": "Execute a bash command.",
    "parameters": {
      "type": "object",
      "properties": {
        "command": {
          "type": "string",
          "description": "The command to execute"
        },
        "timeout": {
          "type": "integer",
          "description": "Timeout in milliseconds (max 600000)"
        },
        "description": {
          "type": "string",
          "description": "Brief description of what the command does"
        },
        "working_dir": {
          "type": "string",
          "description": "Working directory (optional)"
        }
      },
      "required": ["command"]
    }
  }
}
```

**Usage Rules:**
- Quote paths with spaces
- Use absolute paths
- Prefer dedicated tools over bash equivalents:
  - `grep` → use Grep tool
  - `find` → use Glob tool
  - `cat` → use Read tool
- Chain commands with `&&` or `;`

---

### 7. ListDirectory

List directory contents.

```json
{
  "type": "function",
  "function": {
    "name": "list_directory",
    "description": "List files and directories in a path.",
    "parameters": {
      "type": "object",
      "properties": {
        "path": {
          "type": "string",
          "description": "Absolute path to directory"
        },
        "ignore": {
          "type": "array",
          "items": {"type": "string"},
          "description": "Glob patterns to ignore"
        }
      },
      "required": ["path"]
    }
  }
}
```

---

### 8. TodoWrite

Manage task list for complex operations.

```json
{
  "type": "function",
  "function": {
    "name": "todo_write",
    "description": "Create/update a task list for tracking progress.",
    "parameters": {
      "type": "object",
      "properties": {
        "todos": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "content": {"type": "string"},
              "status": {
                "type": "string",
                "enum": ["pending", "in_progress", "completed"]
              }
            },
            "required": ["content", "status"]
          }
        }
      },
      "required": ["todos"]
    }
  }
}
```

**Usage Rules:**
- Use for 3+ step tasks
- Only ONE task in_progress at a time
- Mark completed immediately after finishing

---

## Tool Usage Guidelines

### When to Use Each Tool

| Task | Tool |
|------|------|
| Read file contents | `read_file` |
| Create new file | `write_file` |
| Modify existing file | `edit_file` (after read_file) |
| Find files by name | `glob` |
| Search file contents | `grep` |
| Run commands | `bash` |
| List directory | `list_directory` |
| Track complex tasks | `todo_write` |

### Tool Calling Best Practices

1. **Read Before Edit**
   ```
   1. read_file(path)
   2. edit_file(path, old, new)
   ```

2. **Search Before Assume**
   ```
   1. glob("**/*.py") or grep("function_name")
   2. read_file(found_path)
   ```

3. **Verify Libraries Exist**
   ```
   1. read_file("package.json") or read_file("requirements.txt")
   2. Check for existing dependency
   ```

4. **Parallel Tool Calls**
   When tools are independent, call them in parallel for efficiency.

---

## Example Tool Call Sequences

### Modify a Function

```json
[
  {"tool": "read_file", "args": {"file_path": "/src/utils.py"}},
  {"tool": "edit_file", "args": {
    "file_path": "/src/utils.py",
    "old_string": "def old_function():",
    "new_string": "def new_function():"
  }}
]
```

### Find and Read Files

```json
[
  {"tool": "grep", "args": {"pattern": "class AuthHandler", "glob": "**/*.py"}},
  {"tool": "read_file", "args": {"file_path": "/src/auth/handler.py"}}
]
```

### Check Dependencies

```json
[
  {"tool": "read_file", "args": {"file_path": "/package.json"}},
  {"tool": "bash", "args": {"command": "npm list axios", "description": "Check if axios is installed"}}
]
```

---

## Response Format

When calling tools, use this format:

```json
{
  "tool_calls": [
    {
      "name": "tool_name",
      "arguments": {
        "param1": "value1",
        "param2": "value2"
      }
    }
  ]
}
```

Or for prompt-based tool use:

```
<tool_call>
{"name": "read_file", "arguments": {"file_path": "/src/main.py"}}
</tool_call>
```

---

## Security Restrictions

Tools MUST NOT be used for:
- Reading/writing credential files (.env, secrets, keys)
- Executing malicious commands
- Accessing sensitive system files
- Network operations without explicit permission

Always validate file paths and command inputs before execution.
