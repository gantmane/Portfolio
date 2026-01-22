# Nielsen's 10 Usability Heuristics - Detailed Reference

## 1. Visibility of System Status
**Principle:** Keep users informed through timely, appropriate feedback.

**Implementation:**
- Loading indicators with progress percentage
- Button state changes on click
- Form validation feedback as user types
- Confirmation messages after actions
- Step indicators in multi-step processes

**Violations to avoid:**
- Silent failures with no error message
- Actions with no visual feedback
- Unclear loading states
- No indication of successful completion

---

## 2. Match Between System and Real World
**Principle:** Use familiar language, concepts, and conventions.

**Implementation:**
- "Shopping Cart" not "Purchase Queue"
- Calendar uses familiar date formats
- Icons match real-world objects
- Industry-appropriate terminology

**Violations to avoid:**
- Technical jargon in user-facing text
- Unfamiliar metaphors
- System-centric language

---

## 3. User Control and Freedom
**Principle:** Provide clear "emergency exits" from unwanted states.

**Implementation:**
- Undo/Redo functionality
- Cancel buttons on dialogs
- Back navigation that preserves data
- Confirmation before destructive actions

**Violations to avoid:**
- No cancel option in wizards
- Destructive actions without confirmation
- No way to undo mistakes
- Trapped in modal flows

---

## 4. Consistency and Standards
**Principle:** Follow platform conventions; maintain internal consistency.

**Implementation:**
- Primary actions always in same position
- Consistent color meanings (red = error)
- Standard icons for common actions
- Same terminology throughout

**Types:**
- Internal: Within the same product
- External: With platform/industry standards
- Visual: Colors, typography, spacing
- Functional: Behaviors and interactions

---

## 5. Error Prevention
**Principle:** Design to prevent problems before they occur.

**Implementation:**
- Constraints preventing invalid input
- Confirmation for irreversible actions
- Clear format requirements upfront
- Disabled options when not applicable
- Smart defaults

**Strategies:**
1. Eliminate error-prone conditions
2. Use constraints and defaults
3. Offer suggestions and auto-complete
4. Require confirmation for high-impact actions

---

## 6. Recognition Rather Than Recall
**Principle:** Minimize memory load by making information visible.

**Implementation:**
- Recently used items visible
- Search with suggestions
- Visible navigation (not hidden menus)
- Labels on icons
- Contextual help

**Memory load reducers:**
- Show recently used items
- Provide inline help and tooltips
- Use descriptive labels
- Show example formats
- Breadcrumb navigation

---

## 7. Flexibility and Efficiency of Use
**Principle:** Accelerators for experts while remaining accessible to novices.

**Implementation:**
- Keyboard shortcuts
- Customizable interfaces
- Batch operations
- Quick actions and gestures
- Command palettes (Cmd+K patterns)

**Features:**
- Customizable dashboards
- Saved filters and views
- Bulk selection and actions
- Configurable defaults

---

## 8. Aesthetic and Minimalist Design
**Principle:** Remove irrelevant information; every element competes for attention.

**Implementation:**
- Clean visual hierarchy
- Progressive disclosure
- Effective whitespace
- Only essential information visible
- Clear focus on primary actions

**Strategies:**
- Hide advanced options by default
- Use progressive disclosure
- Prioritize primary actions visually
- Remove redundant elements
- Break complex tasks into steps

---

## 9. Help Users Recognize, Diagnose, and Recover from Errors
**Principle:** Plain language errors with specific solutions.

**Error message formula:**
1. **What happened:** "Your password is too short"
2. **Why:** "Passwords must be at least 8 characters"
3. **How to fix:** "Add 3 more characters to continue"

**Implementation:**
- Specific error descriptions
- Clear cause explanation
- Actionable recovery steps
- Non-technical language
- Visual proximity to error source

---

## 10. Help and Documentation
**Principle:** Easy-to-search, task-focused, concrete help.

**Implementation:**
- Contextual help tooltips
- Searchable documentation
- Step-by-step tutorials
- FAQ sections
- Inline hints

**Best practices:**
- Task-focused, not feature-focused
- Searchable and scannable
- Include examples
- Keep up to date
- Multiple formats (text, video)

---

## Severity Rating Scale

| Rating | Severity | Action |
|--------|----------|--------|
| 0 | None | Not a problem |
| 1 | Cosmetic | Fix only if time |
| 2 | Minor | Low priority |
| 3 | Major | High priority |
| 4 | Catastrophic | Fix before release |

## Evaluation Process

1. **Prepare:** Define scope, select 3-5 evaluators
2. **Evaluate:** Each reviews independently
3. **Document:** Record violations with severity, location, heuristic
4. **Consolidate:** Combine findings, resolve duplicates
5. **Prioritize:** Rank by severity × frequency
6. **Report:** Present findings with recommendations
