# Claude Code Execution & Workflow Rules

## 1. Build Plan & Progress Tracking (MANDATORY)

For any task involving multiple steps, refactoring, or feature implementations:

1. **Initial Plan:** Before executing code edits or commands, outline a clear, numbered build plan breaking down the overall objective into discrete steps.
2. **Intermittent Progress Updates:** After completing **each step** (or sub-task) of the plan, output an updated progress status block before continuing to the next step.
3. **Format:** Use the standard checklist format below to indicate what is done, currently active, and remaining.

### Progress Status Block Format

```text
--- PROGRESS OVERVIEW ---
[x] Step 1: Initial setup & environment configuration (Completed)
[>] Step 2: Build authentication routes and middleware (In Progress)
[ ] Step 3: Write integration tests
[ ] Step 4: Update API documentation
-------------------------
