# Repository Guidelines

## Project Structure & Module Organization
- Core engine packages live at the repository root (`agent/`, `runtime/`, `orchestrator/`, `schema/`, `memory/`, `coordination/`, `workflows/`). Keep related `*_test.go` files beside their implementation.
- `llm/` hosts model adapters, while `tools/` and `utils/` provide reusable extensions. Feature-specific integrations (e.g., `hitl/`) should stay isolated to avoid circular dependencies.
- Use `examples/` for runnable demos; mirror production-ready patterns there before promoting them into core packages.

## Build, Test, and Development Commands
- `go fmt ./...` – format Go files before committing.
- `go vet ./...` – surface common correctness issues.
- `go test ./...` – run the full suite. Use `go test ./agent/...` to isolate a module.
- `go test -run TestWorkflow -v ./workflows` – example targeted test for workflow behavior.

## Coding Style & Naming Conventions
- Follow idiomatic Go: tabs for indentation, PascalCase for exported APIs, camelCase for internals, and `ErrX` for error values.
- Keep modules cohesive: agents orchestrate tools, workflows orchestrate deterministic steps, and schema structs define cross-package contracts.
- Prefer `context.Context` as the first parameter in long-running functions and always thread the runtime context provided by `runtime.NewContext`.

## Testing Guidelines
- Write table-driven tests and colocate fixtures near the package under test.
- Mock external LLM calls with the lightweight adapters in `llm/` instead of hitting real endpoints.
- Aim for meaningful coverage on orchestration paths (agent execution, workflow branching, memory persistence). Add concurrency tests when touching coordination primitives.

## Commit & Pull Request Guidelines
- Use concise, typed commit prefixes seen in history (`feat:`, `fix:`, `update:`, `wip:`) followed by a short description (≤50 chars).
- Reference related issues in the body and describe behavioral changes plus validation steps.
- Pull requests should summarize scope, list breaking changes, include test command outputs, and add screenshots or logs for orchestration flows when UI/trace output changes.

## Configuration & Security Notes
- Do not commit secrets. Load runtime credentials via environment variables (`LLM_API_KEY`, `LLM_MODEL`, `LLM_BASE_URL`); prefer `.env.local` entries ignored by Git.
- When adding new adapters or tools, document required variables in the README and guard against missing configs with explicit errors.
