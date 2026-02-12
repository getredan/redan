# Example Dockerfiles

Build redan images from these Dockerfiles:

```bash
redan image import claude-code --dockerfile images/claude-code.dockerfile
```

Then run:

```bash
redan exec \
  --image claude-code \
  --interactive \
  --secret "ANTHROPIC_API_KEY=sk-ant-...:api.anthropic.com" \
  --mount /path/to/project \
  --timeout 3600 \
  --command "cd /workspace && claude"
```
