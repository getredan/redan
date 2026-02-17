# Example Dockerfiles

Build redan images from these Dockerfiles:

```bash
redan image import claude-code --dockerfile dockerfiles/claude-code.dockerfile
```

Then run:

```bash
redan exec --image claude-code -i \
  --secret "ANTHROPIC_API_KEY=sk-ant-...:api.anthropic.com" \
  --mount /path/to/project \
  -- claude
```
