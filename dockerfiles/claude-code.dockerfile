FROM ubuntu:24.04

# Base toolset agents commonly reach for. The sandbox is default-deny
# egress, so the agent can't apt/pip/npm-install at runtime; tools have to
# be here at build time. No build-essential: compilation-heavy work belongs
# in a custom image (redan image import, or a devcontainer).
RUN apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      ca-certificates curl wget git iproute2 openssh-client gnupg \
      ripgrep fd-find jq unzip less vim procps tmux \
      python3 python3-pip && \
    ln -sf "$(command -v fdfind)" /usr/local/bin/fd && \
    rm -rf /var/lib/apt/lists/*

# Node.js via NodeSource (Ubuntu 24.04 ships Node 18, which is EOL)
ARG NODE_MAJOR=22
RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - && \
    apt-get install -y -qq --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*

# Claude Code, plus WebSocket/CDP clients so `--browser` tasks can drive
# Chrome without reinventing a WebSocket from raw sockets. `ws` is what
# agents reach for by default; chrome-remote-interface is the higher-level
# CDP client. Both global; NODE_PATH (set by redan) makes them require-able.
RUN npm install -g @anthropic-ai/claude-code ws chrome-remote-interface

# Non-root user (ubuntu:24.04 ships with ubuntu:1000, remove it first)
RUN userdel -r ubuntu 2>/dev/null; \
    groupdel ubuntu 2>/dev/null; \
    groupadd --gid 1000 dev && \
    useradd --uid 1000 --gid 1000 -m -s /bin/bash dev && \
    mkdir -p /workspace && chown dev:dev /workspace

USER dev
WORKDIR /workspace
CMD ["claude"]
