FROM ubuntu:24.04

RUN apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      ca-certificates curl git iproute2 && \
    rm -rf /var/lib/apt/lists/*

# Node.js via NodeSource (Ubuntu's nodejs package is too old)
ARG NODE_MAJOR=22
RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - && \
    apt-get install -y -qq --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*

# Claude Code
RUN npm install -g @anthropic-ai/claude-code

# Non-root user
RUN groupadd --gid 1000 dev && \
    useradd --uid 1000 --gid 1000 -m -s /bin/bash dev && \
    mkdir -p /workspace && chown dev:dev /workspace

USER dev
WORKDIR /workspace
CMD ["claude"]
