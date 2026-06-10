FROM ubuntu:24.04

RUN apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      ca-certificates curl git iproute2 && \
    rm -rf /var/lib/apt/lists/*

# Node.js via NodeSource
ARG NODE_MAJOR=22
RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - && \
    apt-get install -y -qq --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*

# Pi coding agent
RUN npm install -g @earendil-works/pi-coding-agent

# Non-root user (ubuntu:24.04 ships with ubuntu:1000, remove it first)
RUN userdel -r ubuntu 2>/dev/null; \
    groupdel ubuntu 2>/dev/null; \
    groupadd --gid 1000 dev && \
    useradd --uid 1000 --gid 1000 -m -s /bin/bash dev && \
    mkdir -p /workspace && chown dev:dev /workspace

USER dev
WORKDIR /workspace
CMD ["pi"]
