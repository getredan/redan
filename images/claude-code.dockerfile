FROM ubuntu:24.04

RUN apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
      nodejs npm git curl wget ca-certificates iproute2 && \
    npm install -g @anthropic-ai/claude-code && \
    rm -rf /var/lib/apt/lists/*
