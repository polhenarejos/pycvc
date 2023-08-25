FROM debian:bullseye

ARG DEBIAN_FRONTEND=noninteractive

RUN apt update && apt upgrade -y
RUN apt install -y apt-utils
RUN apt install -y \
    git \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /
