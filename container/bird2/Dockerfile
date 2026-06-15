ARG ALPINE_VER=3.24

# ---- Build stage ----
FROM alpine:${ALPINE_VER} AS builder

ARG BIRD_VER=2.19.1

RUN apk add --no-cache \
    autoconf \
    automake \
    bison \
    build-base \
    curl \
    flex \
    linux-headers \
    m4 \
    ncurses-dev \
    readline-dev

WORKDIR /root

RUN curl -O -L https://bird.nic.cz/download/bird-${BIRD_VER}.tar.gz
RUN tar -zxvf bird-${BIRD_VER}.tar.gz

RUN cd bird-${BIRD_VER} && \
    autoconf && \
    autoheader && \
    ./configure && \
    make && \
    make install

# ---- Runtime stage ----
FROM alpine:${ALPINE_VER}

LABEL maintainer="Kawaii Networks <noc@projectk.org>"

EXPOSE 179

# Only the shared libraries BIRD links against at runtime.
RUN apk add --no-cache \
    ncurses-libs \
    readline

# bird daemon, birdc (readline client) and birdcl (standalone client).
COPY --from=builder /usr/local/sbin/bird* /usr/local/sbin/

# This directory must be mounted as a local volume with '-v `pwd`/bird:/etc/bird:rw' docker's command line option.
# The host's file at `pwd`/bird/bird.conf is used as the configuration file for BIRD.
RUN mkdir /etc/bird

CMD bird -c /etc/bird/bird.conf -d
