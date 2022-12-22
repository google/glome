FROM docker.io/library/debian:bullseye AS build
WORKDIR /app
COPY . .
RUN kokoro/rodete/fetch_dependencies.sh
RUN rm -rf build \
    && meson build \
    && meson compile -C build \
    && meson test --print-errorlogs -C build \
    && meson install -C build

FROM docker.io/library/debian:bullseye
COPY --from=build /usr/local /usr/local
COPY kokoro/docker/glome-start /usr/local/sbin
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
       openssh-server \
       socat \
       xxd \
    && rm -rf /var/lib/apt/lists/*
CMD ["/usr/local/sbin/glome-start"]
EXPOSE 22 23
