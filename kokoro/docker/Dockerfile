FROM docker.io/library/debian:trixie AS build
WORKDIR /app
COPY . .
RUN kokoro/rodete/fetch_dependencies.sh
RUN rm -rf build \
    && meson build \
    && meson compile -C build \
    && meson test --print-errorlogs -C build \
    && meson install -C build
RUN kokoro/rodete/debian_cargo.sh prepare-debian /app/debian/cargo_registry --link-from-system \
    && kokoro/rodete/debian_cargo.sh build \
    && kokoro/rodete/debian_cargo.sh test \
    && kokoro/rodete/debian_cargo.sh install --features=cli

FROM docker.io/library/debian:trixie
COPY --from=build /usr/local /usr/local
COPY kokoro/docker/glome-start /usr/local/sbin
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
       openssh-server \
       socat \
    && rm -rf /var/lib/apt/lists/*
CMD ["/usr/local/sbin/glome-start"]
EXPOSE 22 23
