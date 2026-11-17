FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p leptiq

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/passhost /usr/local/bin/passhost
WORKDIR /var/lib/passhost
ENV PASSHOST_DATA_DIR=/var/lib/passhost/data \
    PASSHOST_DATABASE_URL=sqlite:///var/lib/passhost/passhost.db?mode=rwc
VOLUME /var/lib/passhost
EXPOSE 8080
ENTRYPOINT ["passhost"]
CMD ["serve"]
