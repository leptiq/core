FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p leptiq

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/leptiq /usr/local/bin/leptiq
WORKDIR /var/lib/leptiq
ENV LEPTIQ_DATA_DIR=/var/lib/leptiq/data \
    LEPTIQ_DATABASE_URL=sqlite:///var/lib/leptiq/leptiq.db?mode=rwc
VOLUME /var/lib/leptiq
EXPOSE 8080
ENTRYPOINT ["leptiq"]
CMD ["serve"]
