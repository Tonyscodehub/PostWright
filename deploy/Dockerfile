# Build:  docker build -f deploy/Dockerfile -t postwright .
# Run:    docker run -d --name postwright -v /srv/postwright:/data \
#           -p 25:25 -p 465:465 -p 587:587 -p 993:993 -p 443:443 postwright
# First:  docker run --rm -v /srv/postwright:/data postwright init --hostname mail.example.com --data-dir /data
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
 && useradd --system --home /data postwright
COPY --from=build /src/target/release/postwright /usr/local/bin/postwright
USER postwright
WORKDIR /data
VOLUME /data
EXPOSE 25 143 443 465 587 993
ENTRYPOINT ["postwright", "--config", "/data/postwright.toml"]
CMD ["serve"]
