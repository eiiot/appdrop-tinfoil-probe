FROM golang:1.26-bookworm@sha256:5de7c99eb78ca5e515a4c340235d0955ec5964a5071c492c15503d7c267da473 AS roughtime
WORKDIR /src
COPY roughtime/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -buildid=" -o /roughtime .

FROM node:24-bookworm-slim@sha256:c86ecead9e55a5210ac1727de38a4ca840bf03dcaf34dc9749addbf383b1920c
WORKDIR /app
COPY --from=roughtime /roughtime /usr/local/bin/roughtime
COPY package.json config.json *.mjs ./
EXPOSE 8080
CMD ["node", "server.mjs"]
