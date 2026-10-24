FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/bridge ./cmd/bridge

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/bridge /bridge
ENTRYPOINT ["/bridge"]
