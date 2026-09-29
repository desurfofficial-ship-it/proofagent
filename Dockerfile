FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY packages ./packages
COPY services ./services
RUN go mod tidy && CGO_ENABLED=0 go build -o /proofagent-api ./services/api

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /proofagent-api /usr/local/bin/proofagent-api
EXPOSE 8080
ENTRYPOINT ["proofagent-api"]
