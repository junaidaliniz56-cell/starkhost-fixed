FROM golang:1.24-alpine AS build
WORKDIR /src
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /nova .

FROM alpine:3.20
RUN apk add --no-cache docker-cli git ca-certificates tzdata
COPY --from=build /nova /nova
ENV PORT=8085 DATA_DIR=/srv/hosting
EXPOSE 8085
CMD ["/nova"]
