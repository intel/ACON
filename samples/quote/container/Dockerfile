FROM alpine:latest as builder
RUN apk update && apk add g++ libc++-static
COPY sdk/include/* .
COPY samples/quote/container/src/* .
RUN g++ -o quote_server --static quote_server.cpp

FROM busybox:latest
COPY --from=builder quote_server .
ENTRYPOINT ["./quote_server"]
