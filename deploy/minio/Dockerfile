# MinIO stopped publishing community container images, so local development builds the server
# from source at a pinned commit (module pseudo-version resolves via proxy.golang.org).
# Local development only. Production uses AWS S3 (see infra/).
FROM golang:1.24-alpine AS build
RUN go install github.com/minio/minio@v0.0.0-20260212201848-7aac2a2c5b7c

FROM alpine:3.21
COPY --from=build /go/bin/minio /usr/bin/minio
RUN adduser -S -u 10002 minio && mkdir /data && chown minio /data
USER 10002
EXPOSE 9000 9001
HEALTHCHECK --interval=5s --timeout=3s --retries=12 CMD wget -q -O /dev/null http://127.0.0.1:9000/minio/health/live || exit 1
ENTRYPOINT ["/usr/bin/minio"]
