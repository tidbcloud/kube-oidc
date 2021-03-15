FROM golang:alpine as builder

RUN apk --update add ca-certificates

WORKDIR /go/src/

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -a -ldflags '-extldflags "-s -w -static"' -o /go/bin/kube-oidc-proxy ./cmd/kube-oidc-proxy

FROM scratch

# Add in certs
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Add the binary
COPY --from=builder /go/bin/kube-oidc-proxy /usr/local/bin/kube-oidc-proxy

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/kube-oidc-proxy"]