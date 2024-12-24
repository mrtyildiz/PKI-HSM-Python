FROM golang:1.18-alpine as builder

ARG DOMAIN=procenne.com
# Install MailHog:
RUN apk --no-cache add --virtual build-dependencies \
    git \
  && mkdir -p /root/gocode \
  && export GOPATH=/root/gocode \
  && go install github.com/mailhog/MailHog@latest

FROM alpine:3
# Add mailhog user/group with uid/gid 1000.
RUN adduser -D -u 1000 mailhog

COPY --from=builder /root/gocode/bin/MailHog /usr/local/bin/

USER mailhog

WORKDIR /home/mailhog

ENTRYPOINT ["MailHog", "-ui-bind-addr", "0.0.0.0:8025", "-smtp-bind-addr", "0.0.0.0:1025", "-hostname", "${DOMAIN}"]

# Expose the SMTP and HTTP ports:
EXPOSE 1025 8025
