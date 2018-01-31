# Run syslogstash

FROM ruby:2.3-alpine
MAINTAINER Matt Palmer "matt.palmer@discourse.org"

RUN apk update \
	&& apk add build-base \
	&& gem install syslogstash -v 1.3.0 \
	&& apk del build-base \
	&& rm -f /var/cache/apk/*

ENTRYPOINT ["/usr/local/bundle/bin/syslogstash"]
