FROM ruby:2.5.1-alpine

ARG GEM_VERSION="> 0"

COPY pkg/syslogstash-$GEM_VERSION.gem /tmp/syslogstash.gem

RUN apk update \
	&& apk add build-base \
	&& gem install /tmp/syslogstash.gem \
	&& apk del build-base \
	&& rm -f /var/cache/apk/* /tmp/syslogstash.gem

ENTRYPOINT ["/usr/local/bundle/bin/syslogstash"]
