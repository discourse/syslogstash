FROM ruby:2.6

ARG GEM_VERSION="> 0"

COPY pkg/syslogstash-$GEM_VERSION.gem /tmp/syslogstash.gem

RUN gem install /tmp/syslogstash.gem \
	&& rm -f /tmp/syslogstash.gem

ENTRYPOINT ["/usr/local/bundle/bin/syslogstash"]
