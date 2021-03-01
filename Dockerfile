FROM debian:buster-slim

ARG GEM_VERSION="> 0"

COPY pkg/syslogstash-$GEM_VERSION.gem /tmp/syslogstash.gem

RUN DEBIAN_FRONTEND=noninteractive apt-get update \
	&& DEBIAN_FRONTEND=noninteractive apt-get -y dist-upgrade \
	&& DEBIAN_FRONTEND=noninteractive apt-get -y install --no-install-recommends ruby \
	&& gem install /tmp/syslogstash.gem \
	&& rm -f /tmp/syslogstash.gem \
	&& DEBIAN_FRONTEND=noninteractive apt-get clean \
	&& ( find /var/lib/apt/lists -mindepth 1 -maxdepth 1 -delete || true ) \
	&& ( find /var/tmp -mindepth 1 -maxdepth 1 -delete || true ) \
	&& ( find /tmp -mindepth 1 -maxdepth 1 -delete || true )

ENTRYPOINT ["/usr/local/bin/syslogstash"]
