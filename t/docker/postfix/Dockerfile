FROM registry.fedoraproject.org/fedora-minimal:latest

LABEL maintainer=dockerhub@mimedefang.org

ENV TZ=Europe/Utc

RUN microdnf -y --nodocs install postfix perl make gcc perl-Net-DNS sendmail-milter-devel \
	perl-MIME-tools perl-Test-Class perl-Test-Most spamassassin mimedefang \
	rpm-build autoconf perl-Unix-Syslog supervisor initscripts rsyslog

RUN microdnf clean all -y

RUN postconf -e 'smtpd_milters = inet:10997'

RUN postconf -e 'non_smtpd_milters = $smtpd_milters'

RUN postconf -e 'myhostname = example.com'

RUN postconf -e 'inet_interfaces = 127.0.0.1'

# RUN postconf -e 'maillog_file = /var/log/maillog'

RUN newaliases

COPY ./supervisord.conf /etc/supervisord.conf

# COPY startMD.sh /startMD.sh

# RUN chmod 700 "/startMD.sh"

EXPOSE 25

# ENTRYPOINT "/startMD.sh"

CMD ["/usr/bin/supervisord"]
