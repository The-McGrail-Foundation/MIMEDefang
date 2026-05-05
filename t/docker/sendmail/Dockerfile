FROM registry.fedoraproject.org/fedora-minimal:latest

LABEL maintainer=dockerhub@mimedefang.org

ENV TZ=Europe/Utc

RUN microdnf -y install sendmail sendmail-cf perl make gcc perl-Net-DNS sendmail-milter-devel \
	perl-MIME-tools perl-Test-Class perl-Test-Most spamassassin mimedefang \
	rpm-build autoconf perl-Unix-Syslog supervisor initscripts rsyslog

RUN microdnf -y clean all

# RUN useradd defang

RUN echo 'example.com' >>/etc/mail/local-host-names
RUN sed -i 's/FEATURE(`conncontrol.*//' /etc/mail/sendmail.mc
RUN echo -n 'INPUT_MAIL_FILTER(`mimedefang' >>/etc/mail/sendmail.mc
RUN echo -n "'" >>/etc/mail/sendmail.mc
RUN echo -n ', `S=inet:10997@127.0.0.1, F=T, T=S:1m;R:1m' >>/etc/mail/sendmail.mc
RUN echo -n "'" >>/etc/mail/sendmail.mc
RUN echo ")" >>/etc/mail/sendmail.mc

RUN make -C /etc/mail

COPY ./supervisord.conf /etc/supervisord.conf

# COPY startMD.sh /startMD.sh

# RUN chmod 700 "/startMD.sh"

EXPOSE 25

# ENTRYPOINT "/startMD.sh"

CMD ["/usr/bin/supervisord"]
