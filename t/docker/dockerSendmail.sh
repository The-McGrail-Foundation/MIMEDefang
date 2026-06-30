#!/bin/sh

echo "Building MIMEDefang inside Docker..."

VER=$(perl -I modules/lib -e 'use Mail::MIMEDefang; print Mail::MIMEDefang::md_version();')
echo "MIMEDefang source version: $VER"

echo ">>> Installing initscripts..."
dnf install -y initscripts 1>/dev/null 2>&1 || true
echo ">>> Removing existing mimedefang package..."
dnf remove -y --noautoremove mimedefang 1>/dev/null 2>&1 || true
echo ">>> make distclean..."
make distclean 1>/dev/null 2>&1 || true
# Remove any stale tarball from a previous build (source tree is bind-mounted)
rm -f Mail-MIMEDefang-*.tar.gz Mail-MIMEDefang-*.tar
echo ">>> perl Makefile.PL..."
perl Makefile.PL MAKEMETA=1 INSTALLDIRS=vendor 1>/dev/null 2>&1 || { echo "perl Makefile.PL FAILED"; exit 1; }
echo ">>> make tardist..."
make tardist 1>/dev/null 2>&1 || { echo "make tardist FAILED"; exit 1; }
mkdir -p ~/rpmbuild/SOURCES ~/rpmbuild/BUILD
cp "Mail-MIMEDefang-${VER}.tar.gz" ~/rpmbuild/SOURCES
make spec 1>/dev/null 2>&1 || { echo "make spec FAILED"; exit 1; }
rm -rf ~/rpmbuild/RPMS/x86_64/mimedefang-*
echo ">>> rpmbuild -bb..."
rpmbuild -bb redhat/mimedefang.spec 1>/dev/null 2>&1 || { echo "rpmbuild FAILED"; exit 1; }
echo ">>> dnf install..."
dnf -y install ~/rpmbuild/RPMS/x86_64/mimedefang-* || { echo "dnf install FAILED"; exit 1; }

cp t/data/mimedefang-test-filter /etc/mail/mimedefang-filter

chown root t/data/md.conf
mkdir -p /root/.spamassassin
touch /root/.spamassassin/user_prefs
rm -f /var/spool/mail/defang*

# Ensure spool dir exists and is writable by defang
mkdir -p /var/spool/MIMEDefang
chown defang:defang /var/spool/MIMEDefang
chmod 750 /var/spool/MIMEDefang

# Custom rsyslog config with SysSock.Use="on" (Fedora default disables /dev/log)
cat > /tmp/rsyslog-test.conf << 'EOF'
module(load="imuxsock" SysSock.Use="on")
*.* /var/log/messages
EOF
touch /var/log/messages
chmod 666 /var/log/messages

echo "Starting rsyslogd..."
/usr/sbin/rsyslogd -n -f /tmp/rsyslog-test.conf >/var/log/rsyslog.out 2>&1 &

echo "Waiting for /dev/log socket..."
for i in $(seq 1 30); do
    if [ -S /dev/log ]; then
        echo "/dev/log is ready"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "WARNING: /dev/log did not appear in time"
    fi
    sleep 1
done

# Add our test domain name to hosts(5) to make sendmail(8) start faster
H=$(tail -n1 /etc/hosts)
cp /etc/hosts ~/hosts.new
sed -i "s/$H/$H example.com/" ~/hosts.new
cp -f ~/hosts.new /etc/hosts

echo "Starting mimedefang-multiplexor..."
/usr/bin/mimedefang-multiplexor -D -m 2 -x 10 -y 0 -U defang -b 600 -l \
    -s /var/spool/MIMEDefang/mimedefang-multiplexor.sock \
    >/var/log/multiplexor.log 2>&1 &

echo "Starting mimedefang..."
/usr/bin/mimedefang -D -m /var/spool/MIMEDefang/mimedefang-multiplexor.sock \
    -U defang -q -p inet:10997 \
    >/var/log/mimedefang-milter.log 2>&1 &

echo "Starting sendmail..."
/usr/sbin/sendmail -bd

echo "Waiting for multiplexor socket..."
for i in $(seq 1 30); do
    if [ -S /var/spool/MIMEDefang/mimedefang-multiplexor.sock ]; then
        echo "Multiplexor socket is ready"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "WARNING: Multiplexor socket did not appear in time"
    fi
    sleep 1
done

echo "Waiting for MIMEDefang milter to be ready on port 10997..."
for i in $(seq 1 30); do
    if perl -e "use IO::Socket::INET; IO::Socket::INET->new('127.0.0.1:10997') or exit 1" 2>/dev/null; then
        echo "MIMEDefang milter is ready"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "WARNING: MIMEDefang milter did not start in time"
    fi
    sleep 1
done

echo "Starting regression tests inside Docker..."
make test NET_TEST=yes SMTP_TEST=yes
RC=$?

exit $RC
