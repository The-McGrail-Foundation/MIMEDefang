#!/bin/sh

echo "Building MIMEDefang inside Docker..."

dnf remove -y --noautoremove mimedefang 1>/dev/null 2>&1
make distclean 1>/dev/null 2>&1
./configure 1>/dev/null 2>&1
make distro 1>/dev/null 2>&1
mkdir -p ~/rpmbuild/SOURCES
mkdir -p ~/rpmbuild/BUILD
cp mimedefang-2.86.tar.gz ~/rpmbuild/SOURCES
rpmbuild -bb redhat/mimedefang.spec 1>/dev/null 2>&1
dnf -y install ~/rpmbuild/RPMS/x86_64/mimedefang-* 1>/dev/null 2>&1
cp t/data/mimedefang-test-filter /etc/mail/mimedefang-filter

/usr/bin/mimedefang-multiplexor -m 4 -x 10 -y 0 -U defang -l -d -s /var/spool/MIMEDefang/mimedefang-multiplexor.sock
/usr/bin/mimedefang -m /var/spool/MIMEDefang/mimedefang-multiplexor.sock -y -U defang -q -T -p inet:10997
# Add our test domain name to hosts(5) to make sendmail(8) start faster
H=`tail -n1 /etc/hosts`
cp /etc/hosts ~/hosts.new
sed -i "s/$H/$H example.com/" ~/hosts.new
cp -f ~/hosts.new /etc/hosts
sendmail -bd
chown root t/data/md.conf
mkdir -p /root/.spamassassin
touch /root/.spamassassin/user_prefs

echo "Starting regression tests inside Docker..."
make test
