#!/bin/sh

echo "Building MIMEDefang inside Docker..."

dnf remove -y --noautoremove mimedefang 1>/dev/null 2>&1
make distclean 1>/dev/null 2>&1
./configure 1>/dev/null 2>&1
make 1>/dev/null 2>&1
make install 1>/dev/null 2>&1
/usr/local/bin/mimedefang-multiplexor -U defang
/usr/local/bin/mimedefang -U defang -m /var/spool/MIMEDefang/mimedefang-multiplexor.sock -p inet:10997
# Add our test domain name to hosts(5) to make sendmail(8) start faster
H=`tail -n1 /etc/hosts`
cp /etc/hosts ~/hosts.new
sed -i "s/$H/$H example.com/" ~/hosts.new
cp -f ~/hosts.new /etc/hosts
sendmail -bd
chown root t/data/md.conf

echo "Starting regression tests inside Docker..."
make test
