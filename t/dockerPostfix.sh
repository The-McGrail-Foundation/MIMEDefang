#!/bin/sh

echo "Building MIMEDefang inside Docker..."

dnf remove -y --noautoremove mimedefang 1>/dev/null 2>&1
make distclean 1>/dev/null 2>&1
./configure 1>/dev/null 2>&1
make 1>/dev/null 2>&1
make install 1>/dev/null 2>&1
/usr/local/bin/mimedefang-multiplexor -m 2 -x 10 -y 0 -U defang -b 600 -E -l -s /var/spool/MIMEDefang/mimedefang-multiplexor.sock
/usr/local/bin/mimedefang -m /var/spool/MIMEDefang/mimedefang-multiplexor.sock -y -R -1 -U defang -r -H -s -t -q -p inet:10997
postfix start
chown root t/data/md.conf

echo "Starting regression tests inside Docker..."
make test
