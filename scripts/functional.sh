#!/bin/bash

cd /var/tmp
wget "https://github.com/linux-test-project/ltp/releases/download/20250130/ltp-full-20250130.tar.xz"
tar xvf "ltp-full-20250130.tar.xz"

mkdir /var/tmp/ltp
cd "ltp-full-20250130"
./configure --prefix=/var/tmp/ltp
make -j$(nproc) install

ln -sf /var/tmp/ltp /opt/ltp
ls -al /opt/ltp

which ubench


# httpd-tests
cd /var/tmp
git clone https://github.com/apache/httpd-tests.git
cd httpd-tests
cpanm Bundle::ApacheTest HTTP::DAV DateTime Time::HiRes Test::Harness Crypt::SSLeay Net::SSLeay IO::Socket::SSL IO::Socket::IP IO::Select LWP::Protocol::https AnyEvent AnyEvent::WebSocket::Client LWP::Protocol::AnyEvent::http FCGI
cpanm --force Apache::Test
cpanm --local-lib=~/perl5 local::lib && eval $(perl -I ~/perl5/lib/perl5/ -Mlocal::lib)
which apxs
perl Makefile.PL -apxs /usr/bin/apxs


cd /opt/ltp
for i in {1..2}; do
  echo "===== Run $i at $(date) ====="
  ./kirk -f ltp -r syscalls
done
cd /var/tmp/ltp
for i in {1..2}; do
  echo "===== Run $i at $(date) ====="
  ubench -i 1
done
cd /var/tmp/httpd-tests
for i in {1..2}; do
  echo "===== Run $i at $(date) ====="
  t/TEST
done
