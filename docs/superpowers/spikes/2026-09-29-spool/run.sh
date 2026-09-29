#!/bin/zsh
# 사용: run.sh <이름> <curl 추가 인자...> — mitmdump RSS 최대값과 curl 결과를 기록한다
cd "${0:a:h}"
name=$1; shift
pid=$(cat mitm.pid)
: > rss.$name
( while kill -0 $pid 2>/dev/null; do ps -o rss= -p $pid >> rss.$name; sleep 0.2; done ) &
sampler=$!
out=$(curl -sS -x http://127.0.0.1:18081 -o out.$name -w '%{http_code} hdr=%{time_starttransfer}s total=%{time_total}s bytes=%{size_download}' "$@" 2>&1)
kill $sampler 2>/dev/null
max=$(sort -n rss.$name | tail -1)
sha=$( [ -s out.$name ] && shasum -a 256 out.$name | cut -c1-16 )
echo "$name: $out maxRSS=$((max/1024))MB sha=$sha"
rm -f out.$name
