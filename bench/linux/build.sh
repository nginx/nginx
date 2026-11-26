#!/bin/sh
# Build the benchmark tools and the nginx variants inside the container.
# Sources are the worktrees mounted at /w; builds go to /build (container-local).
#
#   stock  nginx/ at master (git archive, so uncommitted experiment code is excluded)
#   p1     nginx-fp/      patch 0001
#   p12    nginx-bucket/  patches 0001+0002
#   p123   nginx-smooth/  patches 0001+0002+0003
set -e
mkdir -p /build/bin

cd /w/bench/linux
go build -o /build/bin/backend backend.go
go build -o /build/bin/loadgen loadgen.go

src() { # name dir
  rm -rf /build/$1 && mkdir -p /build/$1
  if [ "$1" = stock ]; then
    git -c safe.directory="*" -C /w/nginx archive master | tar -x -C /build/$1
  else
    rsync -a --exclude 'objs*' --exclude .git /w/$2/ /build/$1/
  fi
}

for v in stock:nginx p1:nginx-fp p12:nginx-bucket p123:nginx-smooth; do
  name=${v%%:*}; dir=${v#*:}
  src $name $dir
  cd /build/$name
  ./auto/configure --with-stream --with-cc-opt='-O2' --without-http_gzip_module \
      --without-http_rewrite_module --with-threads > /build/$name.configure.log 2>&1
  make -j"$(nproc)" > /build/$name.make.log 2>&1
  cp objs/nginx /build/bin/nginx-$name
  echo "built $name: $(md5sum objs/nginx | cut -c1-12)"
done
