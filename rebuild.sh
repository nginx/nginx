workdir=$(cd $(dirname $0); pwd)
echo "workdir=${workdir}"
./auto/configure --prefix=/home/learning/nginx
make