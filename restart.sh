#!/bin/bash
pid_list=($(ps -ef | grep nginx | grep process | awk '{print $2}'))
echo ${pid_list[@]}
for element in ${pid_list[@]}
#也可以写成for element in ${array[*]}
do
 kill -9 $element
done
workdir=$(cd $(dirname $0); pwd)
./objs/nginx

