#!/bin/bash

#################
# split_queries.sh
#
# v1.0 April 30, 2015
#
# Copyright 2015 Blake Caldwell
# Oak Ridge National Laboratory
#
# This program is part of balanced-perfquery. 
# This program is licensed under GNU GPLv3. Full license in LICENSE
#
# This script takes to balance.out with the queries for all nodes and splits
# just the queries for the current host name. The queries then go to a file
# that will be read by wrapper_once.sh when spawning the perfqueries
#
#################

START_TIME=$1
[ $START_TIME ] || die "the first argument must be the START_TIME"
[ $WORK_DIR ] || WORK_DIR=$(pwd)

cd ${WORK_DIR}

mkdir -p perfqueries/$START_TIME

if [ ! -e balance.out.$START_TIME ]; then
  die wrapper_once.sh did not generate balance.out.$START_TIME
fi

if [ ! -e perfqueries/$START_TIME ]; then
  die "failed to create directory perfqueries/$START_TIME"
fi

# Reads the output of the balancer file and parses it into a per_node list.
# This script should be run once on job startup
LID=$(cat /sys/class/infiniband/mlx4_0/ports/1/lid)
LID=$(echo $LID| xargs -i'{ }' printf "%d\n" '{ }')
cat balance.out.$START_TIME | awk -F':' "\$1 == $LID { print \$2\":\"\$3 }" > perfqueries/${START_TIME}/$(hostname)_perfqueries
