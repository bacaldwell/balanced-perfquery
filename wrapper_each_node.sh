#!/bin/bash

#################
# wrapper_each_node.sh
#
# v1.0 April 30, 2015
#
# Copyright 2015 Blake Caldwell
# Oak Ridge National Laboratory
#
# This program is part of balanced-perfquery. 
# This program is licensed under GNU GPLv3. Full license in LICENSE
#
#################

die() {
  echo "$@" 1>&2
  exit 1
}

START_TIME=$1
[ $START_TIME ] || die "the first argument must be the START_TIME"

LOOP_DELAY=$2
[ $LOOP_DELAY ] || die "the second argument must be the LOOP_DELAY"
[ $WORK_DIR ] WORK_DIR=$(pwd)

cd ${WORK_DIR}

if [ ! -e balance.out.$START_TIME ]; then
  die "balance.out.$START_TIME was not generated by balance_queries.py"
fi

${WORK_DIR}/split_queries.sh $START_TIME
# This will take balance.out and split it into the individual files the node is responsible for

if [ ! -e logs/${START_TIME} ]; then
  mkdir -p logs/${START_TIME}
fi

${WORK_DIR}/spawn_queries.sh $START_TIME $LOOP_DELAY > logs/${START_TIME}/$(hostname)_perfquery.log
# This will spawn N jobs in the background (where N is wc -l perfqueries/$HOSTNAME_perfqueries
#   and then wait until that sweep is complete. It writes the output to ${WORK_DIR}/logs/
#   It will loop forever until it is killed (by the slurm script)