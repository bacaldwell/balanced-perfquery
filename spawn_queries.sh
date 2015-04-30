#!/bin/bash

#################
# spawn_queries.sh
#
# v1.0 April 30, 2015
#
# Copyright 2015 Blake Caldwell
# Oak Ridge National Laboratory
#
# This program is part of balanced-perfquery. 
# This program is licensed under GNU GPLv3. Full license in LICENSE
#
# This script expects an input file $HOSTNAME_perfqueries with the lids and ports
# to check for each perfquery sweep
#
# This will run forever
#################

START_TIME=$1
[ $START_TIME ] || die "the first argument must be the START_TIME"

LOOP_DELAY=$2
[ $LOOP_DELAY ] || die "the second argument must be the LOOP_DELAY"

DIR=perfqueries

PORTS=$(cat $DIR/${START_TIME}/$(hostname)_perfqueries)

while true; do
  echo "Starting sweep at $(date +"%T.%N")"
  perfquery -C mlx4_0 -P 1 $PORTS
  echo "Finished sweep at $(date +"%T.%N")"
  if [ "$LOOP_DELAY" != "0" ]; then
    sleep $LOOP_DELAY 
  fi
done
