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

TIMEOUT=10 # in ms

[ $SLURM_NODELIST ] || die "are you running outside of SLURM?"
[ $WORK_DIR ] || WORK_DIR=$(pwd)

cd ${WORK_DIR}

if [ ! -e tmp ]; then
  mkdir tmp
  chown 2775 tmp
fi

dump_fts -n -t ${TIMEOUT} > tmp/fts.out.${START_TIME}
scontrol show hostname ${SLUM_NODELIST} > tmp/job_nodes.${START_TIME}
ibnetdiscover -p -t ${TIMEOUT} |grep -f tmp/job_nodes.${START_TIME}|grep -e "^CA" |awk '{print $2}' > tmp/lids_of_job_members.${START_TIME}
for each in $(cat tmp/lids_of_job_members.${START_TIME}); do
  OUTPUT=$(saquery -x $each)
  echo $OUTPUT
done | sed 's/.*\.\.\([0-9]\+\) .*\.\.\([0-9]\+\) .*\.\.\([0-9]\+\) .*\.\.\([0-9]\+\)/\1:\2:\3:\4/' > tmp/neighbors.${START_TIME}

# Balance the queries
python balance_queries.py --forwardingdb tmp/fts.out.${START_TIME} --neighbors tmp/neighbors.${START_TIME} > ${WORK_DIR}/balance.out.${START_TIME}
