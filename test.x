#!/bin/sh
#
# students must NOT change this file in any way!!!
TEST=$0

# this is the commandline to use
INPUT="$1"
# CMD="./tcarp -n $INPUT"
CMD="./tcarp $INPUT"


# this is the correct output
cat .${INPUT}.correct > $INPUT.correct 

# don't change anything else
echo "  Running: $CMD"
$CMD > ${INPUT}.myoutput 2>&1
if cmp -s ${INPUT}.correct ${INPUT}.myoutput; then
    echo "PASSES"; exit 0
else
    echo "FAILS"
    echo '==== output differences: < means the CORRECT output, > means YOUR output'
    echo 'see man page for "diff" and "cat" with arguments "-vet" for details on the output'
    diff ${INPUT}.correct ${INPUT}.myoutput | cat -evt
    exit 99
fi
