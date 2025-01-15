#!/bin/bash
# test_sparse.sh [PLUGINS] [ENCODE] [DECODE]
#
# Tests whether we deal with sparsity correctly
#

TESTFILE=testfile

do_copy()
# $1: "-a" (or "-a -b 16k") or empty
# $2: plugin: "-L ./libddr_xxx=xxx"
# $3: encrypt or compress ...
# $4: decrypt or decompress ...
{
	rm -f ${TESTFILE}.copy2 ${TESTFILE}.copy
	if test -z "$3"; then
		echo ./dd_rescue $1 $2 ${TESTFILE} ${TESTFILE}.copy || return
		./dd_rescue $1 $2 ${TESTFILE} ${TESTFILE}.copy || return
	elif test -z "$4"; then
		echo ./dd_rescue $1 $2$3 ${TESTFILE} ${TESTFILE}.copy || return
		./dd_rescue $1 $2$3 ${TESTFILE} ${TESTFILE}.copy || return
	else
		echo ./dd_rescue $1 $2$3 ${TESTFILE} ${TESTFILE}.copy2 || return
		./dd_rescue $1 $2$3 ${TESTFILE} ${TESTFILE}.copy2 || return
		echo ./dd_rescue $1 $2$4 ${TESTFILE}.copy2 ${TESTFILE}.copy || return
		./dd_rescue $1 $2$4 ${TESTFILE}.copy2 ${TESTFILE}.copy || return
		du ${TESTFILE}.copy2
		rm ${TESTFILE}.copy2
	fi
}

my_exit()
{
	echo "ERROR $1: $2" 1>&2
	rm -f ${TESTFILE}.copy2 ${TESTFILE}.copy ${TESTFILE}
	exit $1
}

SZ=${4:-10M}
EH=$5
mktestfile()
{
	echo "./dd_rescue -qt -Z 0 -m $SZ ${TESTFILE}
./dd_rescue -q -S 32k -m 16k /dev/zero ${TESTFILE}
./dd_rescue -q -S 1M -m 1M /dev/zero ${TESTFILE}
./dd_rescue -q -S 2308k -R -b 16k -m 256k README.dd_rescue ${TESTFILE}
./dd_rescue -q -S 2560k -m 256k dd_rescue ${TESTFILE}
./dd_rescue -q -S 3M -m 1M /dev/zero ${TESTFILE}
./dd_rescue -q -S 5140k -m 278k /dev/zero ${TESTFILE}
./dd_rescue -q -S 7140k -m 278k /dev/zero ${TESTFILE}
"
	if test -n "$EH"; then echo ./dd_rescue -S 0 -m 64k /dev/zero ${TESTFILE}; fi
	# Create sparse file
	./dd_rescue -qt -Z 0 -m $SZ ${TESTFILE}
	./dd_rescue -q -S 32k -m 16k /dev/zero ${TESTFILE}
	./dd_rescue -q -S 1M -m 1M /dev/zero ${TESTFILE}
	# Some compressible content: Text and binary
	./dd_rescue -q -S 2304k -R -b 16k -m 256k README.dd_rescue ${TESTFILE}
	./dd_rescue -q -S 2560k -m 256k dd_rescue ${TESTFILE}
	./dd_rescue -q -S 3M -m 1M /dev/zero ${TESTFILE}
	./dd_rescue -q -S 5140k -m 278k /dev/zero ${TESTFILE}
	./dd_rescue -q -S 7140k -m 278k /dev/zero ${TESTFILE}
	if test -n "$EH"; then ./dd_rescue -S 0 -m 64k /dev/zero ${TESTFILE}; fi
}

mktestfile
# Without -a
do_copy "" "$1" "$2" "$3"
ERR=$?
if test $ERR != 0; then my_exit $ERR "Copy error"; fi
cmp ${TESTFILE} ${TESTFILE}.copy
ERR=$?
if test $ERR != 0; then my_exit $((ERR+32)) "Compare error"; fi
# With -a
do_copy "-a -b 16k" "$1" "$2" "$3"
ERR=$?
if test $ERR == 13; then
	echo "INFO: sparse not supported with "${1%%=*}" (no error)"
elif test $ERR != 0; then
	my_exit $((ERR+64)) "Error with sparse"
else
	du ${TESTFILE} ${TESTFILE}.copy
	cmp ${TESTFILE} ${TESTFILE}.copy
	ERR=$?
	if test $ERR != 0; then my_exit $((ERR+96)) "Sparse compare error"; fi
fi
do_copy "-ar" "$1" "$2" "$3"
ERR=$?
if test $ERR == 13; then
	echo "INFO: reverse not supported with "${1%%=*}" (no error)"
elif test $ERR != 0; then
	my_exit $((ERR+64)) "Error with sparse"
else
	du ${TESTFILE} ${TESTFILE}.copy
	cmp ${TESTFILE} ${TESTFILE}.copy
	ERR=$?
	if test $ERR != 0; then my_exit $((ERR+96)) "Sparse compare error"; fi
fi
rm -f ${TESTFILE}.copy2 ${TESTFILE}.copy ${TESTFILE}
