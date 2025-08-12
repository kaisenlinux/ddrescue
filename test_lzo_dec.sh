#!/bin/bash
rm -f testfile testfile.compr testfile.cmp
set -e
COMPRESS=lzo
testcase()
{
	echo "Test with concatenated files len $1"
	./dd_rescue -qtZ0 -m $1 testfile
	./dd_rescue -b16k -qatL ./libddr_$COMPRESS.so=compress testfile testfile.compr
	./dd_rescue -b16k -qaxL ./libddr_$COMPRESS.so=compress testfile testfile.compr
	./dd_rescue -qx -m $1 testfile testfile
	echo ./dd_rescue -b16k -qatL ./libddr_$COMPRESS.so=decompress testfile.compr testfile.cmp
	./dd_rescue -b16k -qatL ./libddr_$COMPRESS.so=decompress testfile.compr testfile.cmp
	ls -l testfile testfile.compr testfile.cmp
	if ! cmp testfile testfile.cmp; then
		./dd_rescue -q -m $1 testfile testfile.single
		./dd_rescue -b16k -qatL ./libddr_$COMPRESS.so=compress testfile.single testfile.compr
		echo ./dd_rescue -b16k -vaxL ./libddr_$COMPRESS.so=compress:debug testfile.single testfile.compr
		$VG ./dd_rescue -b16k -vaxL ./libddr_$COMPRESS.so=compress:debug testfile.single testfile.compr
		echo ./dd_rescue -b16k -vatL ./libddr_$COMPRESS.so=decompress:debug testfile.compr testfile.cmp
		$VG ./dd_rescue -b16k -vatL ./libddr_$COMPRESS.so=decompress:debug testfile.compr testfile.cmp
		rm testfile.single
		echo cmp testfile testfile.cmp
		cmp testfile testfile.cmp
	fi
}

ln=32640
while test $ln -lt 32860; do
	testcase $ln
	let ln+=1
done
rm -f testfile testfile.compr testfile.cmp
