#!/bin/bash
set -e
COMPRESS=${1:-lzo}
# create sparse test file
rm -f test test.comp.enc test.comp.enc2 test.cmp
echo ./dd_rescue -qt -S 256k dd_rescue test
./dd_rescue -qt -S 256k dd_rescue test
echo ./dd_rescue -q -S 2048k dd_rescue test
./dd_rescue -q -S 2048k dd_rescue test
echo ./dd_rescue -qax -m 256k /dev/zero test
./dd_rescue -qax -m 256k /dev/zero test
# Chain with hash, compress, hash, encrypt, hash
SIZE=$(stat -Lc "%s" test)
echo ./dd_rescue -L ./libddr_hash.so=sha256,./libddr_$COMPRESS.so=compress,./libddr_hash.so=sha256,./libddr_crypt.so=aes192-ctr:pbkdf2:pass=PASS:enc,./libddr_hash.so=sha256 test test.comp.enc
./dd_rescue -L ./libddr_hash.so=sha256,./libddr_$COMPRESS.so=compress,./libddr_hash.so=sha256,./libddr_crypt.so=aes192-ctr:pbkdf2:pass=PASS:enc,./libddr_hash.so=sha256 test test.comp.enc
echo ./dd_rescue -L ./libddr_hash.so=sha256,./libddr_crypt.so=aes192-ctr:pbkdf2:pass=PASS:dec:saltlen=$SIZE,./libddr_hash.so=sha256,./libddr_$COMPRESS.so=decompress,./libddr_hash.so=sha256 test.comp.enc test.cmp
./dd_rescue -L ./libddr_hash.so=sha256,./libddr_crypt.so=aes192-ctr:pbkdf2:pass=PASS:dec:saltlen=$SIZE,./libddr_hash.so=sha256,./libddr_$COMPRESS.so=decompress,./libddr_hash.so=sha256 test.comp.enc test.cmp
echo cmp test test.cmp
cmp test test.cmp
echo ./dd_rescue -aL ./libddr_hash.so=sha256,./libddr_$COMPRESS.so=compress,./libddr_hash.so=sha256,./libddr_crypt.so=aes192-ctr:pbkdf2:pass=PASS:enc,./libddr_hash.so=sha256 test test.comp.enc2
./dd_rescue -aL ./libddr_hash.so=sha256,./libddr_$COMPRESS.so=compress,./libddr_hash.so=sha256,./libddr_crypt.so=aes192-ctr:pbkdf2:pass=PASS:enc,./libddr_hash.so=sha256 test test.comp.enc2
echo ./dd_rescue -taL ./libddr_hash.so=sha256,./libddr_crypt.so=aes192-ctr:pbkdf2:pass=PASS:dec:saltlen=$SIZE,./libddr_hash.so=sha256,./libddr_$COMPRESS.so=decompress,./libddr_hash.so=sha256 test.comp.enc2 test.cmp
./dd_rescue -taL ./libddr_hash.so=sha256,./libddr_crypt.so=aes192-ctr:pbkdf2:pass=PASS:dec:saltlen=$SIZE,./libddr_hash.so=sha256,./libddr_$COMPRESS.so=decompress,./libddr_hash.so=sha256 test.comp.enc2 test.cmp
echo cmp test test.cmp
cmp test test.cmp
rm -f test test.comp.enc test.comp.enc2 test.cmp
