#!/bin/bash
# Script to test crypt module

enc_dec_compare_noxit()
{
	file=$1; alg=$2; 
	if test -n "$3"; then keyargs=":$3"; else unset keyargs; fi
	if test -n "$4"; then othargs=":$4"; else unset othargs; fi
	if test -n "$5"; then eng=":engine=$5"; else unset eng; fi
	if test -n "$6"; then opt="$6"; else opt="-qptA"; fi
	echo "#Validating enc/decryption $eng $alg $othargs"
	cp -p $file.enc $file.enc.old 2>/dev/null
	echo $VG ./dd_rescue $opt -L ./libddr_crypt.so=enc$eng:weakrnd:alg=$alg:$keyargs$othargs $file $file.enc 
	if test -n "$7"; then
		echo echo $7 \| $VG ./dd_rescue $opt -L ./libddr_crypt.so=enc$eng:weakrnd:alg=$alg$keyargs$othargs $file $file.enc 
		echo "$7" | $VG ./dd_rescue $opt -L ./libddr_crypt.so=enc$eng:weakrnd:alg=$alg$keyargs$othargs $file $file.enc || return 1
	else
		echo $VG ./dd_rescue $opt -L ./libddr_crypt.so=enc$eng:weakrnd:alg=$alg$keyargs$othargs $file $file.enc 
		$VG ./dd_rescue $opt -L ./libddr_crypt.so=enc$eng:weakrnd:alg=$alg$keyargs$othargs $file $file.enc || return 1
	fi
	if test -n "$7"; then
		echo echo $7 \| $VG ./dd_rescue $opt -L ./libddr_crypt.so=dec$eng:weakrnd:alg=$alg$othargs $file.enc $file.cmp 
		echo "$7" | $VG ./dd_rescue $opt -L ./libddr_crypt.so=dec$eng:weakrnd:alg=$alg$othargs $file.enc $file.cmp || return 2
	else
		echo $VG ./dd_rescue $opt -L ./libddr_crypt.so=dec$eng:weakrnd:alg=$alg$othargs $file.enc $file.cmp 
		$VG ./dd_rescue $opt -L ./libddr_crypt.so=dec$eng:weakrnd:alg=$alg$othargs $file.enc $file.cmp || return 2
	fi
	cmp $file $file.cmp || return 3
}

enc_dec_compare()
{
	enc_dec_compare_noxit "$@"
	RC=$?
	if test $RC = 0; then return; fi
	echo "*** ERROR $RC ***"
	ls -l KEYS* IVS* dd_rescue.*
	cat KEYS* IVS*
	VG=strace enc_dec_compare_noxit "$@"
	RC=$?
	if test $RC != 0; then exit $RC; fi
}

enc_dec_compare_keys()
{
	enc_dec_compare "$1" "$2" "$3" "$4:keysfile:ivsfile" "$5" "$6" "$7"
}

run_ddr()
{
	echo $VG ./dd_rescue "$@"
	$VG ./dd_rescue "$@"
}


ECB_ALGS="AES192-ECB AES192+-ECB AES192x2-ECB"
CBC_ALGS="AES192-CBC AES192+-CBC AES192x2-CBC"
CTR_ALGS="AES128-CTR AES128+-CTR AES128x2-CTR AES192-CTR AES192+-CTR AES192x2-CTR AES256-CTR AES256+-CTR AES256x2-CTR"
if test "$1" = "-q"; then
  TESTALGS=""
else
  TESTALGS="$ECB_ALGS $CBC_ALGS $CTR_ALGS"
fi

echo "#We will eat a lot of entropy ... hopefully you have some left afterwards!"

# MAIN TEST
if test -e test_aes -a -z "$SKIP_MAIN"; then
  LOG=test_aes.log
  #for ALG in $TESTALGS; do echo $VG ./test_aes $ALG 10000; $VG ./test_aes $ALG 10000 >$LOG 2>&1; if test $? != 0; then cat $LOG; echo "ERROR"; exit 1; fi; done
  #rm $LOG
  echo $VG test_aes -s -w AES128-CTR 50000 0 15392
  $VG ./test_aes -s -w AES128-CTR 50000 0 15392
  for len in $(seq 0 130); do
    for ALG in $TESTALGS; do echo $VG ./test_aes $ALG 10 0 $len; $VG ./test_aes $ALG 10 0 $len >$LOG 2>&1; if test $? != 0; then cat $LOG; echo "ERROR"; exit 1; fi; done
  done
  rm $LOG
fi
# Pass passphrase via pipe
echo "# *** pass via pbkf2, pipe ***"
enc_dec_compare dd_rescue AES192-CTR "" "pbkdf2:passfd=0" "" "-qptA" "password"
# Reverse (CTR, ECB)
echo "# *** Reverse ***"
enc_dec_compare_keys dd_rescue AES192-CTR keygen:ivgen "" "" "-qptAr"
enc_dec_compare_keys dd_rescue AES192-ECB keygen:ivgen "" "" "-qptAr"
# Appending (CTR, ECB only when block-aligned)
enc_dec_compare_keys dd_rescue AES192-CTR
# This one fails on musl/clang if the size of the dd_rescue binary is not a multiple of 16 (crypt blk size)
run_ddr -qAx -L ./libddr_crypt.so=enc:weakrnd:alg=AES192-CTR:keysfile:ivsfile dd_rescue dd_rescue.enc || exit 1
cat dd_rescue dd_rescue > dd_rescue2
run_ddr -qAp -L ./libddr_crypt.so=dec:weakrnd:alg=AES192-CTR:keysfile:ivsfile dd_rescue.enc dd_rescue.cmp || exit 2
cmp dd_rescue.cmp dd_rescue2 || exit 3
# encrypt forward, decrypt backward
echo "# *** Forward enrypt, Backward decrypt ***"
run_ddr -qt  -L ./libddr_crypt.so=enc:weakrnd:alg=AES192-CTR:keysfile:ivsfile dd_rescue dd_rescue.enc || exit 1
run_ddr -qtr -L ./libddr_crypt.so=dec:weakrnd:alg=AES192-CTR:keysfile:ivsfile dd_rescue.enc dd_rescue.cmp || exit 2
cmp dd_rescue.cmp dd_rescue || exit 3
echo "# *** Backward enrypt, Forward decrypt ***"
run_ddr -qtr  -L ./libddr_crypt.so=enc:weakrnd:alg=AES192-CTR:keysfile:ivsfile dd_rescue dd_rescue.enc || exit 1
run_ddr -qt  -L ./libddr_crypt.so=dec:weakrnd:alg=AES192-CTR:keysfile:ivsfile dd_rescue.enc dd_rescue.cmp || exit 2
cmp dd_rescue.cmp dd_rescue || exit 3
rm dd_rescue2

# Holes (all), skiphole
echo "# *** Holes ***"
# Produce file that consists of dd_rescue + hole + dd_rescue
run_ddr -qpt dd_rescue dd_rescue3
run_ddr -qS 512k dd_rescue dd_rescue3
# Ensure there is a hole even if dd_rescue is long
run_ddr -qS 384k -m 128k /dev/zero dd_rescue3
# Test without and with skiphole
enc_dec_compare_keys dd_rescue3 AES192-CTR keygen:ivgen "" "" "-qpt"
enc_dec_compare_keys dd_rescue3 AES192-CTR keygen:ivgen skiphole "" "-qpt"
# Store 384k-512k in cmp3
run_ddr -qt -s 384k -m 128k -S 0 dd_rescue3.cmp dd_rescue3.cmp3
# Should be 128k of zeroes
run_ddr -qm 128k /dev/zero dd_rescue3.cmp2
cmp dd_rescue3.cmp2 dd_rescue3.cmp3 || exit 4
# Repeat test with reverse
enc_dec_compare_keys dd_rescue3 AES192-CTR keygen:ivgen "" "" "-qptr"
enc_dec_compare_keys dd_rescue3 AES192-CTR keygen:ivgen skiphole "" "-qptr"
run_ddr -qt -s 384k -m 128k -S 0 dd_rescue3.cmp dd_rescue3.cmp3
cmp dd_rescue3.cmp2 dd_rescue3.cmp3 || exit 4

#exit 1

# Chain with lzo, hash (all)
if test -n "$HAVE_LZO"; then
echo "# *** Plugin chains ... ***"
rm -f CHECHSUMS.*
SHA256SUM=`type -p sha256sum`
run_ddr -pqt -L ./libddr_hash.so=sha256:outnm=,./libddr_lzo.so=compr,./libddr_hash.so=sha256:output,./libddr_crypt.so=enc:AES192-CTR:keygen:ivgen:weakrnd:keysfile:ivsfile,./libddr_hash.so=sha256:outnm= dd_rescue3 dd_rescue3.enc || exit 1
if test -n "$SHA256SUM"; then
sha256sum -c CHECKSUMS.sha256 || exit 4
else
echo "WARNING: Cant run sha256sum, binary not found"
fi
run_ddr -pqt -L ./libddr_hash.so=sha256:chknm,./libddr_crypt.so=AES192-CTR:weakrnd:dec:keysfile:ivsfile,./libddr_lzo.so=decompr,./libddr_hash.so=sha256:outnm dd_rescue3.enc dd_rescue3.cmp
if test -n "$SHA256SUM"; then
sha256sum -c CHECKSUMS.sha256 || exit 4
fi
cmp dd_rescue3.cmp dd_rescue3 || exit 3
cat CHECKSUMS.sha256
ls -lAF dd_rescue3*
else
echo "# *** SKIP Plugin chains...  ***"
fi

# Chain with lzo, hash sha512 (all)
if test -n "$HAVE_LZO"; then
echo "# *** Plugin chains ... ***"
SHA512SUM=`type -p sha512sum`
run_ddr -pqt -L ./libddr_hash.so=sha512:outnm=,./libddr_lzo.so=compr,./libddr_hash.so=sha512:output,./libddr_crypt.so=enc:AES192-CTR:keygen:ivgen:weakrnd:keysfile:ivsfile,./libddr_hash.so=sha512:outnm= dd_rescue3 dd_rescue3.enc || exit 1
if test -n "$SHA512SUM"; then
sha512sum -c CHECKSUMS.sha512 || exit 4
else
echo "WARNING: Cant run sha512sum, binary not found"
fi
run_ddr -pqt -L ./libddr_hash.so=sha512:chknm,./libddr_crypt.so=AES192-CTR:weakrnd:dec:keysfile:ivsfile,./libddr_lzo.so=decompr,./libddr_hash.so=sha512:outnm dd_rescue3.enc dd_rescue3.cmp
if test -n "$SHA6512SUM"; then
sha512sum -c CHECKSUMS.sha512 || exit 4
fi
cmp dd_rescue3.cmp dd_rescue3 || exit 3
cat CHECKSUMS.sha512
ls -lAF dd_rescue3*
fi
rm -f dd_rescue3 dd_rescue3.enc dd_rescue3.enc.old dd_rescue3.cmp dd_rescue3.cmp2 dd_rescue3.cmp3
# Various ways to pass in keys/IVs

# Padding variations
run_ddr -t -m 4100 /dev/urandom . || exit 1
enc_dec_compare_keys urandom AES192-CBC keygen:ivgen pad=always "" "-qpt"
enc_dec_compare_keys urandom AES192-CBC "" pad=asneeded "" "-qpt"
# For odd sizes, always and asneeded should be identical
cmp urandom.enc urandom.enc.old || exit 4
# zero padding does not work well for odd sizes (trailing zeroes)
#enc_dec_compare_keys urandom AES192-CBC "" pad=zero "" "-qpt"
# Reverse: Need to use ECB (reverse not possible with CBC)
enc_dec_compare_keys urandom AES192-ECB keygen:ivgen pad=always "" "-qptr"
enc_dec_compare_keys urandom AES192-ECB "" pad=asneeded "" "-qptr"
# For odd sizes, always and asneeded should be identical
cmp urandom.enc urandom.enc.old || exit 4
# Block aligned ("even")
run_ddr -t -m 4096 urandom urandom.new || exit 1
# Ensure that we don't have 01 or 02 02 or ... at the end,
# which would trip pad=asneeded
echo -n "a" | run_ddr -S 4095 -m 1 - urandom.new
mv urandom.new urandom
enc_dec_compare_keys urandom AES192-CBC "" pad=always "" "-qpt"
enc_dec_compare_keys urandom AES192-CBC "" pad=asneeded "" "-qpt"
# Those are not identical ...
#cmp urandom.enc urandom.enc.old || exit 4
enc_dec_compare_keys urandom AES192-CBC "" pad=zero "" "-qpt"
# For even sizes, zero and asneeded should be identical
cmp urandom.enc urandom.enc.old || exit 4
# Reverse
enc_dec_compare_keys urandom AES192-ECB "" pad=always "" "-qptr"
enc_dec_compare_keys urandom AES192-ECB "" pad=asneeded "" "-qptr"
# Those are not identical ...
#cmp urandom.enc urandom.enc.old || exit 4
enc_dec_compare_keys urandom AES192-ECB "" pad=zero "" "-qptr"
# For even sizes, zero and asneeded should be identical
cmp urandom.enc urandom.enc.old || exit 4
rm -f urandom urandom.enc urandom.enc.old urandom.cmp

# OpenSSL compatibility

echo "# *** OpenSSL compatibility ***"
OPENSSLMAJ=$(openssl version | head -n 1 | sed 's/^OpenSSL \([0-9]\).*/\1/')
if test "$OPENSSLMAJ" = "3"; then NOSALTHDR=:nosalthdr; fi
echo "openssl enc -aes-192-ctr -K 4d20e517cd98ff130ac160dcb4177ef1ab4e8f9501bc6e1d -iv f61059ec2d87a410853b8f1500dead00 -in dd_rescue -out dd_rescue.enc.o"
if openssl enc -aes-192-ctr -K 4d20e517cd98ff130ac160dcb4177ef1ab4e8f9501bc6e1d -iv f61059ec2d87a410853b8f1500dead00 -in dd_rescue -out dd_rescue.enc.o; then
  enc_dec_compare dd_rescue AES192-CTR "" keyhex=4d20e517cd98ff130ac160dcb4177ef1ab4e8f9501bc6e1d:ivhex=f61059ec2d87a410853b8f1500dead00
  cmp dd_rescue.enc dd_rescue.enc.o || exit 4
fi
echo "openssl enc -aes-192-cbc -K 4d20e517cd98ff130ac160dcb4177ef1ab4e8f9501bc6e1d -iv f61059ec2d87a410853b8f150752bd8f -in dd_rescue -out dd_rescue.enc.o"
if openssl enc -aes-192-cbc -K 4d20e517cd98ff130ac160dcb4177ef1ab4e8f9501bc6e1d -iv f61059ec2d87a410853b8f150752bd8f -in dd_rescue -out dd_rescue.enc.o; then
  enc_dec_compare dd_rescue AES192-CBC "" keyhex=4d20e517cd98ff130ac160dcb4177ef1ab4e8f9501bc6e1d:ivhex=f61059ec2d87a410853b8f150752bd8f
  cmp dd_rescue.enc dd_rescue.enc.o || exit 4
  rm -f dd_rescue.enc.o
fi
# Salted__ tests ...
echo "openssl enc -aes-192-ctr -pass pass:PASWD -S f61059ec2d87a410 -md sha256 -p -in dd_rescue -out dd_rescue.enc.o"
if openssl enc -aes-192-ctr -pass pass:PASWD -S f61059ec2d87a410 -md sha256 -p -in dd_rescue -out dd_rescue.enc.o; then
  enc_dec_compare dd_rescue AES192-CTR "" pass=PASWD:salthex=f61059ec2d87a410:opbkdf11:outkeyiv$NOSALTHDR
  cmp dd_rescue.enc dd_rescue.enc.o || exit 4
fi
echo "openssl enc -aes-192-ctr -pass pass:PASWD -S f61059ec2d87a410 -md md5 -p -in dd_rescue -out dd_rescue.enc.o"
if openssl enc -aes-192-ctr -pass pass:PASWD -S f61059ec2d87a410 -md md5 -p -in dd_rescue -out dd_rescue.enc.o; then
  enc_dec_compare dd_rescue AES192-CTR "" pass=PASWD:salthex=f61059ec2d87a410:opbkdf:outkeyiv$NOSALTHDR
  cmp dd_rescue.enc dd_rescue.enc.o || exit 4
fi
echo "openssl enc -aes-192-cbc -pass pass:PASWD -S f61059ec2d87a410 -md md5 -p -in dd_rescue -out dd_rescue.enc.o"
if openssl enc -aes-192-cbc -pass pass:PASWD -S f61059ec2d87a410 -md md5 -p -in dd_rescue -out dd_rescue.enc.o; then
  enc_dec_compare dd_rescue AES192-CBC "" pass=PASWD:salthex=f61059ec2d87a410:opbkdf:outkeyiv$NOSALTHDR
  cmp dd_rescue.enc dd_rescue.enc.o || exit 4
  rm -f dd_rescue.enc.o
fi
# Bug compat
echo "openssl enc -aes-192-ctr -K 4d20e517cd98ff130ac160dcb4177ef1ab4e8f9501bc6e1d -iv f61059ec2d87a410853b8f1500000000 -in dd_rescue -out dd_rescue.enc.o"
if openssl enc -aes-192-ctr -K 4d20e517cd98ff130ac160dcb4177ef1ab4e8f9501bc6e1d -iv f61059ec2d87a410853b8f1500000000 -in dd_rescue -out dd_rescue.enc.o; then
  enc_dec_compare dd_rescue AES192-CTR "" keyhex=4d20e517cd98ff130ac160dcb4177ef1ab4e8f9501bc6e1d:ivhex=f61059ec2d87a410853b8f1500dead00:ctrbug198
  cmp dd_rescue.enc dd_rescue.enc.o || exit 4
fi


echo "# *** Algorithms ... ***"
# Algs and Engines
for alg in $TESTALGS; do
	echo "# ** $alg **"
	# Generate key+IV, save to index file and use for decryption
	enc_dec_compare_keys dd_rescue $alg keygen:ivgen
	## Generate key+IV, save to binary files 
	#enc_dec_compare dd_rescue $alg keygen:ivgen keyfile=KEY:ivfile=IV
	# Use default salt generation 
	enc_dec_compare dd_rescue $alg "" pass=PWRD:pbkdf2
	# Use random numbers and write to index file
	enc_dec_compare dd_rescue $alg saltgen pass=PAWD:pbkdf2:saltsfile
done
echo "# *** Salt and XAttrs ***"
# Use random numbers and write to binary file
enc_dec_compare dd_rescue AES192-CTR saltgen pass=PWD_:pbkdf2:saltfile=SALT
if grep 'define HAVE_\(SYS\|ATTR\)_XATTR_H 1' config.h >/dev/null 2>&1 ; then
  # Use random numbers and write to xattr, fall back to saltsfile
  enc_dec_compare dd_rescue AES192-CTR saltgen pass=PSWD:pbkdf2:saltxattr:sxfallback
  # Save key and IV to xattrs
  enc_dec_compare dd_rescue AES192-CTR keygen:ivgen keyxattr:kxfallb:ivxattr:ixfallb
fi

HAVE_AESNI=`grep " sse4" /proc/cpuinfo 2>/dev/null | grep " aes " 2>/dev/null`
HAVE_AESARM=`grep " pmull " /proc/cpuinfo 2>/dev/null`
HAVE_LIBCRYPTO=`grep 'HAVE_LIBCRYPTO 1' config.h 2>/dev/null`
#HAVE_LZO=`grep 'HAVE_LIBLZO2 1' config.h 2>/dev/null`
if test -n "$TESTALGS"; then
  echo "# *** Engines comparison ***"
fi
for alg in $TESTALGS; do
	rm dd_rescue.enc.old dd_rescue.enc
	case $alg in AES???+-???)
		ENG="aes_c"
		;;
	*)
		ENG="aes_c openssl"
		;;
	esac
	if test -n "$HAVE_AESNI"; then
		ENG="$ENG aesni"
	fi
	if test -n "$HAVE_AESARM"; then
		ENG="$ENG aesarm64"
	fi
	if test -z "$HAVE_LIBCRYPTO"; then ENG=`echo $ENG | sed 's/ openssl//'`; fi
	if test "$HAVE_AES" = "0"; then ENG=`echo $ENG | sed 's/ aesni//'`; fi
	echo "#** Alg $alg engines $ENG **"
	for engine in $ENG; do
		enc_dec_compare dd_rescue $alg "" pass=PASSWORD:pbkdf2 $engine
		if test -e dd_rescue.enc.old; then cmp dd_rescue.enc dd_rescue.enc.old || exit 4; fi
	done
done

## TODO: Encryption with fault injection

rm -f dd_rescue.enc dd_rescue.enc.o dd_rescue.enc.old dd_rescue.cmp SALT SALT.* KEYS.* IVS.*
