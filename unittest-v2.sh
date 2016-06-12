#!/bin/bash

BS=256
data_bytes=1048576
data_blocks=$(( $data_bytes / $BS))
image_kb=1044
image_bytes=$(( $image_kb * 1024 ))
extra_bytes=$(( $image_bytes - $data_bytes ))

echo "block_bytes: " $BS
echo "data_bytes:  " $data_bytes
echo "data_blocks: " $data_blocks
echo "image_kb:    " $image_kb

head -c $data_bytes /dev/urandom >test_00.tmp
cat test_00.tmp >test_01.tmp

echo cdrparity -b $BS -s "$image_kb"k -p test_01.tmp
./cdrparity -b $BS -s "$image_kb"k -p test_01.tmp

echo
if ! ./cdrverify test_01.tmp; then
    echo 'FAILED!'
    exit 1
fi

cat test_01.tmp >test_02.tmp
echo
if ! ./cdrrepair test_02.tmp || ! diff -q test_01.tmp test_02.tmp; then
    echo 'FAILED!'
    exit 1
fi

modify_byte() {
    dd if=$1 bs=1 skip=$2 count=1 status=none \
	|tr '\000-\377' '\100-\377\000-\077' \
	|dd of=$1 bs=1 seek=$2 conv=notrunc status=none
}

echo
cat test_01.tmp >test_02.tmp
modify_byte test_02.tmp 0
if ! ./cdrrepair test_02.tmp || ! diff -q test_01.tmp test_02.tmp; then
    echo 'FAILED!'
    exit 1
fi

echo
cat test_01.tmp >test_02.tmp
modify_byte test_02.tmp $(( $data_bytes / 2 ))
modify_byte test_02.tmp $data_bytes
if ! ./cdrrepair test_02.tmp || ! diff -q test_01.tmp test_02.tmp; then
    echo 'FAILED!'
    exit 1
fi

echo
cat test_01.tmp >test_02.tmp
modify_byte test_02.tmp $(( $data_bytes - 1 ))
modify_byte test_02.tmp $(( $image_bytes - 1 )) 
if ! ./cdrrepair test_02.tmp || ! diff -q test_01.tmp test_02.tmp; then
    echo 'FAILED!'
    exit 1
fi

echo
cat test_01.tmp >test_02.tmp
modify_byte test_02.tmp $(( $data_bytes + $extra_bytes / 2 ))
modify_byte test_02.tmp $data_bytes
truncate -s $(( $image_bytes - $BS )) test_02.tmp
if ! ./cdrrepair test_02.tmp || ! diff -q test_01.tmp test_02.tmp; then
    echo 'FAILED!'
    exit 1
fi

echo
cat test_01.tmp >test_02.tmp
truncate -s $(( $data_bytes + $extra_bytes / 2 )) test_02.tmp
if ! ./cdrrepair test_02.tmp || ! diff -q test_01.tmp test_02.tmp; then
    echo 'FAILED!'
    exit 1
fi

echo
echo unit tests passed
rm test_??.tmp
