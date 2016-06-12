#!/bin/bash

cat cdrrescue cdrparity cdrverify cdrrescue cdrparity cdrverify >test_00.tmp
low_size=$((2*`wc -c test_00.tmp |awk '{printf "%d",$1*1.2/2048}'`))
high_size=`wc -c test_00.tmp |awk '{printf "%d",$1*4/1024}'`

cat test_00.tmp >test_01.tmp
if [ $(( `wc -c <test_01.tmp` % 2048 )) -ne 0 ]; then
    head -c $(( 1024 - (`wc -c <test_01.tmp` % 1024) )) /dev/zero >>test_01.tmp
fi

echo
cat test_00.tmp >test_02.tmp
echo cdrparity -b 1k -s "$low_size"k -p test_02.tmp
./cdrparity-v1 -b 1k -s "$low_size"k -p test_02.tmp
echo
if ! ./cdrverify test_02.tmp; then
    echo 'FAILED!'
    exit
fi
echo
if ! ./cdrrescue test_02.tmp test_03.tmp; then
    echo 'FAILED!'
    exit
fi
if ! diff -q test_01.tmp test_03.tmp; then
    echo 'FAILED!'
    exit
fi

echo
cat test_00.tmp >test_04.tmp
echo cdrparity -b 1k -s "$high_size"k -p test_04.tmp
./cdrparity-v1 -b 1k -s "$high_size"k -p test_04.tmp
echo
if ! ./cdrverify test_04.tmp; then
    echo 'FAILED!'
    exit
fi
echo
if ! ./cdrrescue test_04.tmp test_05.tmp; then
    echo 'FAILED!'
    exit
fi
if ! diff -q test_01.tmp test_05.tmp; then
    echo 'FAILED!'
    exit
fi

echo
echo unit tests passed
rm test_??.tmp
