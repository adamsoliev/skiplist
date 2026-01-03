#!/bin/bash -eu

# OSS-Fuzz build script for minilsm skiplist
#
# This builds fuzzers using OSS-Fuzz environment variables:
# - $CXX: Compiler with fuzzing instrumentation
# - $CXXFLAGS: Compiler flags with sanitizer options
# - $LIB_FUZZING_ENGINE: Fuzzing engine library
# - $OUT: Output directory for fuzzers
# - $SRC: Source directory

cd $SRC/minilsm

# Build each fuzzer
cd fuzz
for fuzzer in skiplist_fuzzer arena_fuzzer iterator_fuzzer; do
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
        -std=c++17 \
        -I../src \
        ${fuzzer}.cc \
        -o $OUT/${fuzzer}

    # Copy seed corpus if exists
    if [ -d "corpus/${fuzzer}" ] && [ "$(ls -A corpus/${fuzzer})" ]; then
        zip -j $OUT/${fuzzer}_seed_corpus.zip corpus/${fuzzer}/*
    fi

    # Copy dictionary if exists
    if [ -f "dictionaries/skiplist.dict" ]; then
        cp dictionaries/skiplist.dict $OUT/${fuzzer}.dict
    fi
done
