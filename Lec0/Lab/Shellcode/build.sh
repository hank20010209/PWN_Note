#!/bin/bash

if [[ "$1" == "clean" ]]; then
    rm hello.o hello
    echo "Removed hello.o and hello"
    exit 0
fi

nasm -felf32 hello.s -o hello.o
echo "Generated hello object file"

ld hello.o -melf_i386 -o hello
echo "Generated hello execute file"
