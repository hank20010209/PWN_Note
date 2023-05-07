#!/bin/bash

if [[ "$1" == "clean" ]]; then
    rm hello_shellcode
    echo "Removed hello_shellcode"
    exit 0
fi

objcopy -O binary hello shellcode.bin

echo "generate hello shellcode in hello_shellcode"
xxd -i shellcode.bin > hello_shellcode

rm shellcode.bin
