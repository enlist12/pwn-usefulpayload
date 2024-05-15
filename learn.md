### vtable

​	在目前 libc2.23 版本下，位于 libc 数据段的 vtable 是不可以进行写入的。不过，通过在可控的内存中伪造 vtable 的方法依然可以实现利用。

​	在2.24中，对vtable的地址也进行了检测，不能再进行劫持。

​	vtable的地址可在ida中查看，在data段的末尾。



### 高版本libc新增保护（libc 2.32+)

​	将tcachebin和fastbin的fd指针进行了处理，将本fd的地址右移12位(就是16进制末尾3位去除)，再与它应该指向的地址进行异或。

​	同时分配内存时进行了对齐检查，必须对0x10对齐，(glibc 2.34)移除了malloc_hook和free_hook。所以若要将堆块分配到要写的区域，需要泄露堆的基址。



### 64位下的参数分配

​	参数依次在rdi,rsi,rdx,rcx,r8,r9。之后的第一个参数会在rsp，接下来就是rsp+8.......以此类推

scanf也能像printf一样 %8$s,特定情况下能实现地址任意写。



### House of Orange

​	将top chunk链接到unsortedbin中， 这种操作的原理简单来说是当前堆的 top chunk 尺寸不足以满足申请分配的大小的时候，原来的 top chunk 会被释放并被置入 unsorted bin 中，通过这一点可以在没有 free 函数情况下获取到 unsorted bins。一般需要堆溢出漏洞来修改top chunk的size，且修改完的size要与内存页对齐（0x1000)。



### off-by-one 

​	溢出字节可以修改下一个堆块的大小，造成堆块重叠。

​	溢出字节只能是null字节，可以将下一个堆块的pre_inuse位改为0，进行unlink。

发生场景：

![image-20240417202921219](C:\Users\29987\AppData\Roaming\Typora\typora-user-images\image-20240417202921219.png)

![image-20240417202944464](C:\Users\29987\AppData\Roaming\Typora\typora-user-images\image-20240417202944464.png)



### overlap

​	当前chunk的大小是通过当前chunk的size位确定的，当前chunk是否inuse是通过下一个chunk的size最后一位确定的，下一个chunk的地址是当前chunk的地址加上size确定的，上一个chunk的地址是当前地址减去pre_size确定的。

​	可以通过修改chunk的size位，是它变大，free时会将下个chunk也free掉，然后在malloc，就能控制下一个chunk了。

​	通过 extend 可以实现 chunk overlapping，通过 overlapping 可以控制 chunk 的 fd/bk 指针从而可以实现 fastbin attack 等利用

**libc-2.28之后，unlink 开始检查按照 prev_size 找到的块的大小与prev_size 是否一致。 **

​	strcpy 在复制字符串时会拷贝结束符 '\x00'

​	循环写入时，循环次数设置错误导致多写入了一个字节；

​	劫持__malloc_hook或者__free_hook函数地址为one_gadget，最后printf打印大量字符调用malloc。



### house of storm

**glibc版本小于2.30,因为2.30之后加入了检查**

1.将unsorted_bin中的bk指针改为fake_chunk
2.largebin中的bk指针改为fake_chunk+8，bk_nextsize指针改为fake_chunk-0x18-5	,
（target为要修改的目标地址，fake_chunk为target-0x20）
 来满足victim->bk_nextsize->fd_nextsize = victim（即fake_chunk-0x18-5=victim）
3.再次malloc获得target地址处的chunk，可修改target地址处的值

~~~c
else 
    {
        // unsorted_bin->fd_nextsize = large_bin;
        victim->fd_nextsize = fwd;
        // unsorted_bin->bk_nextsize = stack2;
        victim->bk_nextsize = fwd->bk_nextsize;
        if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))
            malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");
        // stack2 = unsorted_bin;
        fwd->bk_nextsize = victim;
        // stack2->fd_nextsize = victim;
        victim->bk_nextsize->fd_nextsize = victim;
    }
    // bck=stack1;
    bck = fwd->bk;
    if (bck->fd != fwd)
        malloc_printerr ("malloc(): largebin double linked list corrupted (bk)");
    }
    ...
    mark_bin (av, victim_index);
    // unsorted_bin->bk = stack1;
    victim->bk = bck;
    // unsorted_bin->fd = large_bin;
    victim->fd = fwd;
    // stack2 = victim;
    fwd->bk = victim;
    // stack->fd = unsorted_bin;
    bck->fd = victim;

~~~

~~~c
1. victim 为 0
2. IS_MMAPPED 为 1
3. NON_MAIN_ARENA 为 0
~~~

多试几次，等size区域为0x55时就可以了，因为0x56后四位为0110,ismapped区域为1，会造成crash。



### mips

**MIPS体系结构中 寄存器大小为32位，字的大小为32位与寄存器相同。**

**所有MIPS指令都是32位长。**

**MIPS是按字节编址的，字的起始地址必是4的倍数。**

**MIPS采用大端编址。**

**大端编址和小端编址的字地址都是字的最低字节地址。**

用$a0~$a3传递函数的前4个参数，记忆方法，寄存器名字a实际为argument的缩写。多余的参数用栈传递。

j指令跳转到某个标签处，单纯的jmp

$ra寄存器，ra为，return address的缩写，一般用于存储返回地址，一个函数结尾往往会从栈里弹出一个值赋值给$ra寄存器，然后jr $ra。

sw register,addr指令，sw即store word的缩写（对应的有store byte）,将register寄存器里的值写入到addr地址处。

lw register,addr指令，lw即load word的缩写（对应的有load byte）,读取addr处的数据，放入register寄存器。

la指令，相当于x86的lea

la $a0,1($s0)指令，带有偏移的寻址，它的作用是$a0 = 1 + $s0

**$s0---$s7**(16~23) 存放变量的寄存器

**$t0---$t9** (8~15) 存放临时变量的寄存器

**$zero** 存放常数0的寄存器

$fp寄存器可以理解为x86下的ebp

li 指令用于将一个立即数（immediate value）加载到指定的寄存器中。 li $t0, 42



### fastbinsize检测

![在这里插入图片描述](https://img-blog.csdnimg.cn/988a4906f93447429ddc06563c576a85.png)

这是汇编层面的检测代码，r15就是chunk的起始地址。

但注意看，我们其实只是取了size的低8位，所以size的高八位其实不会影响我们的检测，

例如 0x73740060和0x00000060效果其实是一样的，这样有利于我们伪造chunk，躲过fastbin的size检测



### 汇编知识

在汇编语言中，`jmp $+0xe` 是一个跳转指令，其中 `jmp` 表示“跳转”，而 `$+0xe` 表示跳转的目标地址。这里的 `$` 通常代表当前指令的地址，`+0xe` 则表示从当前地址偏移 0xE（即十进制中的 14）个字节。

push和pop指令一般都只占用1字节，sycall指令占用2字节。

若遇到能写的shellcode长度不够，可以考虑重新调用read执行。



### exit_hook

函数调用exit或正常返回时，都会call exit。

p &_rtld_global._dl_rtld_lock_recursive。 gdb调试可以用这个命令打印exit_hook地址。

不过exit_hook貌似libc 2.31的一些小版本之后就取消了。





### setcontext





### vsyscall

关于vsyscall

vsyscall是第一种也是最古老的一种用于加快系统调用的机制，工作原理十分简单，许多硬件上的操作都会被包装成内核函数，然后提供一个接口，供用户层代码调用，这个接口就是我们常用的int 0x80和syscall+调用号。

当通过这个接口来调用时，由于需要进入到内核去处理，因此为了保证数据的完整性，需要在进入内核之前把寄存器的状态保存好，然后进入到内核状态运行内核函数，当内核函数执行完的时候会将返回结果放到相应的寄存器和内存中，然后再对寄存器进行恢复，转换到用户层模式。

这一过程需要消耗一定的性能，对于某些经常被调用的系统函数来说，肯定会造成很大的内存浪费，因此，系统把几个常用的内核调用从内核中映射到用户层空间中，从而引入了vsyscall。

因此vsycall地址是不变的，不受PIE影响，我们可以利用其对栈进行填充。

![image-20240429104924227](C:\Users\29987\AppData\Roaming\Typora\typora-user-images\image-20240429104924227.png)

![这就是那四个函数](https://img-blog.csdnimg.cn/29f50cc9e7324b74b3d651392fb2cef5.png)

这就是vsyscall中的4各个函数

这些函数不会对程序的执行流造成影响，所以可以利用retn构造滑梯。

如果直接设置rip执行0xffffffffff600007的syscall时发现提示段错误(got SIGSEGV signal (Segmentation violation))。显然，我们没办法直接利用vsyscall中的syscall指令。这是因为vsyscall执行时会进行检查，如果不是从函数开头执行的话就会出错。因此，我们唯一的选择就是利用0xffffffffff600000, 0xffffffffff600400, 0xffffffffff600800这三个地址。



### 零散知识点

* 通过阅读glibc2.29源码，我们得知calloc不会从tcache bin里取空闲的chunk，而是从fastbin里取，取完后，和malloc一样，如果fastbin里还有剩余的chunk，则全部放到对应的tcache bin里取，采用头插法。
* 当程序已经运行了一个alarm函数时 此时我们再次执行另一个alarm函数 就会返回第一个alarm函数所设定的时间已经经过的时间,返回值是保存在eax或rax中，例如，可以sleep(4)，然后触发alarm函数，就能将eax赋值为4，然后执行open函数





### stdout泄露基址

这是file结构

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210218173629561.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxMjAyMjM3,size_16,color_FFFFFF,t_70#pic_center)

进程中的FILE结构会通过`_chain域`彼此连接形成一个链表，链表头部用全局变量`_IO_list_all`表示，通过这个值可以遍历所有的FILE结构，大致的链表结构如下图：

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210218150610948.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxMjAyMjM3,size_16,color_FFFFFF,t_70)

在标准I/O库中，每个程序启动时有三个文件流是自动打开的：`stdin`、`stdout`、`stderr`。

**_IO_FILE_plus结构**

事实上`_IO_FILE`结构外包裹着另一种结构`_IO_FILE_plus`，其中包含了一个重要的指针`vtable`（虚表）指向了一系列函数指针：

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021021817403567.png)

所以在上述stdout等file底部紧接着vtable的地址

**puts函数的执行流**

_io_puts-> _io_sputn-> _io_new_file_xsputn-> _overflow-> _io_do_write

_io_do_write 会打印 _io_write_base 到 _io_write_ptr之间的值

这就是stdout泄露基址的原理

这能查看stdout的地址

~~~pyt
p &_IO_2_1_stdout_
~~~

![image-20240507135621501](C:\Users\29987\AppData\Roaming\Typora\typora-user-images\image-20240507135621501.png)

**为了满足一些绕过，设置flag为0xfbad1800**

在实践中，往往需要配合off-by-one进行overlap，将tcachebin的fd覆盖为unsortedbin，随后覆盖末尾字节使其指向stdout，然后将_io_write_base末尾覆盖b'\x00'，通过gdb调试，确定偏移。堆体menu函数一般会执行puts，就会触发。

由于内存页机制，所以stdout最后3位十六进制是不变的，可以gdb预先调试一下记下这三位。根据观察，stdout是在unsortedbin的下一个内存页，所以第四位需要爆破，应该多试几次就好了。



### 有疑惑的题

https://www.nssctf.cn/problem/832

[[MTCTF 2021\]Bookshop | NSSCTF](https://www.nssctf.cn/problem/1137)



### 输入

scanf和gets一样，在遇到换行符或空字符会停止输入，但会在字符串末尾自动补上空字符，会造成栈上的off-by-null。

例如scanf("%256s",s)，最后会补上空字符，所以其实输入了257个字符。



### environ

存储着程序运行的一些关键数据，存在于libc中，其中一些是栈上的地址，可以通过泄露这些，然后根据偏移得到栈上的任意地址，将堆分配上去，进行orw，libc.sym['environ']可以得到。

高版本可用，很方便，可替代io和tls_dtor_list



### tls_dtor_list

#### fs

这是段寄存器，用于保存线程中的一些数据。例如 fs:0x28,即fs中保存的地址加0x28保存着canary，fs:0x30保存着pointer guard，即一个随机数，用于函数的加密。

~~~
p $fs_base
tls
~~~



#### exit

~~~c
void
exit (int status)
{
  __run_exit_handlers (status, &__exit_funcs, true, true);
}
libc_hidden_def (exit)
~~~

exit函数其实是_run_exit_handlers函数的一个包装。

~~~c
void
attribute_hidden
__run_exit_handlers (int status, struct exit_function_list **listp,
             bool run_list_atexit, bool run_dtors)
{
  /* First, call the TLS destructors.  */
#ifndef SHARED
  if (&__call_tls_dtors != NULL) // 需要__call_tls_dtors 不为空
#endif
    if (run_dtors) // 需要run_dtors不为空
      __call_tls_dtors (); // 调用 __call_tls_dtors
 
  __libc_lock_lock (__exit_funcs_lock);
~~~

_run_exit_handlers内部会调用 _call_tls_dtors函数。

~~~c
void
__call_tls_dtors (void)
{
  while (tls_dtor_list)
    {
      struct dtor_list *cur = tls_dtor_list;
      dtor_func func = cur->func;
#ifdef PTR_DEMANGLE
      PTR_DEMANGLE (func);
#endif
 
      tls_dtor_list = tls_dtor_list->next;
      func (cur->obj);
 
      /* Ensure that the MAP dereference happens before
     l_tls_dtor_count decrement.  That way, we protect this access from a
     potential DSO unload in _dl_close_worker, which happens when
     l_tls_dtor_count is 0.  See CONCURRENCY NOTES for more detail.  */
      atomic_fetch_add_release (&cur->map->l_tls_dtor_count, -1);
      free (cur);
    }
}
~~~

然而这里需要注意的是 PTR_DEMANGLE (func) 会将func解密，正常情况解密过程是先将reg循环右移0x11位，然后再将reg与pointer_guard进行异或得到最终的结果。

所以这里加密的过程也就很清晰了，只需要将我们真实地址先与pointer_guard进行异或，然后再循环左移0x11位即可。这也就是为什么我们需要泄露pointer_guard(fs:0x30)的原因。

_call_tls_dtors内部会调用tls_dtor_list这个链表中成员的函数（cur->func)，参数是 (cur->obj)

~~~c
struct dtor_list
{
  dtor_func func; // 8字节
  void *obj;
  struct link_map *map;
  struct dtor_list *next;
};
~~~

这是链表上的成员，func是第一个，obj是第二个。

从而我们不难得出，如果我们劫持得了**tls_dtor_list**链表，就可以进入循环并控制**dtor_list**结构体**cur**，从而控制其成员变量**func**与**obj**，然后实现任意函数执行，并且第一个参数可控！

接下来，我们对着 **__call_tls_dtors**汇编调挑重点分析该如何利用

~~~
 0x00007ffff7c45d60 <+0>:     endbr64
   0x00007ffff7c45d64 <+4>:     push   rbp
   0x00007ffff7c45d65 <+5>:     push   rbx
   0x00007ffff7c45d66 <+6>:     sub    rsp,0x8
   0x00007ffff7c45d6a <+10>:    mov    rbx,QWORD PTR [rip+0x1d401f]        # 0x7ffff7e19d90
   0x00007ffff7c45d71 <+17>:    mov    rbp,QWORD PTR fs:[rbx]
   0x00007ffff7c45d75 <+21>:    test   rbp,rbp
   0x00007ffff7c45d78 <+24>:    je     0x7ffff7c45dbd <__call_tls_dtors+93>
   0x00007ffff7c45d7a <+26>:    nop    WORD PTR [rax+rax*1+0x0]
   0x00007ffff7c45d80 <+32>:    mov    rdx,QWORD PTR [rbp+0x18]
   0x00007ffff7c45d84 <+36>:    mov    rax,QWORD PTR [rbp+0x0]
   0x00007ffff7c45d88 <+40>:    ror    rax,0x11
   0x00007ffff7c45d8c <+44>:    xor    rax,QWORD PTR fs:0x30
   0x00007ffff7c45d95 <+53>:    mov    QWORD PTR fs:[rbx],rdx
   0x00007ffff7c45d99 <+57>:    mov    rdi,QWORD PTR [rbp+0x8]
   0x00007ffff7c45d9d <+61>:    call   rax
   0x00007ffff7c45d9f <+63>:    mov    rax,QWORD PTR [rbp+0x10]
   0x00007ffff7c45da3 <+67>:    lock sub QWORD PTR [rax+0x468],0x1
   0x00007ffff7c45dac <+76>:    mov    rdi,rbp
   0x00007ffff7c45daf <+79>:    call   0x7ffff7c28370 <free@plt>
   0x00007ffff7c45db4 <+84>:    mov    rbp,QWORD PTR fs:[rbx]
   0x00007ffff7c45db8 <+88>:    test   rbp,rbp
   0x00007ffff7c45dbb <+91>:    jne    0x7ffff7c45d80 <__call_tls_dtors+32>
   0x00007ffff7c45dbd <+93>:    add    rsp,0x8
   0x00007ffff7c45dc1 <+97>:    pop    rbx
   0x00007ffff7c45dc2 <+98>:    pop    rbp
   0x00007ffff7c45dc3 <+99>:    ret
~~~

- **__call_tls_dtors+10** 将**rbx**赋值为**0xffffffffffffffa8(-88)**
- **__call_tls_dtors+17** 将**fs-88(tls_dtor_list)** 赋值给**rbp**（这为我们的栈迁移提供了条件）
- **__call_tls_dtors+21** 其实就是在判断**tls_dtor_list**是否为空
- **call_tls_dtors+36 ** 将**tls_dtor_list**的第一个成员变量(偏移0，8 byte)赋值给**rax**
- **__call_tls_dtors+40**与 **__call_tls_dtors+44** 是对rax进行解密，先向右循环移位，再与**fs+0x30**上的值(一个随机数)进行异或
- **__call_tls_dtors+57** 将**tls_dtor_list**的第二个成员变量(偏移8，8 byte)赋值给**rdi**
- **__call_tls_dtors+61** 调用**rax**

对此，易得我们劫持**tls_dtor_list**触发 **system('/bin/sh')** 的利用思路：

- 构造一个**chunk** ，**[chunk_addr]为加密后的system**地址， **[chunk_addr+8]** 为 **'/bin/sh'** 字符串地址
- 泄露**libc**基地址，然后得到**fs**的基地址
- 然后将**fs-88(tls_dtor_list)赋值为该堆地址chunk_addr**
- 最后调用exit函数或者程序正常main函数返回结束，就可以执行**system('/bin/sh')** 来getshell

除此之外，如果题目开了沙箱**ban**掉**execve**，我们还可以栈迁移构造链

因为 **__call_tls_dtors+17**将**fs-88(tls_dtor_list)赋值给rbp** ，如果我们往 **[chunk_addr]** 里面填**leave_ret**的**gadget**，那么当执行**leave_ret**后，**rip**就会变成 **[chunk_addr+8]** ，从而执行我们在这后面构造的**ROP**链！！！

**所以我们可知tls_dotor_list的利用条件是**

* 能够泄露堆的基址
* 能够泄露libc的基址
* 能够泄露或修改fs+0x30
* 程序能正常从main函数退出或触发exit函数









​	