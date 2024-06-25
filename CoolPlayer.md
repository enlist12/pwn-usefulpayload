# CVE-2009-1437

## 前情

**hexdump查看文件的16进制形式**

**vscode hex editor修改文件16进制**

**python脚本生成可能会出现16进制乱码**

**原理：程序读取文件，并且没有NX,ASRL等保护然后用strcpy将内容复制到返回地址上方，可以进行栈溢出**

**利用：由于是读取文件和strcpy，所以payload中不能含有\x00和\x0a。**

**由于找不到win11下合适的弹窗的shellcode,所以采取将返回地址覆盖为程序内的弹窗地址**

![image-20240607135010618](C:\Users\29987\AppData\Roaming\Typora\typora-user-images\image-20240607135010618.png)

![image-20240607135143223](C:\Users\29987\AppData\Roaming\Typora\typora-user-images\image-20240607135143223.png)

## 2.19

payload='\x41'*184+gadget



## 2.18

payload='\x41'*184+gadget



## 2.17

payload='\x41'*184+gadget



## 2.16

偏移为196

![image-20240607135435852](C:\Users\29987\AppData\Roaming\Typora\typora-user-images\image-20240607135435852.png)

栈溢出后程序会在call @_security_check崩溃

![image-20240607135537509](C:\Users\29987\AppData\Roaming\Typora\typora-user-images\image-20240607135537509.png)

进入程序，发现 cmp ecx,__security_cookie

很明显__security_cookie是程序自己生成的随机值

现在看看exc怎么来的

~~~
mov ecx,[esp+12Ch,var_4]
xor ecx,esp
~~~

此时 esp为0x19f288,[esp+12Ch,var_4]是0x193a0中的值

再网上看看，0x193a0中的值怎么来的

![image-20240607140030112](C:\Users\29987\AppData\Roaming\Typora\typora-user-images\image-20240607140030112.png)

这段将__security_cookie的值与esp异或，此时esp也是0x19f288,然后放入0x193a0中。

由于0x193a0正好在返回地址上方，达到canary的效果。

![image-20240607140158060](C:\Users\29987\AppData\Roaming\Typora\typora-user-images\image-20240607140158060.png)

用winchecksec检查，确实有canary。



## 2.15

![image-20240607140245869](C:\Users\29987\AppData\Roaming\Typora\typora-user-images\image-20240607140245869.png)

也有canary



## 2.14

偏移为192,payload='\x41'*192+gadget



## 2.14 && 2.19

两个版本偏移不同，2.19为184，2.14为192，着重比较执行strcpy的函数和返回的函数

2.19：sub_40C960    

执行流程：40C960-->0x40C97B  jmp 0x40C9E2-->0x40CA36

**使用diaphora**

![image-20240607152522228](C:\Users\29987\AppData\Roaming\Typora\typora-user-images\image-20240607152522228.png)



![image-20240607152539775](C:\Users\29987\AppData\Roaming\Typora\typora-user-images\image-20240607152539775.png)

定义的时候2.14的字符串就多给8个字节？？？
![image-20240607152808513](C:\Users\29987\AppData\Roaming\Typora\typora-user-images\image-20240607152808513.png)

在一开始布置栈空间的时候就相差了0x8

## 2.13

同上，偏移也是192

![image-20240607153018374](C:\Users\29987\AppData\Roaming\Typora\typora-user-images\image-20240607153018374.png)



## 2.12

同上，gadget也一样



## 2.11

无法运行



## 2.10

payload='\41'*188+gadget

![image-20240607160744179](C:\Users\29987\AppData\Roaming\Typora\typora-user-images\image-20240607160744179.png)

![image-20240607160906605](C:\Users\29987\AppData\Roaming\Typora\typora-user-images\image-20240607160906605.png)

与之前的相比，貌似没调用strcpy



## 2.09

同上

![image-20240607161612607](C:\Users\29987\AppData\Roaming\Typora\typora-user-images\image-20240607161612607.png)

## 2.08

同上

![image-20240607161918749](C:\Users\29987\AppData\Roaming\Typora\typora-user-images\image-20240607161918749.png)



## 2.07

同上

![image-20240607162214063](C:\Users\29987\AppData\Roaming\Typora\typora-user-images\image-20240607162214063.png)



## 2.06

同上

![image-20240607162508873](C:\Users\29987\AppData\Roaming\Typora\typora-user-images\image-20240607162508873.png)

## 2.05

同上

![image-20240607162801539](C:\Users\29987\AppData\Roaming\Typora\typora-user-images\image-20240607162801539.png)

## 2.04

同上

![image-20240607164017588](C:\Users\29987\AppData\Roaming\Typora\typora-user-images\image-20240607164017588.png)



## 2.03

exploit添加不上去，没有漏洞