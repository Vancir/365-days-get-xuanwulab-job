# Week 2

## Day8: Linux内核及其内在机理

> 传送门: [linux-insides](https://github.com/0xAX/linux-insides)

- [x] 从引导加载内核:
    1. 按下电源开关主板供电备妥后, CPU会`复位寄存器的所有数据, 并设置每个寄存器的预定值`. CPU复位后, 寄存器的预设数据如下: `IP=0xfff0, CS=0xffff`. `实模式`下内存寻址时通过段寄存器偏移(实模式CPU只能用16位寄存器)得到, 也即`CS:IP=(0xffff)<<4+0xfff0=0xfffffff0`. 而实模式下CPU是无法访问`0xfffffff0`这个地址的, 所以`0xfffffff0`被映射到了ROM而非RAM. 
    2. `0xfffffff0`是`4GB-16B`, 也就是`复位向量`所在位置, 也就是CPU在重置后期望执行的内存地址入口. 通常为一个`jump指令`, 用于跳往`BIOS入口`
    3. BIOS在初始化和检查硬件后, 需要找到一个`可引导设备`. BIOS会根据BIOS配置里的可引导设备列表顺序, 依次尝试寻找引导程序, 对硬盘而言就会去`MBR分区`, 该分区存储在磁盘第一个扇区(512字节)的头446字节, 引导扇区的最后必须为`0x55`和`0xaa`(这是引导程序的magic标识). 
    4. `MBR`分区代码只能占用一个扇区, 因此非常简单, 只做了一些初始化, 然后就跳转到`GRUB2`的`core image`去继续执行. `core image`的初始化代码会把整个`core image`(包括GRUB2的内核代码和文件系统驱动)引导到内存中. 引导完成后, 调用`grub_main`
    5. `grub_main`初始化控制台, 计算模块基地址, 设置root设备, 读取grub配置文件, 加载模块. 最后将grub置于`normal`模式, 调用`grub_nomal_execute`完成最后的准备工作, 然后显示菜单列出所有可用的操作系统. 
    6. 选择操作系统之后, 执行`grub_menu_execute_entry`, 它会调用grub的`boot`命令, 来引导选择的系统.
    7. 引导会根据`kernel boot protocol`的描述, 填充`kernel setup header`里的字段, 将内核引导入内存后, 交由Kernel继续执行. Kernel的代码从`0x1000 + X + sizeof(KernelBootSector) + 1`开始执行(`X`是kernel bootsector被载入内存的基址)
- [x] 内核引导和设置
    1. 首先需要正确设置内核, 内核设置代码的运行起点为`arch/x86/boot/header.S`的`_start`函数. 在`_start`之前还有一些kernel自带的bootloader代码, 主要是兼容`UEFI`. 
    2. `_start`第一句就是`jmp`语句, 跳转到其后的相对地址(`start_of_setup-1f`), 也就是`_start`后第一个标号为`1`的代码, 该部分包含了剩下的`setup header`结构. 而`1`之后就是`start_of_setup`的代码, 该部分开始会完成`段寄存器设置`, `堆栈设置`, `bss段设置`, `跳转到main.c开始执行代码`的工作
    3. `段寄存器设置`: 将`ds`和`es`寄存器的内容设置为一样, 通过利用`lretw`将`ds`寄存器的值放入`cs`寄存器
    4. `堆栈设置`: 检查`ss`寄存器的内容, 如果内容不对则进行更正
    5. `设置BSS段`: 检查`magic`签名`setup_sig`, 如果签名不对直接跳转到`setup_bad`执行相应代码. 如果签名正确, 就设置好`BSS`段将其全部清零. 
    6. `跳转到main函数`: `calll main`. main()定义在`arch/x86/boot/main.c`
- [x] 保护模式
    * 保护模式相比实模式, 有32位地址线能访问`4GB`的地址空间并且引入了内存分页的功能. 
    * 保护模式提供了2中完全不同的内存管理机制: `段式内存管理`和`内存分页`. 
    * 实模式下物理地址由`内存段的基地址`和`基地址开始的偏移`组成, 也即`segement << 4 + offset`. 但在保护模式下, 每个内存段不再是64K大小, 段的大小和起始位置通过`段描述符`描述, 所有内存段的段描述符存储在`全局描述符表(GDT)`结构里. 
    * `全局描述符表(GDT)`在内存位置并不固定, 它的地址保存在特殊寄存器`GDTR`里. 使用指令`lgdt gdt`将`GDT`的基地址和大小保存到`GDTR`寄存器中. `GDTR`是一个`48`位寄存器, 该寄存器保存2部分内容: `GDT的大小16位`和`GDT的基址32位`. 
    * 而保护模式下, 段寄存器保存的`不再是内存段的基地址`而是称为`段选择子`的结构. `段选择子`对应了相应的`段描述符`. 段选择子是一个16位的数据结构, 包含了对应`段描述符的索引号`, `选择是在GDT还是LDT查找段描述符`, 和`请求优先级`. 
    * 保护模式下, CPU通过以下步骤找到寻址:
        1. 将相应`段选择子`载入段寄存器
        2. 根据`段选择子`从`GDT`中找到匹配的`段描述符`, 然后将段描述符放入段寄存器的隐藏部分. 
        3. 在没有向下扩展段的时候, 内存段的基地址, 就是段描述符中的基地址. 
    * 代码从实模式切换到保护模式的步骤:
        1. 禁止中断发生
        2. `lgdt gdt`
        3. 设置CR0寄存器的PE位为1, 使CPU进入保护模式
        4. 跳转执行保护模式代码.
- [x] main函数操作:
    1. 将启动参数拷贝到`zeropage`: 调用`copy_boot_params(void)`, 该函数将`内核设置信息`拷贝到`boot_params`结构的相应字段. 
    2. 控制台初始化: 调用`console_init`. 
       1. 该函数先查看命令行参数是否包含`earlyprintk`选项. 
       2. 如果包含, 函数将分析这个选项的内容, 得到控制台将使用的`串口信息`并进行`串口初始化`. 
       3. 串口初始化成功后, 如果命令行参数带有`debug`选项, 可以看到一行输出`early console in setup code`
    3. 堆初始化: 内核需要初始化全局堆, 通过`init_heap`实现
       1. 首先检查`内核设置头`的`loadflags`是否设置`CAN_USE_HEAP`标志. 如果设置了该标志, 代码会计算`栈的结束地址`和`堆的结束地址`
       2. 栈的结束地址计算: `stack_end = esp - STACK_SIZE`
       3. 堆的结束地址: `heap_end = head_end_ptr + 0x200`
       4. 判断`heap_end`是否大于`stack_end`. 如果大于, 那么就把`stack_end`设置为`heap_end`(栈和堆的生长方向相反, 这里设置让堆和栈相邻, 增大了栈的底部空间, 不影响栈逆向生长)
       5. 这样就完成了全局堆的初始化, 全局堆初始化之后, 就可以使用`GET_HEAP`方法了.
    4. 检查CPU类型: 调用`validate_cpu`检查CPU是否可用. `validate_cpu`会调用`check_cpu`得到当前系统的`cpu_level`并和系统要求的最低`cpu_level`比较, 如果不满足就不允许系统运行. 
    5. 内存分布侦测: 调用`detect_memory`进行内存侦测, 得到系统当前内存的使用分布. 以下是`detect_memory_e820`(该方法的多种接口之一, 用于获取全部内存分配)原理:
       1. 调用`initregs`方法初始化`biosregs`数据结构, 然后向该数据结构填入`e820`接口所要求的参数. 
       2. 通过循环收集内存信息. 循环结束后整个内存分配信息被写入到`e820entry`数组, 数组元素包含三个信息: `内存段起始地址`, `内存段大小`, `内存段类型`. 可以使用`dmesg`查看到这个数组的内容
    6. 键盘初始化: 调用`keyboard_init()`方法进行键盘初始化. 首先调用`initregs`初始化寄存器结构, 然后调用`0x16`中断获取键盘状态, 获取状态后再次调用`0x16`中断来设置键盘的按键检测频率. 
    7. 系统参数查询: 内核进行一系列的参数查询, 依次是:
       1. `query_mac`调用`0x15`中断来获取机器的型号, bios版本和其他硬件相关信息. 
       2. `query_ist`获取`Intel SpeedStep`信息, 首先检查CPU类型, 然后用`0x15`中断获取该信息并填入`boot_params`中
       3. `query_apm_bios`从BIOS获取电源管理信息. 
       4. `query_edd`从BIOS查询硬盘信息. 

## Day9: Android安全里的攻防和分析知识

> Android安全部分参考[《Android安全攻防实战》](https://book.douban.com/subject/26437165/)

- [x] APK结构:
  * 证书签名
    * 证书文件在APK解压后的`META-INF`文件夹内.
      * `CERT.RSA`是公钥证书的自签名. 
        * 使用`keytool`进行检查: `keytool -printcert -file CERT.RSA`, 其中有声明`公钥的持有者`.
        * 使用`openssl`进行检查: `openssl pcks7– inform DER –in META- INF/ CERT. RSA –noout –print_ certs –text` 
        它指定了以下5个信息
        * `Owner`: 公钥持有者, 包含与该个体相关的国家组织信息
        * `Issuer`: 声明该证书的颁发机构. 
        * `Serial number`: 证书的标识符
        * `Valid from...until`: 指定证书有效期, 其关联属性可以由颁发者验证
        * `Certificate fingerprints`: 记录证书的数字校验和, 用来验证证书是否经过村阿盖
      * `CERT.SF`包含了APK中各个资源文件的SHA-1哈希. 使用`jarsigner`验证apk内容时就会比对该文件. 
      * `MANIFEST.MF`: 声明资源文件
    * 如何对App签名?
      1. 创建`keystore`, 用于存放签名app所使用的私钥: `keytool –genkey –v -keystore [keystore名称] –alias [私钥别名] –keyalg RSA –keysize 2048 –validity [有效天数]`
      2. 使用`keystore`通过`jarsigner`对app签名: `jarsigner –verbose –sigalg MD5withRSA –digestalg SHA1 –keystore [keystore文件] [你的.apk文件] [私钥别名]`
    * 如何验证app签名? `jarsigner –verify –verbose [apk文件]`
  * `AndroidManifest.xml`: 声明app的权限和组件信息
    * 如何提取`AndroidManifest.xml`? `apktool d -f -s [apk文件] [解压目录]`
  * adb命令:
    * `adb logcat`: 显示调试日志
    * `adb shell pm list packages`: 列出设备中所有package
    * `am start [Activity名]`: 启动指定activity.
      * 对于intent可以使用`-e key value`传递字符串键值
      * 对于service可以使用`am startservice`启动
- [x] APP中的漏洞:
  * logcat信息泄露: logcat里泄露了一些网址信息(http(s))或者cookie信息
  * 检查网络流量:
    1. 在设备上使用`tcpdump`和`nc`捕获流量: `tcpdump -w - | nc -l -p 31337`
    2. 使用adb命令将设备的流量转发到本地端口: `adb forward tcp:12345 tcp:31337`
    3. 本地`nc`连接转发端口: `nc 127.0.0.1 12345`
    4. `wireshark`连接管道获取流量: `nc 127.0.0.1 12345 | wireshark -k -S -i -`
  * 通过`am`被动嗅探`intent`: TODO 需要使用`drozer`
  * 攻击service: 
    1. 搜索哪些service是exported
    2. 尝试运行这些service. 运行的同时使用`logcat`来查看它是否会在运行时泄露一些敏感信息
    3. 如果想通过intent向service发送数据, 你需要去了解它的`intent filter`. 
    4. 某些service可能作为原生库的接口, 将intent接受的数据转换成类似基于堆/栈的数据结构, 这可能会造成内存溢出漏洞
  * 攻击broadcast receiver:
    * 发掘receiver的漏洞需要确定`输入是否可信`以及该`输入的破坏性如何`. 
    * 需要阅读源码, 弄清楚receiver的`intent filter`
- [x] 保护APP:
  * 保护APP组件: 正确使用`AndroidManifest.xml`以及在代码级别上强制进行权限检查
    * 尽量减少`android:exported`属性的使用, 尽可能地减少暴露的组件
    * android 4.2之前, 或者sdk版本17以下, 定义的`intent-filter`元素默认是导出的.
  * 定制权限: 指定组件的`android:permission`和定义`permission-group`
  * 保护`provider`组件:
    * 设置权限`android:permission`
    * 设置读相关权限(query): `android:writePermission`
    * 设置写相关权限: `android:readPermission`
    * 使用`path-permission`元素为单独的路径(比如`/[path]`)设置不同的权限, `path`的权限设置优先级更高
  * 防御SQL注入: 确保攻击者不能注入恶意构造的SQL语句
    * 避免使用`SQLiteDatabase.rawQuery()`, 而是改用一个参数化的语句(参数化的意思就是指定一个语句的格式, 并非指定参数, 而是描述性的表达语句, 可以类比为格式化字符串, 比如`insert into TABLE_NAME (content, link, title) values (?,?,?)`). 
    * 使用一个预先编译好的语句, 比如`SQLiteStatement`, 提供对参数的绑定(binding)和转义(escaping). 
    * 使用`SQLiteDatabase`提供的`query`, `insert`, `update`和`delete`方法. 
  * 验证app的签名: 根据事先计算好的签名哈希, 在代码运行时进行比对来判断文件是否被篡改
  * 反逆向工程方式: 
    * 检测安装程序: 比如检查安装程序是否为谷歌商店
    * 检查是否出于模拟器中: 获取相应的系统特征字符串进行判断
    * 检查app的调试标志是否启用: 启用调试标志意味着app可能连上了adb进行调试
    * 利用JAVA的反射API能在运行时检查类, 方法及成员变量, 这使得能够绕过访问控制修饰符(`access modifier`)的限制, 调用正常情况下无法使用的东西. 
  * 使用`ProGuard`: `ProGuard`是Android SDK自带的开源java代码混淆器.
    * `ProGuard`会把程序执行时不需要的信息都删除掉, 比如代码中不使用的方法, 域, 属性和调试信息
    * 它会把一些代码优化成更短更难以阅读的混淆代码
  * 使用`DexGuard`进行高级代码混淆
    * 相比`ProGuard`不仅能混淆Java代码, 还能保护资源文件和Dalvik字节码
    * API隐藏: 使用`API反射机制`隐藏对敏感API和代码的调用
    * 字符串加密: 对源代码的字符串进行加密
    * 反射调用会把类名和方法名包存为字符串, 而字符串加密可以结合起来将这些反射字符串加密起来. 
- [x] 逆向app
  * java源码编译成dex:
    1. `javac -source 1.6 -target 1.6 example.java`
    2. `dx --dex --output=example.dex example.class`
  * dex文件格式: 可以使用`dexdump example.dex`进行解析
    * magic(8bytes): `dex\n035`
    * checksum(4B): 表示dex文件的`Adler32`校验和, 用于验证dex文件头是否被篡改. 
    * SHA签名(20B)
    * fileSize(4B): 表示整个dex文件的长度
    * headerSize(4B): 表示整个DexHeader结构的长度, 单位为byte
    * endianTag(4B): 存放的是固定值, 在所有dex文件中都意义. 为`0x12345678`, 根据这个值在内存的排列顺序来判断是大端序还是小端序.
    * linkSize和linkOff: 多个.class被编译到一个dex时会哟感到
    * mapOff
    * stringIdsSize: 存放StringIds区段大小. 
    * stringIdsOff: 存放stringIds区段的实际偏移, 帮助Dalvik编译器和虚拟机直接跳转到该区段而不用计算偏移. 
    * StringIds区段实际上保存的是各个字符串的地址
    * TypeIds区段则是存放了各个类型描述符在stringIds列表的索引号. 
    * ProtoIds区段存放一系列用来描述方法的prototype id, 其中含有关于各个方法的返回类型和参数信息
    * FieldIds区段由一些stringIds和typeIds区段中数据的索引号组成, 用于描述类中各个成员
    * MethodIds区段用于描述方法, ClassDefs区段用于描述类
    * 除开用`dexdump`对dex解析, 还可以使用`dx`, 不过你得有相应的class文件: `dx -dex -verbose-dump -dump-to=[output].txt [input].class`
  * 反汇编/反编译/gdb调试操作:
    * 将dex反汇编得到smali代码: `baksmali example.dex`
    * 将dex反编译得到.class文件: `dex2jar example.dex`
    * 将.class反编译得到java代码: 使用jd-gui
    * 反汇编native so文件: 使用android ndk的toolchain提供的arm版本objdump. `arm-linux-androideabi-objdump -D [native library].so`
    * gdb调试正在运行的android进程:
      * `mount`会输出每个块设备都是怎么mount的一些信息
      1. `mount -o rw,remount [device] /system`
      2. `adb push [NDK-path]/prebuilt/android-arm/gdbserver/gdbserver /system/bin`
      3. 使用`ps`确定要调试的进程PID, 使用gdbserver进行attach: `gdbserver :[tcp-port] --attach [PID]`
      4. 转发android设备的TCP端口: `adb forward tcp:[remote_port] tcp:[local_port]`
      5. 本地运行交叉编译好的`arm-linux-androideabi-gdb`然后输入`target remote :[local_port]`来连接端口
- [x] SSL安全:  验证SSL签名证书: 利用OpenSSL
  1. 对于网络上的自签名证书, 使用`openssl s_client -showcerts -connect server.domain:443 < /dev/null`显示该证书的详细信息, `BEGIN CERTIFICATE`到`END CERTIFICATE`部分为证书内容, 将其保存为`mycert.crt`
    * 使用openssl创建自签名证书: `openssl genrsa -out my_private_key.pem 2048`生成.pem的私钥文件, 然后用该私钥生成证书: `openssl req -new -x509 -key my_private_key.pem -out mycert.crt -days 365`
  2. 得到`mycert.crt`后, 我们要将证书打包到app中, 就需要创建证书并将其导入到`.keystore`文件中, 该文件会被视为`truststore`.
  3. 使用`Bouncy Castle`库创建并导入证书到truststore:
    1. 设置`CLASSPATH`环境变量: `$ export CLASSPATH=libs/bcprov-jdk15on-149.jar`
    2. 使用`keytool`创建并导入公钥证书
        ``` bash
        $ keytool -import -v -trustcacerts -alias 0 / 
          -file < ( openssl x509 -in mycert.crt) / 
          -keystore customtruststore.bks / 
          -storetype BKS / 
          -providerclassorg.bouncycastle.jce.provider.BouncyCastleProvider /
          -providerpath libs/bcprov-jdk15on-149.jar \
          -storepass androidcookbook
        ```
    3. 输出文件是添加了公钥证书的`customtruststore.bks`(bks为Bouncy Castle Keystore). 保护口令为`androidcockbook`
    4. 复制`customtruststore.bks`到app的raw文件夹去. 
    5. 在app代码里从raw文件夹中加载本地truststore到一个KeyStore对象里去. ? 书里将保护口令硬编码了出来, 但是该口令只是用于验证truststore的完整性, 不是用来保护其安全性. 而且truststore是服务器的公钥证书
- [x] Android原生代码的漏洞分析
  * 检查文件权限: 寻找权限设置不正确或存在问题的文件
    * 列出"所有用户均可读取的文件": `find [path-to-search] -perm 0444 -exec ls -al {} \;`
    * 列出"所有用户均可写的文件": `find [path-to-search] -perm 0222 -exec ls -al {} \;`
    * 列出"所有用户均可执行的文件": `find [path-to-search] -perm 0111 -exec ls -al {} \;`
    * 列出"setuid位设为1的可执行文件": `find [path-to-search] -perm -4111 -exec ls -al {} \;`
    * 列出所有属于"root"用户的文件: `find [path-to-search] -user 0 -exec ls -al {} \`
  * 交叉编译原生可执行程序: 创建Android.mk文件和JNI文件夹, 利用NDK提供的`ndk-build`进行编译.
  * 条件竞争漏洞. 攻击者利用条件竞争漏洞需要满足以下条件:
    1. 能访问和恶意修改存在漏洞的进程所要竞争访问的资源: 如果攻击者无法访问到竞争的资源, 那么是不能引发漏洞的. 当有访问能力时, 进程内所有不适用互斥的独占式访问就都可以利用, 而且进程不检查信号量或自旋锁就直接使用某个指针指向数据的情况发生的非常频繁
    2. 使用时间/检查时间(TOU/TOC)的窗口大小: 本质上是应用程序请求访问一个资源和实际访问到该资源之间的时间差. 竞争条件漏洞利用非常依赖于该时间差, 因为利用的本质就是在这个时间差内竞争到资源的访问权, 以恶意地影响资源.
  * fuzzing: 使用`Radamsa`进行模糊测试 

## Day10: 阅读软件供应链安全相关论文

- [x] [软件供应链安全综述](http://jcs.iie.ac.cn/xxaqxb/ch/reader/view_abstract.aspx?file_no=20200106&flag=1) 
  - [x] 软件供应链的定义: 
    * 商品与服务: 软件
    * 供应者: 软件供应商
    * 消费者: 软件用户
    * 资源: 软件设计开发各阶段编入软件的代码,模块和服务
    * 加工: 编码过程, 工具和设备
    * 渠道: 软件官网和第三方平台 
  - [x] 软件供应链安全的定义: 软件设计开发过程中本身的`编码过程/工具/设备`以及供应链上游的`代码/模块/服务的安全`, 以及`软件交付渠道安全`的总和. 
  - [x] 软件供应链安全发展历程:
    1. 1984年, `K. Thompson`提出`KTH`攻击, 在难以发现的情况下修改编译器并设置后面, 污染所有通过此编译器编译并发布的软件. 
    2. 2004年, 微软提出`SDL安全开发生命周期`流程, 将软件开发划分为多个阶段并在每个阶段引入相应安全措施, 保障软件开发安全并建立漏洞发现和处理框架机制. 
    3. 2010年, `R.J. Ellison`和`C. Woody`提出`软件供应链风险管理`的概念, 介绍了相关分享的来源,总类,分享分析的方法, 威胁模型, 并讨论了应对风险的措施. 
    4. 2015年`XcodeGhost`开发工具污染事件. 攻击者注入病毒污染了非官方渠道发布的Xcode, 使得编译出的app会将运行过程中收集到的敏感信息发送到攻击者服务器. 
    5. 2017年6月`NotPetya`勒索病毒事件. 攻击者通过劫持软件的`升级更新渠道`, 使得用户更新软件时下载并感染了`NotPetya`勒索病毒.
    6. 2017年`CCleaner`恶意代码植入事件. 攻击者入侵公司开发环境, 篡改了编码过程中使用的`CRT函数库`并置入后门代码. 同年7月`Xshell`也以类似手段植入恶意代码.
    7. 2017年8月`WireX` Android僵尸网络事件. 攻击者将病毒与普通安卓app捆绑和伪装, 避过了Google Play对app的检测, 用户下载后感染为僵尸主机. 
  - [x] 供应安全的三个环节四个攻击:
    * 三个环节: 开发环节, 交付环节, 使用环节. (还可以增加一个运营环节)
    * 四个攻击: `开发环节的开发工具攻击`, `开发环节的源代码攻击`, `交付环节的分发渠道攻击`和`使用环节的升级补丁攻击`
  - [x] 软件供应安全研究技术:
    1. 软件漏洞挖掘和分析手段
      * 基于源代码: 使用静态分析方法对源代码进行脆弱性检测
      * 基于模糊测试: 使用黑盒测试手段, 动态挖掘漏洞
      * 基于代码特征: 根据已发现的漏洞提取漏洞特征然后检测目标是否含有该特征.
      * 软件漏洞位置匹配: 确定软件存在漏洞后需要方法匹配识别定位漏洞. 
      * 上游模块漏洞分析: `测量依赖关系/代码复用关系`, 结合`知识流网络/知识图谱`, 对软件模块进行分析. 
    2. 恶意软件及模块的识别和清除手段
      * 恶意特征提取: 基于`统计分析`以及`机器学习`方法对恶意代码静态分析. 
      * 模块恶意篡改: `注入恶意代码`和`重打包/捆绑`是污染供应链的主要方式
      * 比较篡改: 基于`图比较算法`分析相似二进制文件间的差异
    3. 网络劫持的检测和防御手段: 劫持或篡改软件的`交付/维护`渠道: 目前软件的交付和使用阶段高度依赖于网络环节, 因此网络劫持是污染供应链的关键技术. 
    4. 用户端软件安全机制
- [x] [Constructing Supply Chains in Open Source Software](https://dl.acm.org/doi/pdf/10.1145/3183440.3183454)
  * 论文对开源软件设计了三种类型的网络图
    * 用于检查`软件包/库`的`依赖`网络图
    * 用于检查`commit/文件/代码片段`的`代码复用`网络图
    * 用于检查复杂软件的`知识流`网络
  * 构建网络遇到的问题:
    * 共同问题: 
      1. 不同平台的数据格式是`异构`的
      2. 同一平台可能需要支持多种版本控制系统, 比如Github也支持SVN
      3. 公开数据可能并不完整或者说是过时的. 
    * 单独问题:
      1. 依赖网络: 建立依赖关系的分类存在困难
      2. 代码复用网络: 代码复用的检测存在困难
      3. 知识流网络: 确定知识流的属性存在困难
         1. 如何设置流的权重?
         2. 如何确定流的方向?
         3. 作者提出了一个公式来解决该问题
  * 如何构建网络?
    * 依赖网络: 分析语言的`import`和`depend`
    * 知识流网络: 未说明
    * 代码复用网络: 分析git里的`blob`
- [x] [Detecting repackaged smartphone applications in third-party android marketplaces]
  - [x] 重打包apk的两个共同特征
    1. 原始APK与重打包APK之间的代码库存在相似性
    2. 由于开发者签名密钥没有泄露, 因此原始APK和重打包APK必须使用不同的开发者密钥进行签名
  - [x] 特征提取: 
    * 提取`class.dex`里的字节码, 保留字节码指令中的`操作码`. 同时出于实践考虑, 大部分的重打包都是捆绑广告, 因此作者对常用广告SDK库做了白名单将其筛去. 
    * 使用`META-INF`目录获取开发者签名证书, 其中包括有开发者名称, 联系方式, 组织信息和公钥指纹等. 
  - [x] 生成指纹: 使用序列通过模糊哈希算出指纹, 然后通过指纹的距离来判断序列的相似性. 模糊哈希的另一个好处就是能通过哈希更改的地方来确定相应代码的改动区域
  - [x] 相似度评估: 计算两个指纹的编辑距离(参考`spamsum`算法). 但距离超出阈值则认为不相似. 
  * 一个笑点: 作者在实验过程中发现了QQ的一个版本要求了更多的权限, 但是权限的滥用是不足以证明这个apk就是重打包(植入代码)的恶意程序. 我想这里其实也有可能是因为作者从Google Play商店下载了QQ认定为良性, 从国内的平台下载了QQ发现滥用权限. 但通常QQ在国内就是滥用权限,而在国外为了通过Play商店审核而避免了权限滥用, 所以造成了论文中的乌龙现象. 当然后续的分析表明, 它应该确实是一个植入恶意代码的apk, 会跟c2服务器通信.

## Day11: 阅读软件供应链安全相关论文

- [x] [Towards Measuring and Mitigating Social Engineering Software Download Attacks](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_nelms.pdf)
  * 社工攻击主要分为两类, 一类是重打包良性软件(捆绑软件或其他潜在恶意程序), 一类是警告用户正在使用的`Adobe Flash`或`Java`以及过时或不安全, 而要求用户下载伪造的更新. 
- [x] [软件供应链污染机理与防御研究](http://gb.oversea.cnki.net/KCMS/detail/detail.aspx?filename=1018097481.nh&dbcode=CMFD&dbname=CMFDREF)
  * 污染技术研究
    * 开发环境污染
      1. 源代码污染: 以CCleaner为例, 攻击者入侵公司服务器, 在开发环境里的CRT静态库函数内植入了恶意代码. 并且植入的代码并非开发人员编写的源代码, 因此难以被发现
      2. 开发工具污染: 以XCode为例, 从非官方渠道下发植入恶意代码的Xcode工具.
      3. 第三方开发包污染: 以pypi为例, 主要是通过名称的相似来迷惑受害者. 
    * 软件捆绑污染
      * 众多未授权的第三方下载站点, 云服务, 共享资源, 破解版软件等共同组成了灰色软件供应链. 而通过灰色软件供应链获取的软件极易被攻击者植入恶意代码. 
      * 而一些正规下载站也会因审核不严格而被攻击者上传恶意软件
      * Android的应用通过二次打包生成篡改后的app, 并且用户容易将罪名怪罪给app的开发者. 
    * 网络劫持污染
      * 软件下载时劫持污染: 用户到软件下载服务器之间形成一条数据链路, 攻击者通过中间人的方式进行攻击, 影响传输的数据, 进而对用户下载的软件造成污染
      * 软件升级时劫持污染: 攻击者在中间网络中, 通过URL劫持的放啊, 对多款软件升级时的下载URL进行劫持, 跳转到攻击者的服务器上, 进而导致下载了恶意如那件.
    * 运行环境污染
      * 污染软件运行环境, 比如python, java, php
- [x] [程序逆向分析在软件供应链污染检测中的应用研究综述](http://www.cnki.com.cn/Article/CJFDTotal-JSJY202001018.htm)
  * 程序逆向分析
    * 传统恶意代码分析技术使用的特征主要分为`语法特征`和`语义特征`两大类. 
      * 语法特征需要通过解析程序的二进制指令, 并转换成高级语言(反汇编, 反编译)
      * 语义特征包括`API调用`和`执行过程中系统状态改变情况`
    * 动态分析的瓶颈在于覆盖率邮箱, 很容易受到干扰. 对此提出了`路径探索`和`透明分析`技术
      * 路径探索时应用最广泛的提高动态分析覆盖率的方法. 该技术通过求解不同路径约束的程序输入, 引导程序控制流向更高覆盖率方向转移
      * 透明分析着力于构建被分析样本无法感知的分析系统, 防止被分析程序因为检测到分析环境而不再执行恶意行为. 
  * 供应链安全中的挑战:
    * 程序分析需要能处理多样化的软件发布形式, 并从这个提取相应的城固县进行分析
    * 分析系统需要能自动执行或解压安装包, 成功释放程序可执行文件, 并监控整个安装和程序执行过程. 
    * 输入形式的多样化, 比如配置文件, UI交互, 网络通信, 与操作系统交互等. 这些致使动态分析方法很难自动发现并提供有效输入. 而且异步处理时常用的编程技术, 尚未有静态分析方法能理解各种异步编程模型并准确还原程序逻辑或控制流转移关系
    * 现有工作多出于语法分析层面, 少有工作能自动准确理解程序语义. 

## Day12: 学习知识图谱知识, 掌握ES和Neo4j的使用

- [x] ElasticSearch
  * ES里可以将`index`理解为数据库(`index`的名称必须小写), `index`里的单条记录称为`Document`, `Document`可以分组(`Type`), 分组实际上是一种过滤的手段. 
  * 使用`elasticsearch`和`elasticsearch_dsl`进行操作
- [x] 知识图谱
  * 在信息的基础上, 建立实体之间的联系, 就能形成知识
  * 每条知识用一个三元组表示(subject-predicate-object)
  * 知识图谱的架构:
    * 逻辑结构
    * 分为`模式层`和`数据层`
      * 数据层主要由一系列事实组成, 而知识将以事实为单位进行存储. 
      * 模式层构建在数据层智商, 通过本体库来规范数据层的一系列事实表达
    * 体系架构
  * 知识抽取: 从公开的半结构化, 非结构化数据中提取处实体, 关系, 属性等知识要素
    * 面向开放的链接数据, 通过自动化技术抽取出可用的知识单元
    * 知识单元主要包括`实体`, `关系`和`属性`
      * 实体抽取: 从原始语料中自动识别出命名实体. 
      * 关系抽取: 结局实体间语义链接的问题. 
      * 属性抽取: 通过属性形成对实体的完整勾画
  * 知识融合: 消除实体, 关系, 属性等指称项与事实对象之间的其一, 形成高质量的知识库
    * 由于知识来源广泛, 存在知识质量良莠不齐, 来自不同数据源的知识重复, 知识间的关联不够明确等问题, 所以需要进行知识的融合. 
    * 将不同源的知识进行异构数据整合, 消歧, 加工, 推理严重, 更新等步骤达成融合
  * 知识推理: 在已有的知识库基础上进一步挖掘隐含的知识, 从而丰富, 扩展知识库
  * 技术上, 知识图谱的难点在于NLP, 因为需要机器理解海量的文字信息. 但工程上, 难点在于知识的获取和融合.
- [x] Neo4j
  * 使用`py2neo`进行操作
  * 连接图: ` graph = Graph('bolt://localhost:7687', username='neo4j', password='neo4j')`
  * 创建节点: `a = Node('label', name='a')`, 进行绘制`graph.create(a)`
  * 建立关系: `r1 = Relationship(a, 'to', b, name='goto')`

## Day13: 学习Neo4j的CQL语法以及使用python操作es

> 传送门: [Neo4j教程](https://www.w3cschool.cn/neo4j/)

- [x] Neo4j:
  * 优点: 容易表示连接的数据, 检索/遍历/导航连接数据容易且快速, 容易表示半结构化数据
  * 构建模块:
    * 节点: 节点是图表的基本单位, 包含具有键值对的属性
    * 属性: 用于描述图节点和关系的键值对
    * 关系: 用于连接两个节点, 具有方向, 关系也有属性
    * 标签: 用于描述节点和关系, 是一个分类
  - [x] CQL:
    * CREATE: 用于创建节点, 关系和标签, 要注意, CREATE始终都会创建新的节点
      * 创建没有属性的节点: `CREATE (<node-name>:<label-name>)`
      * 创建具有属性的节点: `CREATE (<node-name>:<label-name>{<Property1-name>:<Property1-Value>})`
      * 还可以用于创建关系和标签
    * MATCH: 用于获取匹配到的数据
      * `MATCH (<node-name>:<label-name>)`
      * 不过MATCH不能单独使用, 需要进行配合
    * RETURN: 用于节点的属性, 关系的属性
      * `RETURN <node-name>.<property1-name>`
      * 同MATCH意义不能单独使用 
    * MATCH+RETURN: MATCH可以和RETURN组合使用: `MATCH Command \n RETURN Command`
    * 创建关系: `CREATE (p1:Profile1)-[r1:LIKES]->(p2:Profile2)`
      * `CREATE (<node1-name>:<label1-name>)-[(<relationship-name>:<relationship-label-name>)]->(<node2-name>:<label2-name>)` 
    * WHERE: 用于过滤MATCH的结果, `WHERE <condition> <boolean-operator> <condition>`, condition的格式为`<property-name> <comparison-operator> <value>`
    * DELETE: 用于删除节点和关系, `DELETE <node-name-list>` 这里的list是用MATCH返回得到的, 也可以是用`,`分隔的多个节点名
    * SET: 用于设置或修改属性, 用法与DELETE类似 
    * REMOVE: 用于删除属性和标签: 用法与DELETE类似
    * ORDER BY: 用于对MATCH结果进行排序, `ORDER BY  <property-name-list>  [DESC]`
    * UNION: 用于将结果合并, 要求结果的名称/数据类型都必须匹配, `<MATCH Command1> UNION <MATCH Command2>`
    * LIMIT: 用于限制MATCH返回结果的行数, 它修剪CQL查询结果集底部的结果, `LIMIT <number>`
    * SKIP: 同LIMIT, 不过是修剪了结果集顶部的结果
    * MERGE: `MERGE = CREATE + MATCH`, MERGE会在创建节点前进行查重, 如果重复了就不会插入新节点.
    * NULL值: CQL里将NULL视作为`缺失值`或`未定义值`, 很多没有指定的地方都会用NULL进行缺省
    * IN: `IN[<Collection-of-values>]`, 类似python的in, 用于确定范围
    * 函数:
      * String函数: `UPPER/LOWER/SUBSTRING/REPLACE`
      * AGGREGATION函数: `COUNT/MAX/MIN/SUM/AVG`
      * 关系函数: `STARTNODE/ENDNODE/ID/TYPE`
    * 索引: `CREATE INDEX ON :<label_name> (<property_name>)`
    * UNIQUE约束: `CREATE CONSTRAINT ON (<label_name>) ASSERT <property_name> IS UNIQUE`

## Day14: 学习知识图谱构建技术和阅读两篇应用知识图谱于安全分析的论文

> 传送门: [自底向上——知识图谱构建技术初探](https://www.anquanke.com/post/id/149122)

- [x] 知识图谱构建技术:
  * 知识图谱: 是结构化的语义知识库, 用于描述概念及相互关系, 实现知识的推理
  * 构建方式: 
    * 自顶向下: 借助已有的结构化数据源(比如百科类), 从高质量数据中提取本体和模式信息, 加入到知识库
    * 自底向上: 从公开采集的数据中提取出资源模式, 选取其中置信度高的信息加入到知识库
  * 逻辑架构:
    * 数据层: 存储真实具体的数据
    * 模式层: 在数据层之上, 存储经过提炼的知识.
  * 技术架构: 构建知识图谱是一个迭代更新的过程, 每轮迭代包括三个阶段
    * 信息抽取: 从多源异构数据源中提取出实体, 属性及相互关系
    * 知识融合: 在获得新知识后, 需要进行整合, 以消除矛盾和歧义. 
    * 知识加工: 对于融合后的新知识, 需要进行质量评估, 将合格的部分加入到知识库中, 确保知识库的质量
- [x] [一种基于知识图谱的工业互联网安全漏洞研究方法](http://www.qczk.cnki.net/kcms/detail/detail.aspx?filename=WXJY202001004&dbcode=CRJT_CJFD&dbname=CJFDAUTO&v=)
  * 从ISVD这样的半结构化信息源里提取了漏洞信息条目. 
  * 信息提取引擎将漏洞信息, 事件信息和产品信息从原始信息中提取出来, 以下是提取规则
    * 通过正则表达式, 提取描述中的`时间`
    * 模糊匹配提取产品的相关描述
  * 关联分析: 建立事件到漏洞的关系, 再建立产品到漏洞的关系, 推导处事件到产品的关系.
- [x] [数据驱动的物联网安全威胁检测与建模](http://kns.cnki.net/kcms/detail/detail.aspx?filename=1020606498.nh&dbcode=CMFD&dbname=CMFDTEMP&v=)
  * 知识融合: 将表示相同内涵但是名称不一致的实体统一成一个名称表示. 
    * 实体层融合首先生成候选物联网安全实体, 主要有基于名称词典, 基于搜索引擎的方法
    * 其次, 候选实体排序. 主要为有监督和无监督的排序方法
    * 最后, 无链接指称项预测, 当知识库里没有相关的候选实体项时, 需要给出近似的实体
  * 知识推理: 包含基于符号的推理和基于统计的推理
    * 基于符号: 通过指定规则, 从已有关系中归纳出新的规则
    * 基于统计: 利用机器学习方法, 通过统计规律从知识图谱中可以有效发现一些网络异常和攻击, 挖掘安全威胁的隐藏关系和路径, 并对攻击进行预测, 从而感知并展示网络的安全态势. 主要包括实体关系学习方法, 类型推理方法和模式归纳方法. 