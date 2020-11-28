# Week 11

## Day71: 参考xnu-qemu-arm64项目使用QEMU模拟iOS

> 传送门: [xnu-qemu-arm64](https://github.com/alephsecurity/xnu-qemu-arm64)

使用qemu+kvm模拟macOS目前算是资料较多的一方面了, 可以参考[Docker-OSX](https://github.com/sickcodes/Docker-OSX). 因为是写的dockerfile, 所以相当完善地记录了构建的整个过程, 熟悉qemu和黑苹果安装的话会很好理解. 

这次想来看这个项目是如何进行iOS的模拟的. 

* 准备材料: a **kernel image**, a **device tree**, a static **trust cache**, and **ramdisk** images
* 首先下载苹果官方给出的更新文件: [iOS 12.1 update file](http://updates-http.cdn-apple.com/2018FallFCS/fullrestores/091-91479/964118EC-D4BE-11E8-BC75-A45C715A3354/iPhone_5.5_12.1_16B92_Restore.ipsw) 它是一个zip文件可以直接解压

``` shell
$ unzip iPhone_5.5_12.1_16B92_Restore.ipsw
# 下载解压用的工具
$ git clone git@github.com:alephsecurity/xnu-qemu-arm64-tools.git
# 解码ASN1编码的内核映像
$ pip install pyasn1 # 脚本依赖pyasn1这个包
$ python xnu-qemu-arm64-tools/bootstrap_scripts/asn1kerneldecode.py kernelcache.release.n66 kernelcache.release.n66.asn1decoded
# 解码后还有一层lzss压缩, 继续解压
$ python xnu-qemu-arm64-tools/bootstrap_scripts/decompress_lzss.py kernelcache.release.n66.asn1decoded kernelcache.release.n66.out
# 获取device tree, 同样是ASN1编码, 用之前的工具解码即可.
$ python xnu-qemu-arm64-tools/bootstrap_scripts/asn1dtredecode.py Firmware/all_flash/DeviceTree.n66ap.im4p Firmware/all_flash/DeviceTree.n66ap.im4p.out
# 对于ramdisk同样进行ASN1解码
$ python3 xnu-qemu-arm64-tools/bootstrap_scripts/asn1rdskdecode.py ./048-32651-104.dmg ./048-32651-104.dmg.out
# 对ramdisk进行大小调整, 挂载和赋权
$ hdiutil resize -size 1.5G -imagekey diskimage-class=CRawDiskImage 048-32651-104.dmg.out
$ hdiutil attach -imagekey diskimage-class=CRawDiskImage 048-32651-104.dmg.out
$ sudo diskutil enableownership /Volumes/PeaceB16B92.arm64UpdateRamDisk/
# 挂载原来的映像
$ hdiutil attach ./048-31952-103.dmg 
# 为ramdisk内的dynamic loader cache创建空间并拷贝进去
$ sudo mkdir -p /Volumes/PeaceB16B92.arm64UpdateRamDisk/System/Library/Caches/com.apple.dyld/
$ sudo cp /Volumes/PeaceB16B92.N56N66OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 /Volumes/PeaceB16B92.arm64UpdateRamDisk/System/Library/Caches/com.apple.dyld/
$ sudo chown root /Volumes/PeaceB16B92.arm64UpdateRamDisk/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
# 获取一些编译好的iOS工具, 包括bash
$ git clone https://github.com/jakeajames/rootlessJB
$ cd rootlessJB/rootlessJB/bootstrap/tars/
$ tar xvf iosbinpack.tar
$ sudo cp -R iosbinpack64 /Volumes/PeaceB16B92.arm64UpdateRamDisk/
$ cd -
# 配置launchd不要运行任何服务
$ sudo rm /Volumes/PeaceB16B92.arm64UpdateRamDisk/System/Library/LaunchDaemons/*
```

* 配置launchd运行bash: 创建 `/Volumes/PeaceB16B92.arm64UpdateRamDisk/System/Library/LaunchDaemons/bash.plist` 并写入以下内容

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>EnablePressuredExit</key>
        <false/>
        <key>Label</key>
        <string>com.apple.bash</string>
        <key>POSIXSpawnType</key>
        <string>Interactive</string>
        <key>ProgramArguments</key>
        <array>
                <string>/iosbinpack64/bin/bash</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
        <key>StandardErrorPath</key>
        <string>/dev/console</string>
        <key>StandardInPath</key>
        <string>/dev/console</string>
        <key>StandardOutPath</key>
        <string>/dev/console</string>
        <key>Umask</key>
        <integer>0</integer>
        <key>UserName</key>
        <string>root</string>
</dict>
</plist>
```

* 安装 **jtool** 然后将之前拷贝进去的预编译二进制进行信任.  

  ``` shell
  $ jtool --sig --ent /Volumes/PeaceB16B92.arm64UpdateRamDisk/iosbinpack64/bin/bash
  Blob at offset: 1308032 (10912 bytes) is an embedded signature
  Code Directory (10566 bytes)
                  Version:     20001
                  Flags:       none
                  CodeLimit:   0x13f580
                  Identifier:  /Users/jakejames/Desktop/jelbreks/multi_path/multi_path/iosbinpack64/bin/bash (0x58)
                  CDHash:      7ad4d4c517938b6fdc0f5241cd300d17fbb52418b1a188e357148f8369bacad1 (computed)
                  # of Hashes: 320 code + 5 special
                  Hashes @326 size: 32 Type: SHA-256
   Empty requirement set (12 bytes)
  Entitlements (279 bytes) :
  --
  <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
  <plist version="1.0">
  <dict>
      <key>platform-application</key>
      <true/>
      <key>com.apple.private.security.container-required</key>
      <false/>
  </dict>
  </plist>
  ```

* 将`CDHash`写入到`tchashes`内:

  ``` bash
  $ touch ./tchashes
  $ for filename in $(find /Volumes/PeaceB16B92.arm64UpdateRamDisk/iosbinpack64 -type f); do jtool --sig --ent $filename 2>/dev/null; done | grep CDHash | cut -d' ' -f6 | cut -c 1-40 >> ./tchashes
  ```

* 创建static trust cache blob

  ``` bash
  $ python3 xnu-qemu-arm64-tools/bootstrap_scripts/create_trustcache.py tchashes static_tc
  ```

* 将各个卷宗卸载掉

  ``` bash
  $ hdiutil detach /Volumes/PeaceB16B92.arm64UpdateRamDisk
  $ hdiutil detach /Volumes/PeaceB16B92.N56N66OS   
  ```

* 编译iOS定制过的QEMU

  ``` bash
  $ git clone git@github.com:alephsecurity/xnu-qemu-arm64.git
  $ cd xnu-qemu-arm64
  $ ./configure --target-list=aarch64-softmmu --disable-capstone --disable-pie --disable-slirp
  ```

* 使用QEMU将iOS虚拟机启动起来

  ``` bash
  $ ./xnu-qemu-arm64/aarch64-softmmu/qemu-system-aarch64 -M iPhone6splus-n66-s8000,kernel-filename=kernelcache.release.n66.out,dtb-filename=Firmware/all_flash/DeviceTree.n66ap.im4p.out,ramdisk-filename=048-32651-104.dmg.out,tc-filename=static_tc,kern-cmd-args="debug=0x8 kextlog=0xfff cpus=1 rd=md0 serial=2",xnu-ramfb=off -cpu max -m 6G -serial mon:stdio
  # 进入bash后, 修改PATH指向拷贝有预编译二进制的目录
  bash-4.4# export PATH=$PATH:/iosbinpack64/usr/bin:/iosbinpack64/bin:/iosbinpack64/usr/sbin:/iosbinpack64/sbin
  ```


## Day72: 参考macOS的网络流量监控代码


## Day73: 学习LLVM Pass的编写

参考资料: 
1. [LLVM官方资料: Writing an LLVM Pass](https://llvm.org/docs/WritingAnLLVMPass.html) 
2. [CS6120 Project3: Write an LLVM Pass](https://www.cs.cornell.edu/courses/cs6120/2019fa/project/3/): 同时也是一项公开的编译器课程
3. [Writng an LLVM Pass: 101 LLVM 2019 tutorial](https://llvm.org/devmtg/2019-10/slides/Warzynski-WritingAnLLVMPass.pdf)
4. [UG3 COMPILING TECHNIQUES 2019/2020](https://www.inf.ed.ac.uk/teaching/courses/ct/19-20/): 国外课程
5. [Github: banach-space/llvm-tutor](https://github.com/banach-space/llvm-tutor)
6. [Github: abenkhadra/llvm-pass-tutorial](https://github.com/abenkhadra/llvm-pass-tutorial): 简单的demo, 最下有给出其他的参考资料

- [x] 什么是LLVM Pass?
    * LLVM Pass意即LLVM的转换(transformations)和优化(optimizations)工作
    * 所有的LLVM Pass都继承于Pass类, 根据用途的不同, 可以继承的类有 ModulePass, CallGraphSCCPass, FunctionPass, or LoopPass, or RegionPass classes
- [x] LLVM PASS HelloWorld Demo
    * 首先下载LLVM的源代码, 我们的HelloWorld就在其源码的lib/Transforms/Hello下. 我当前的版本是10.0.1
    * 编辑lib/Transforms/Hello/CMakeLists.txt写入以下内容: 
      ``` cmake
        add_llvm_library(
          LLVMHello
          MODULE
          Hello.cpp
          PLUGIN_TOOL
          opt
          )
      ```
    * 编辑lib/Transforms/CMakeLists.txt加入`add_subdirectory(Hello)`
    * 以上是在配置CMake的编译环境, 接下来可以开始编写LLVM Pass.
    * 首先是引入头文件
      ``` c++
      #include "llvm/Pass.h"        // 编写PASS的头文件
      #include "llvm/IR/Function.h" // 操作函数用
      #include "llvm/Support/raw_ostream.h" // 输出信息用
      ```
    * 指定`using namespace llvm;` 因为引入的头文件里的函数存在于llvm命名空间里
    * `namespace {`指定匿名命名空间, 作用跟c的static类似, 能使得匿名空间内声明的代码仅在当前文件内可见
    * 在命名空间里声明我们的pass本身, 声明继承于FunctionPass, 以及重载FunctionPass的函数runOnFunction
      ``` c++
      namespace {
        // Hello - The first implementation, without getAnalysisUsage.
        struct Hello : public FunctionPass {
          static char ID; // Pass identification, replacement for typeid
          Hello() : FunctionPass(ID) {}

          bool runOnFunction(Function &F) override {
            ++HelloCounter;
            errs() << "Hello: ";
            errs().write_escaped(F.getName()) << '\n';
            return false;
          }
        };
      }
      ```
    * 初始化LLVM的Pass ID. LLVM使用ID的地址来标识一个pass, ID的值并不重要 `char Hello::ID = 0;`
    * 注册我们的Hello类: 第一个是命令行参数, 第二个是其参数释义
    ``` c++
    static RegisterPass<Hello> X("hello", "Hello World Pass",
                             false /* Only looks at CFG */,
                             false /* Analysis Pass */);
    ```
    * 注册pass到现有的分析流水线: 
      * PassManagerBuilder::EP_EarlyAsPossible 可以使得pass优先于所有优化pass前执行
      * PassManagerBuilder::EP_FullLinkTimeOptimizationLast 可以使得pass优先于所有链接时优化Pass前执行. 
    * 使用opt运行pass: `opt -load lib/LLVMHello.so -hello < hello.bc > /dev/null`

## Day74: 学习使用Ghidra进行逆向

> 参考资料: [hackaday-u](https://github.com/wrongbaud/hackaday-u)

参考资料是一个使用Ghidra进行逆向的教程, 但是里面有很多是讲逆向基础的, 所以就此略过, 仅关注其中跟Ghidra相关的部分. 

Ghidra只需要安装有JDK11后运行ghidraRun即可. 界面过于简陋了而且使用有点不方便, 工作需要创建一个工程, 然后点击CodeBrowser按纽(龙的标志)打开窗口, 然后再在窗口里点击上方菜单栏`File->Import File`将待分析的文件导入到工程里.  
打开后Ghidra进行分析, 然后左下角的`Symbol Tree`窗口里是的`Functions`就是各个函数了, 点击其中的函数, 就是相应的汇编代码及反编译的伪代码.

反编译的代码只能算能看了, 但还是有很大空间. 不过鼠标右键有切片的功能, 这就是Ghidra的优势之一了. 

* G: 跳转到地址/标签/表达式
* L: 重命名变量
* T: 定义数据类型
* B: 在整型之间快速转换 byte, word, dword, qword
* ': 在字符类型之间转换 char, string, unicode
* [: 创建数组
* P: 创建指针
* Shift+[: 创建结构体
* 导入C的头文件: File -> Parse C Source
* 交叉引用: References -> Show References to context
* S: 内存搜索值
* Ctrl+Shift+E: 搜索字符串

无头模式: 参考 [analyzeHeadlessREADME](https://ghidra.re/ghidra_docs/analyzeHeadlessREADME.html)

## Day75: 阅读AFL源码

## 0x01 debug.h

定义了各种开发调试用的宏. 

* 有终端控制字符(比如控制终端输出的颜色, 可视化绘画界面用的宏以及其他控制字符).
* 调试输出用的宏,  主要是`SAYF`宏, 然后衍生出WARNF, ACTF, OKF, BADF, FATAL, ABORT, PFATAL, RPFATAL用于日志分级输出. 另外定义了ck_write和ck_read, 在write和read基础上添加了check

## 0x02 hash.h

定义了一个*MurmurHash3*变种哈希算法, 有分32和64位分别实现. 主要追求效率而并非是一个安全的哈希算法, 并且也不支持非8倍数长度的buf进行哈希. 

## 0x03 types.h

* 定义了一些类型的别名, 比如u64, s8, s16, s32, s64. 
* 简单的算术操作, 比如MIN, MAX, SWAP16, SWAP32
* 随机数: 生成方法 random() % (x) 不过会因为是否处于LLVM模式而名称有点变化, 但其实没有什么影响. 
* STRINGIFY: 用于显示变量的名称, 比如STRINGIFY(x) 就是"x"这样
* MEM_BARRIER: 内存屏障, 避免指令重排
* likely和unlikely 用于分支预测优化

## 0x04 config.h

定义了afl的一些配置信息. TODO: 需要时补充

## 0x05 afl-fuzz.c

从main函数开始看起

### 1. 处理函数命令行参数

定义了`i:o:f:m:b:t:T:dnCB:S:M:x:QV`参数. 释义如下:

* i: input dir
* o: output dir
* M: master sync ID, 指定当前fuzzer作为主人, 不能跟-S选项同时使用
* S: slave sync ID, 指定当前fuzzer作为仆从, 不能跟-M选项同时使用
* f: target file, 对应变量out_file
* x: *dictionary*, 字典目录, 对应变量extras_dir
* t: timeout, 超时时间, 对应变量exec_tmout, 时间单位对应suffix
* m: 内存限制, 对应变量mem_limit, 时间可选单位有T, G, k, M
* b:  *bind CPU core*, 对应变量cpu_to_bind
* d: *skip deterministic*, 跳过确定性策略, 会将skip_deterministic和use_splicing置1
* B: *load bitmap*, 未文档化的一个选项, 对应变量in_bitmap, 当你在fuzz过程中找到一个有趣的测试用例时, 并且想要直接对其进行变异时使用.
* C: *crash mode*, 对应变量crash_mode设置为FAULT_CRASH
* n: dumb mode, 会根据是否存在AFL_DUMB_FORKSRV环境变量而将dumb_mode设置为2或1
* T: user banner
* Q: QEMU mode, 将qemu_mode置为1, 并且将内存限制默认设置为MEM_LIMIT_QEMU, 即200M
* V: version, 显示版本

### 2. 初始化配置以及相关检查

* setup_signal_handlers: 注册一些信号处理的函数
* check_asan_opts: 检查ASAN和MSAN的选项是否有冲突的地方
* fix_up_sync: 检验sync ID是否合法以及修正slave的out_dir和sync_dir
* 检查in_dir和out_dir是否重合, 检查是否存在dump_mode和crash_mode & qemu_mode冲突
* 读取环境变量, 对一些开关进行置位或者赋值: 
  * AFL_NO_FORKSRV
  * AFL_NO_CPU_RED
  * AFL_NO_ARITH
  * AFL_SHUFFLE_QUEUE
  * AFL_FAST_CAL
  * AFL_HANG_TMOUT
* 检查是否同时设置了AFL_DUMB_FORKSRV and AFL_NO_FORKSRV环境变量(冲突)
* 设置了AFL_PRELOAD情况下, 会设置相关的环境变量LD_PRELOAD, DYLD_INSERT_LIBRARIES并且不建议使用环境变量AFL_LD_PRELOAD


## Day76: 阅读一篇开源库名称抢注检测的论文

> [SpellBound: Defending Against Package Typosquatting](https://arxiv.org/abs/2003.03471)

论文里对于名称抢注的判定有分以下几种情况, 称之为怀疑抢注的信号:

* Repeated characters: 比如request->reequest
* Omitted characters: 比如require-port->requires-port
* Swapped characters: 比如axois->axios
* Swapped words: 比如import-mysql->mysql-import
* Common typos: 这主要是一些肉眼的差异, 比如signqle->signale, lodash->1odash
* Version numbers: underscore.string->underscore.string-2

抢注包的攻击面也有进行讨论:

* Attacks against end-users: 直接影响终端用户, 执行恶意payload或者泄漏信息
* Attacks against developers using a package: 因为比如npm和pypi在安装时都是需要执行shell命令来进行配置和部署的. 但如果开发者使用root权限进行了系统全局的安装, 那么就可能以root身份执行恶意命令.
* Latent vulnerabilities: 直接镜像一个旧版本的开源库, 因为是镜像, 所以程序行为是一致的, 但是因为旧版本通常存在安全漏洞, 因此用这种方式来进行攻击. 
* Misattribution: 分流?



## Day77: 阅读FANS和Sys论文

* [Sys: a Static/Symbolic Tool for Finding Good Bugs in Good (Browser) Code](https://cseweb.ucsd.edu/~dstefan/pubs/brown:2020:sys.pdf)
* [FANS: Fuzzing Android Native System Services via Automated Interface Analysis](https://www.usenix.org/system/files/sec20fall_liu_prepub.pdf)
