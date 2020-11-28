# Week 8

## Day50: 了解syzkaller并学习learn-go-with-tests

- [x] syzkaller的工作原理
  * `syz-manager`进程负责启动, 监控和重启管理的VM实例, 并在VM里启动一个`syz-fuzzer`进程. `syz-manager`负责corpus持久化和crash存储. 运行在具有稳定内核物理机层面
  * `syz-fuzzer`在不稳定的VM内部运行, 用于指导模糊测试进程(输入生产, 编译, 最小化等), 并通过RPC将触发新覆盖的输入发送回`syz-manager`. 它也会启动短暂的`syz-executor`进程
  * 每个`syz-executor`进程执行单个输入样例(syscalls序列), 它从`syz-fuzzer`处获取一个程序进行执行并返回执行结构. 它被设计得极尽简单(以避免干扰fuzz), 使用c++编写并编译成静态二进制文件, 使用共享内存进行通信.
- [x] learn go with tests
  * 编写测试: 
    * 程序需要在一个名为 xxx_test.go 的文件中编写
    * 测试函数的命名必须以单词 Test 开始
    * 测试函数只接受一个参数 t *testing.T
  * 常量可以提高应用程序的性能, 可以快速理解值的含义
  * 测试驱动(TDD):
    * 编写一个测试
    * 让编译通过
    * 运行测试，查看失败原因并检查错误消息是很有意义的
    * 编写足够的代码以使测试通过
    * 重构
  * 函数返回值使用(name string)更好, name的默认为零值, 只需要在函数内调用`return`即可, 并且这将显示在godoc内, 能使代码更加清晰.
  * 函数名称以小写字母开头。在 Go 中，公共函数以大写字母开始，私有函数以小写字母开头。我们不希望我们算法的内部结构暴露给外部，所以我们将这个功能私有化
  * 质疑测试的价值是非常重要的。测试并不是越多越好，而是尽可能的使你的代码更加健壮。太多的测试会增加维护成本，因为 维护每个测试都是需要成本的。
  * `reflect.DeepEqual`不是类型安全的, 当比较两个不同类型的时候会出问题


## Day51: 学习learn-go-with-tests

- [x] learn go with tests:
  * nil 是其他编程语言的 null。
  * 错误可以是 nil，因为返回类型是 error，这是一个接口。
  * 如果你看到一个函数，它接受参数或返回值的类型是接口，它们就可以是 nil。
  * 如果你尝试访问一个值为 nil 的值，它将会引发 运行时的 panic。这很糟糕！你应该确保你检查了 nil 的值。
  * map是引用类型, 可以是nil值, 但是为了避免nil指针异常错误, 应当使用`map[string]string{}`或`make(map[string]string)`来创建一个空map
  * 测试只测试**有效的行为**, 而不是所有的**实现细节**
  * 让它运作，使它正确，使它快速: 「运作」是通过测试，「正确」是重构代码，而「快速」是优化代码以使其快速运行。
* 阅读syzkaller源码: godep restore 将依赖包都安装好. 


## Day52: 学习angr使用的IR-VEX

* [pyvex](https://github.com/angr/pyvex): 介绍了pyvex的安装和基本的使用方法, 并且介绍了一些IR的知识. 不过不够详细, 只有简单的示例. 而且感觉VEX有点粗糙. 
* [Binary Analysis with angr](https://archive.fosdem.org/2017/schedule/event/valgrind_angr/attachments/slides/1797/export/events/attachments/valgrind_angr/slides/1797/slides.pdf): 使用vex来分析binary的一份ppt. 
* [https://github.com/angr/vex/blob/dev/pub/libvex_ir.h](https://github.com/angr/vex/blob/dev/pub/libvex_ir.h): 该代码内的注释详细得说明了vex.
  * IRSB: IR Super Blocks, 每个IRSB包括以下三样东西:
    1. a type environment, 指示IRSB中每个临时值的类型
    2. a list of statements, 代表代码
    3. a jump that exits from the end the IRSB. 基本块结尾的跳转
  * IRStmt(Statements): 表示带有副作用的操作
  * IRExpr(Expression): 表示无副作用的操作
  * guest state: 一块内存区域, 看描述理解是一块被VEX库控制的内存区域.
  * IRMark: 是个IR语句, 但不表示实际的代码, 它指示的是原始指令的地址和长度
  * ppIRFoo: 输出IRFoo的函数
  * eqIRFoo: IRFoos的结构对等谓词
  * deepCopyIRFoo: IRFoo的深拷贝, 会拷贝整个对象树, 所有的类型都有一个深拷贝函数
  * shallowCopyIRFoo, 浅拷贝, 只拷贝顶层对象


## Day53: 阅读《Go语言标准库》

## Day54-57: 使用Go语言写一个HaboMalHunter

- [x] 使用golang读取配置信息
- [x] 使用golang执行外部命令
- [x] 增加检查是否使用UPX加壳
- [x] 使用file命令获取文件信息
- [x] 计算文件的Md5/Sha128/Sha256/SSdeep 
- [x] 支持提取文件的exif信息
- [x] 支持提取ELF文件的依赖库
- [x] 支持提取ELF文件的文件头信息
