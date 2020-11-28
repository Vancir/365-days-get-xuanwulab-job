# Week 7


## Day44: 快速上手学习Go语言

> 参考: [菜鸟教程-Go语言](https://www.runoob.com/go/go-program-structure.html)

* 安装Golang: `yay -S go`, 使用`go run xxx.go`直接运行程序(可能也是以main作为入口把). 使用`go build`进行编译
* 标识符以`大写字母`开头, 那么这个标识符可以被外部包的代码所使用(导出的, 类似publick). 如果标识符以`小写字母`开头, 则对包外是不可见的, 但是他们则整个包的内部是可见并可用的(类似protected).
* `{`不能单独放在一行(微软写法落泪)
* 一些不太熟悉的保留字: `interface, select, defer, go, map, chan, fallthrough`
* Go语言中变量的声明必须使用空格隔开: `var age int`
* 派生类型: 指针类型, 数组类型, 结构化类型, `Channel`类型, 函数类型, `切片类型`, `接口类型(interface)`, `Map类型`.
* 声明变量: `var identifier type`, 可以一次声明多个变量: `var identifier1, identifier2 type`. 变量声明时如果没有初始化, 则默认为`零`值, `零值`包括`0, false, "", nil`
  * `v_name := value` 这样的写法可以省略`var`, 但是要求`v_name`必须是一个之前没有声明的新变量. 否则会产生编译错误.
  * 多变量声明: 
    * `var vname1, vname2, vname3 = v1, v2, v3`
    * `vname1, vname2, vname3 := v1, v2, v3` 这种格式只能在函数体中出现
    * 以下这种因式分解关键字的写法一般用于声明全局变量
    ``` go
    var (
      vname1 v_type1
      vname2 v_type2
    )
    ```
  * 如果你声明了一个局部变量却没有在相同的代码块中使用它, 同样会得到编译错误. 此外，单纯地给局部变量赋值也是不够的，这个值必须被使用. 
  * 全局变量是允许声明但不使用的. 
  * 空白标识符`_`也被用于抛弃值, 如值 5 在：`_, b = 5, 7` 中被抛弃. 因为Go是必须使用所有被声明的变量的, 但是有时候你并不需要使用从一个函数得到的所有返回值. 
* 常量声明: `const identifier [type] = value`. Go能推断类型所以可以省略type
  * 常量也可以用作枚举: 
    ``` go
    const (
        Unknown = 0
        Female = 1
        Male = 2
    )
    ```
  * 常量可以用`len(), cap(), unsafe.Sizeof()`函数计算表达式的值。常量表达式中，`函数必须是内置函数`，否则编译不过. 
* switch语句从上到下逐一测试, 直到匹配为止. 匹配项后面也不需要再加break. 如果我们需要执行后面的case, 可以使用`fallthrough`. `fallthrough`会强制执行下一条case语句.
* switch语句还可以用于`type-switch`来判断某个interface变量中实际存储的变量类型
  ``` go
  var x interface{}
     
  switch i := x.(type) {
    case nil:  
       fmt.Printf(" x 的类型 :%T",i)                
    case int:  
       fmt.Printf("x 是 int 型")                      
    case float64:
       fmt.Printf("x 是 float64 型")          
    case func(int) float64:
       fmt.Printf("x 是 func(int) 型")                      
    case bool, string:
       fmt.Printf("x 是 bool 或 string 型" )      
    default:
       fmt.Printf("未知型")    
  }  
  ```
* select 是 Go 中的一个控制结构, 类似于用于通信的 switch 语句. `每个case必须是一个通信操作, 要么是发送要么是接受`
  ``` go
  select {
    case communication clause  :
       statement(s);      
    case communication clause  :
       statement(s);
    /* 你可以定义任意数量的 case */
    default : /* 可选 */
       statement(s);
  }
  ```
* Go中通过`方法`来实现面向对象
* 数组: `var variable_name [SIZE] variable_type`
* Go中的`接口`, 可以将所有的具有共性的方法定义在一起, 任何其他类型只要实现来这些方法就是实现了这个接口(类似抽象方法? 继承?)
* Go使用内置的错误接口来提供简单的错误处理机制. 使用`error.New(msg)`
* 使用`go`关键字来开启`goroutine`, `goroutine`是轻量级线程, 调度由Golang运行时进行管理.
* channel是用来传递数据的一个数据结构. 可用于两个goroutine之间通过传递一个指定类型的值来同步运行和通讯. 操作符`<-`用于指定通道的方向, 发送或接受. 如果未指定方向, 则为双向通道. 
  ``` go
  ch := make(chan int)
  ch <- v
  v := <-ch
  ```
* 默认情况下, 通道是不带缓冲区的. 发送端发送数据的同时必须要由接受端接受数据. 通道可以设置缓冲区, 通过make的第二个参数指定`ch := make(chan int, 100)`. 带缓冲的channel允许异步发送/接受数据. 不过缓冲区的大小是有限的, 所以还是必须有接受端来接受数据, 否则缓冲区满来, 接受方就不能发送数据.
* 遍历通道`v, ok := <-ch`. 当通道接受不到数据后`ok`为`false`, 这时channel可以使用`close(c)`来关闭


## Day45-49: 参考Go by Example阅读一些示例代码

工作中常写的是Python来跑任务, 但是近来越发觉得Python的性能不足, 因此考虑学习Go语言, 能很好地兼顾性能和开发效率, 并且谷歌的Syzkaller以及一众项目(包括未来的一些打算会需要性能和并发)都是使用Go语言编写, 因此有必要去掌握这门语言. 

学习过程中练习编写的代码: [Vancir/go-by-example](https://github.com/Vancir/go-by-example)
