# Week 9 


## Day58: 学习UW CSE501 静态分析课程

* 优化选项: 
    * dead code elimination
    * partial redundancy elimination
    * function inlining
    * strength reduction
    * loop transformations
    * constant propagation
* special edge: 
    * back edge: 指向一个之前遍历过的block
    * critical edge: 既不是唯一离开source的边, 也不是唯一进入到target的边
* dataflow framework:  <G, L, F, M>
    * G = flow graph
    * L = (semi-)lattice
    * F/M = flow / transfer functions
- [x] reaching definition:
    * dataflow equations:
        * IN[b]	=	OUT[b1]	U	...	U	OUT[bn]	
        * OUT[b]	=	(IN[b]	-	KILL[b])	U	GEN[b]
        * IN[entry]	=	0000000	
    * solving equations:
    ```
    Input: flow graph (CFG)
    // boundary condition
    OUT[Entry] = 0...0
    // initial conditions
    for each basic block B other than entry
     OUT[B] = 0...0
    // iterate
    while (any out[] changes value) {
     for each basic block B other than entry {
     IN[B] = U (OUT[p]), for all predecessor block p of B
     OUT[B] = (IN[B] – KILL[B]) U GEN[B]
     }
    }
    ```
- [x] live variable
    * transfer function for live variable:
        * x = y + z
        * generates new live variable: USE[s] = {y, z}
        * kills previously live variable: DEF[s] = x
        * variables that were not killed are propagated: OUT[s] - DEF[s]
        * so: IN[s] = USE[s] | (OUT[s] - DEF[s])
    * setup
        * boundary condition: IN[exit] = None
        * initial conditions: IN[B] = None
        * meet operation: OUT[B] = | IN[Successors]
- [x] Must Reach: a definition D must reach a program point P if
    * D appears at least once along all paths that leads to P
    * D is not redefined along any path after the last appearance of D and before P
* constant propagation: lattice
    * undefined: variable has not been initialized
    * NAC: variable definitely has a value( we just don't known what )
    * meet rules:
        * constant & constant = constant (if equal)
        * constant & constant = NAC (if not equal)
        * constant & undefined = constant
        * constant & NAC = NAC
* maximal fixed point
* meet over paths: 可能是无穷个

## Day59: 学习UW CSE501 指针分析

* 应用: 
    * 别名分析: 确定两个指针是否都指向相同的内存区域
    * 编译优化
    * 并行: 将串行代码转换成并行代码
    * shape analysis: 找到堆上数据结构的属性
    * 检测内存问题: 泄漏, 空指针引用等安全问题
* Point Language:
    * assume x and y are pointers
    * y = &x  -> means y points to x
    * y = x   -> means if x points to z then y points to z
    * *y = x  -> means if y points to z and z is a pointer, and if x points to w then z now points to w
    * y = *x  -> means if x points to z and z is a pointer, and if z points to w then y **not** points to w
    * points-to(x): set of variables that pointer variable x may point to 
* Andersen as graph closure
    * one node for each memory location
    * each node contains a points-to set
    * solve equations by computing transitive closure of graph, and add edges according to constraints
* worklist algorithm

    ```
W = { nodes with non-empty points-to sets }
while W is not empty {
    v = choose from W
    for each constraint v in x
        add edge x -> v, and add x to W if edge is new
    for each a in points-to(v) do {
        for each constraint p in *v
            add edge a -> p, and add a to W if edge is new
        for each constraint *v in q
            add edge q -> a, and add q to W if edge is new
    }
    for each edge v -> q do {
        points-to(q) = points-to(q) | points-to(v), and add q to W if points-to(q) changed
    }
}
    ```

## Day60-61: 二进制相似度聚类Golang实现

- [x] 使用binding连接radare2
- [x] 获取程序的字符串信息
- [x] 对字符串进行Base64编码后计算SHA256
- [x] 通过radare2获取二进制的基本块数据
- [x] 使用capstone将二进制数据转换成汇编代码
- [x] 拿到汇编代码后, 生成基本块
- [ ] 拿到基本块后, 生成基本的控制流
- [x] 对基本块进行简单的符号化(去除偏移和立即数等)


## Day62-63: 学习MOBISEC安全课程

- [x] 04 - Intro to Android Architecture and Security

Binder是Android用于RPC和进程间通信的机制, Android利用Binder来将普通进程内调用的API转换到特权进程/服务实现的特权API. 

Android系统启动完毕后会广播一个带 ACTION_BOOT_COMPLETED action的 Intent, 因此app可以通过接收改该 Intent 来做开机启动, 也就可以用于持久化

SYSTEM_ALERT_WINDOW: 可以在其他APP上显示一个窗口, 这会导致许多UI界面的攻击, 比如UI混淆, 点击劫持, 钓鱼等. 

- [x] 05 - Real-World Android Apps

sharedUserId安全问题: 相同证书的APP可以申请使用相同的Linux User ID, 而具有相同的Linux User Id可以共享该ID的所有内容, 也可以访问彼此的内部隐私存储和其他组件等. 

- [x] 08 - Reverse Engineering

Android逆向方法流:

1. 大概了解app的功能: 模拟器里启动app, 观察初始的UI
2. 找到app的攻击面: 
    - 从入口点开始入手做攻击面分析
    - 检查app的各项组件(activities, broadcast, intent, receiver), 这些组件是否暴露给外部的app使用
    - 检查app如何与外部进行交互, 比如文件系统, 网络, 组件间通信等.
3. app如何跟网络端点交互
    - 寻找网络端点的IP, URL等. 虽然有可能经过混淆
    - 寻找网络相关API的调用代码
    - 在模拟器里运行并监视其网络活动.
4. app是如何存储隐私信息
    - 隐私信息包括有, 用户帐号证书, 用户隐私数据, 需要安全权限才能访问的数据等.
5. 检查某个函数是否存在滥用
    - app是怎么使用函数X的
    - app是否有安全地使用该函数
    - 攻击者该如何到达该函数?