# Week 13


## Day85: 阅读Accelerated C++第5,6章

* 迭代vector:
  ``` c++
  for (vector<Student_info>::const_iterator iter = students.begin(); 
    iter != students.end(); ++iter) { 
      cout << iter->name << endl;
      cout << (*iter).name << endl;
  }
  ```
* `copy(bottom.begin(), bottom.end(), back_inserter(ret));`中copy(begin, end, out), 指定拷贝的起始, 终点以及输出的目标. 而back_inserter()在其参数作为目标的时候, 能将内容附加到其参数后, 也就是拷贝到ret的末尾. 切要注意, 不能使用`copy(bottom.begin(), bottom.end(), ret.end())`
* `transform(begin, end, out, func)`前三个参数是迭代器, 第四个参数是函数, begin和end用来指定元素的范围, 而out指定转换后元素的目标存储, 而func则是对应的转换函数, 会用于begin和end指定范围内的各个元素. 
* `accumulate(v.begin(), v.end(), 0.0)`以0为起点, 将v的值全部累加起来. 
* `remove_copy(begin, end, out, value)`, 从容器内移除begin和end指定的内容, 并拷贝其中与value不相等的部分到out
* `partition(begin, end, func)`会对begin, end指定范围进行排布, 满足func为True的排在前面, False的排在后面. 然后返回bounds, 也就是True和False的边界. 这个排布是不稳定的, 可能会打乱其内部的排列顺序, 因此也可以使用`stable_partition`


## Day86-87: 阅读Accelerated C++第7及后续章节

* map的迭代器是pair类型, 且pair类型均是const的, 对于pair类型其有first和second两个成员, 应该是对应于python的tuple.
* 一个模版类声明的示例:
  ``` c++
  template <class T> class Vec { 
  public:
    typedef T* iterator; 
    typedef const T* const_iterator; 
    typedef size_t size_type; 
    typedef T value_type;

    Vec() { create(); } 
    explicit Vec(size_type n, const T& t = T()) { create(n, t); }

    Vec(const Vec& v) { create(v.begin(), v.end()); } 
    Vec& operator=(const Vec&); 
    ~Vec() { uncreate(); }

    T& operator[](size_type i) { return data[i]; } 
    const T& operator[](size_type i) const { return data[i]; }

    void push_back(const T& t) { 
      if (avail == limit) 
        grow(); 
      unchecked_append(t); 
    }

    size_type size() const { return avail - data; }

    iterator begin() { return data; } 
    const_iterator begin() const { return data; }
    iterator end() { return avail; } 
    const_iterator end() const { return avail; } 
  private:
    iterator data; // first element in the Vec 
    iterator avail; // (one past) the last element in the Vec 
    iterator limit; // (one past) the allocated memory

    // facilities for memory allocation 
    allocator<T> alloc; // object to handle memory allocation

    // allocate and initialize the underlying array 
    void create(); 
    void create(size_type, const T&); 
    void create(const_iterator, const_iterator);

    // destroy the elements in the array and free the memory 
    void uncreate();

    // support functions for push_back 
    void grow(); 
    void unchecked_append(const T&);

  };
  ```
* 对于类继承的改写函数使用virtual指定虚函数

## Day88: 阅读LLVM Essentials第1章

* 对于LLVM IR有以下解释: 
  * ModuleID: 指定LLVM模块ID. 一个LLVM模块包含输入文件的完整内容, 由函数, 全局变量, 外部函数原型, 符号表等组成. 
  * datalayout字符串可以指明字节序(e表示小端)以及文件类型(e表示elf, o表示mach-o)
  * IR里所有的全局变量用@作为前缀, 局部变量用%作为前缀
  * LLVM将全局变量视为指针, 因此对指针进行解引用需要使用load指令, 存储值需要使用store质量. 
  * `%1 = value`是寄存器变量, `%2 = alloca i32`是分配在栈上的变量
  * 函数名前的@表明其在全局是可见的.
  * LLVM使用三地址码且是SSA格式
  * ident指明模块和编译器版本. 
* LLVM工具
  * clang -emit-llvm -c add.c
  * llvm-as add.ll –o add.bc
  * llvm-dis add.bc –o add.ll
  * llvm-link main.bc add.bc -o output.bc
  * lli output.bc
  * llc output.bc –o output.s


## Day89: 阅读LLVM Essentials第2章

书里使用的应该是LLVM 3.8的版本, 目前LLVM已经更新到11, 且macos通过homebrew安装的10.0.1版本其`--system-libs`的xml2存在问题. 所以会有一些不适用的情况. 尽管代码发生了很大的变化, 但好在很多思路是大致一样的. 

* LLVM提供了Module()来创建模块, 创建模块需要指定其name和context
* 编译时需要引入LLVM的头文件, 使用`llvm-config --cxxflags --ldflags --system-libs --libs core`
* IRBuilder类用于生成LLVM IR. 
* llvm:Function用于生成函数, llvm::FunctionType()用于关联函数的返回值类型
* 对于生成的Function可以使用verifyFunction()来检查是否正确
* Module类的getOrInsertGlobal()函数可以用于创建全局变量
* Linkage: 指定链接类型
* phi指令用于分支条件情况, 对于不同分支的基本块使用phi指令来确定具体使用哪一个分支的结果(因为IR是SSA形式)

简单的LLVM 10示例代码

``` c++
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"
#include <stdio.h>

using namespace llvm;

int main(int argc, char *argv[]) {
  LLVMContext Context;
  Module *Mod = new Module("MyModule", Context);
  raw_fd_ostream r(fileno(stdout), false);
  verifyModule(*Mod, &r);

  FILE *my_mod = fopen("MyModule.bc", "w+");
  raw_fd_ostream bitcodeWriter(fileno(my_mod), true);
  WriteBitcodeToFile(*Mod, bitcodeWriter);
  delete Mod;
  return 0;
}
```

## Day90: 阅读LLVM Essentials第3,4章

* getelementptr指令用于获取地址, 本身并不访问内存, 只是做地址的计算
* load指令用于读取内存内容, store指令用于写入内容到内存
* insertelement将标量插入到向量中去, 其接受三个参数, 依次是响亮类型, 插入的标量值, 插入索引位置
* extractelement从向量里读出标量. 
* doInitialization: 用于初始化. runOn{Passtype}一般是针对Passtype的处理函数. doFinalization则是最后的结尾清理环境用的
* 编写LLVM Pass需要在`lib/Transforms`下创建目录, 并在其内创建Makefile大概如下:
  ``` makefile
  LEVEL = ../../.. 
  LIBRARYNAME = FnNamePrint 
  LOADABLE_MODULE = 1 
  include $(LEVEL)/Makefile.common
  ```
* 一个打印函数名的pass如下:
  ``` c++
  #include "llvm/Pass.h" 
  #include "llvm/IR/Function.h" 
  #include "llvm/Support/raw_ostream.h"

  using namespace llvm;

  namespace {

  struct FnNamePrint: public FunctionPass { 
    static char ID; 
    FnNamePrint () : FunctionPass(ID) {} 
    bool runOnFunction(Function &F) override { 
      errs() << "Function " << F.getName() << '\n'; 
      return false; 
      } 
    };
  }

  char FnNamePrint::ID = 0;
  static RegisterPass< FnNamePrint > X("funcnameprint","Function Name Print", false, false);
  ```
  最后两行是向pass manager注册当前pass
* 给opt提供–debug-pass=Structure选项可以查看pass运行的情况
* getAnalysisUsage可以指定pass之间的依赖关系
  * AnalysisUsage::addRequired<>方法设定pass的依赖关系, 指定的pass会先于当前pass执行
  * AnalysisUsage:addRequiredTransitive<>指定多个依赖组成分析链条
  * AnalysisUsage::addPreserved<>指定暂时保存某个pass的结果以避免重复计算. 

## Day91: 阅读LLVM Essentials第5,6章

* dominator tree: 支配树, 当所有通向节点n的路径也一定都通过节点d时, 我们称节点d支配节点n, 表示为d->n, 对于所有基本块构成的也就是支配树. 
* DAG: directed acyclic graph, 用于代码生成的一个有向无环图. 
* 代码生成: 将IR转化成SelectionDAG然后进行多阶段优化: DAG组合, 合法化, 指令选择, 指令调度等, 最后分配寄存器生成机器码. 
* SelectionDAGBuilder接口用于创建对应IR指令的DAG节点