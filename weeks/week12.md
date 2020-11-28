# Week 12



## Day78: 阅读两篇fuzzing论文

* [Detecting Critical Bugs in SMT Solvers Using Blackbox Mutational Fuzzing](https://numairmansur.github.io/STORM.pdf)
* [Fuzzing: Challenges and Reflections](https://www.computer.org/csdl/magazine/so/5555/01/09166552/1mgaKsMFDYA)

## Day79: 阅读fuzz深层状态空间探索的论文以及一些收藏文章

* [IJON: Exploring Deep State Spaces via Fuzzing](https://www.syssec.ruhr-uni-bochum.de/media/emma/veroeffentlichungen/2020/02/27/IJON-Oakland20.pdf)
* [Fuzzing Linux GUI/GTK Programs With American Fuzzy Lop (AFL) For Fun And Pr... You Get the Idea. Part One.](https://blog.hyperiongray.com/fuzzing-gtk-programs-with-american-fuzzy-lop-afl/)
* [Pigaios: A Tool for Diffing Source Codes against Binaries](https://docs.google.com/presentation/d/1ifvugStGL7Qc8xSFeYXp2MGQ6jQGOOMSolBrJy8kCMY/edit#slide=id.g4453e8add5_0_85)


## Day80-81: 阅读LLVM Cookbook

## 一些命令行

* opt指定单独的pass进行优化:
  * opt –passname -S demo.ll –o output.ll
  * pass的源码路径在llvm/test/Transforms下, 重要的转换pass:
    * instcombine 合并冗余指令
    * deadargelim 无用参数消除
    * mem2reg 优化内存访问(将局部变量从内存提升到寄存器)
    * adce 入侵式无用代码消除
    * bb-vectorize  基本块向量化
    * constprop 简单常量传播
    * dec: 无用代码消除
    * globaldce: 无用全局变量消除
    * globalopt: 全局变量优化
    * gvn: 全局变量编号
    * inline: 函数内联
    * licm: 循环常量代码外提
    * loop-unswitch 循环外提
    * lowerinvoke: invode指令lowering, 以支持不稳定的代码生成器
    * lowerswitch: switch指令lowering
    * memcpyopt: memcpy优化
    * simplicycfg: 简化CFG
    * sink: 代码提升
    * tailcallelim: 尾部函数调用消除
* 将C代码转换成LLVM IR:
  * clang -emit-llvm -S demo.c -o demo.ll
* 将LLVM IR转换成bitcode
  * llvm-as demo.ll -o demo.bc
* 将bitcode转换为目标平台汇编码
  * llc demo.bc -o demo.s
  * clang -S demo.bc -o demo.s -fomit-frame-pointer (clang默认不消除frame pointer, llc默认消除)
  * 加入-march=architecture参数能指定生成的目标架构
  * 加入-mcpu=cpu能指定目标CPU
  * 加入-regalloc=allocator能制定寄存器分配类型
* 将bitcode转回LLVM IR
  * llvm-dis demo.bc -o demo.ll
* 链接LLVM bitcode
  * llvm-link demo.bc demo2.bc -o output.bc
* lli执行bitcode, 当前架构存在JIT的话会用JIT执行否则用解释器. 
* 使用-cc1选项能指定clang只使用cc1编译器前端
* 输出AST: clang -cc1 demo.c -ast-dump
* 使用llgo来获取go语言转换的LLVM IR
  * llgo -dump demo.go
* DragonEgg是一个GCC插件, 能让GCC使用LLVM优化器和代码生成器
  * gcc testprog.c -S -O1 -o - -fplugin=./dragonegg.so
* opt可以指定-O设置优化级别, 使用--debug-pass=Structure可以查看在每个优化级别运行了哪些pass

## 编写LLVM Pass

### 0x01 编写makefile

在llvm lib/Transform目录下编写makefile文件, 指定llvm目录路径, 库名字, 标识模块为可加载

``` makefile
LEVEL = ../../..
LIBRARYNAME = FuncBlockCount
LOADABLE_MODULE = 1
include $(LEVEL)/Makefile.common
```

### 0x02 编写pass代码

``` c++
#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"

// 引入llvm命名空间以使用其中的函数
using namespace llvm;
namespace {
  // 声明Pass
  struct FuncBlockCount : public FunctionPass {
    static char ID; // 声明Pass标识符, 会被LLVM用作识别Pass
    FuncBlockCount() : FunctionPass(ID) {}
    // 实现run函数
    bool runOnFunction(Function &F) override {
      errs()<< "Function "<< F.getName()<< '\n';
      return false;
    }
  };
}
// 初始化Pass ID
char FuncBlockCount::ID = 0;
// 注册Pass, 填写名称和命令行参数
static RegisterPass<FuncBlockCount> X("funcblockcount", 
                                  		"Function Block Count", false, false);
```

使用opt运行新的pass: 

* opt -load (path_to_so_file)/demo.so -funcblockcount demo.ll

## Day82-83: 学习NLP里的命名实体识别模型(NER)

命名实体识别是NLP的一个基础任务, 简单说就是标定词性. 传统的实现方式都是用的LSTM+CRF, CRF是条件随机场的英文缩写. 当然也有用BiLSTM的, 因为是双向,所以能兼顾上下文的语义信息. 

Google在19年发布的BERT模型也能运用在NER里, 能够帮助提升性能, 也是一个新的实现方案. 

NLP有一个框架名为spaCy, 能运用在工业级场景里, 它的底层也大多用的CPython进行编写. 我主要参考它仓库里的example进行训练, 详情参考: [train_ner.py](https://github.com/explosion/spacy/blob/master/examples/training/train_ner.py)

大致的使用方法就是使用内置的`ner`流水线, 然后训练的时候禁用掉其他内置的流水线, 通过多次的迭代训练. 当然除此外还有一些其他的代码, 比如分割训练集/测试集, 对模型进行性能评估之类的一些代码, 在官方的示例中没有体现, 需要自己去实现. 


## Day84: 学习字符串的几种相似度算法的代码

> 参考项目地址: [python-string-similarity](https://github.com/luozhouyang/python-string-similarity)

* Method of four russians 四个俄罗斯人算法
* Levenshtein 编辑距离: 将一个字符串转化成另一个字符串所需要编辑(插入/删除/替换)的最少次数, 使用Wagner-Fischer算法实现, 空间复杂度为O(m), 时间复杂度为O(m*n)
* Normalized Levenshtein: 在Levenshtein基础上除以最长的字符串长度, 以进行归一化. 
* Weighted Levenshtein: 在Levenshtein基础上对不同字符的编辑设置了去不同的权重, 常用于OCR识别, 比如将P替换成R的成本比将P替换成M的成本要低, 因此P跟R是更为相似的. 也可以用于键盘输入的自动纠正, 比如键盘上相邻字符的替换成本更低. 
* Damerau-Levenshtein: 在Levenshtein基础上增加了`交换`操作, 将相邻的两个字符交换位置.
* Optimal String Alignment: 在Damerau–Levenshtein基础上增加了限制条件: no substring is edited more than once, 区别在于对交换操作增加了一个递归.  
* Jaro-Winkler: 最早用于记录重复链接的检测, 适用于短小的字符串比如人名以及检测错别字. 是Damerau-Levenshtein的变种, 其认为相隔距离远的2个字符交换的重要性要比相邻字符的要大.
* Longest Common Subsequence: 最长公共子序列问题在于找到2个或更多序列公共的最长序列. 与查找子字符串不同, 子序列不需要是连续的, 被用于git diff来记录变动. 字符串X(长度n)和Y(长度m)的LCS距离为`n+m-2|LCS(X, Y)|`, 其最小为0, 最大为n+m. 当编辑仅允许插入和删除, 或者替换的成本为插入删除成本的2倍时, LCS距离等同于编辑距离. 通常使用动态规划来实现, 时间复杂度和空间复杂度均为O(n\*m). 也有新的算法能实现O(log(m)\*log(n))的时间复杂度, 但是空间复杂度的要求是O(m\*n^2)
* Metric Longest Common Subsequence: 计算公式 `1 - |LCS(s1, s2)| / max(|s1|, |s2|)`
* N-Gram: 使用\n附加字符来增加首字符的权重. 
* Shingle (n-gram) based algorithms: 将字符串分割成长度为n的序列然后进行处理, 除开直接计算字符串的距离外, 对于大数据机, 还可以对所有字符串进行预处理再计算距离.
  * Q-Gram: 两个字符串的距离为其profile(每个n-gram出现的次数)差异的L1范数: `SUM( |V1_i - V2_i| )`. Q-gram距离是编辑距离的下界, 但可以在O(m+n)的时间复杂度内完成计算. 
  * Cosine similarity: 两个字符串向量表示的夹角的余弦值: `V1 . V2 / (|V1| * |V2|)`, 距离则为`1-cosine`
  * Jaccard index: 将每个字符串都视为n-gram的集合, `|V1 inter V2| / |V1 union V2|`, 距离则为`1-index`
  * Sorensen-Dice coefficient: 类似于jaccard index, 计算公式为: `2 * |V1 inter V2| / (|V1| + |V2|)`, 距离为`1-similarity`
  * Overlap coefficient: 类似jaccard和sorensen-dice: `|V1 inter V2| / Min(|V1|,|V2|)`, 倾向于产生更高的结果.
* SIFT4: 受JaroWinkler和LCS启发的通用字符串距离算法, 希望尽可能地接近人类对弦距离的感知. 
