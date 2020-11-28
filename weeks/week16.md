# Week 16


## Day106: 简略阅读Triton论文和了解源码

## Day107: 阅读QSYM的Python部分源代码


## Day108: 阅读SnoopSnitch源码移植补丁存在性验证代码

> 传送门: [SnoopSnitch](https://opensource.srlabs.de/projects/snoopsnitch)

这是一个安装到用户手机上检测补丁存在性的工具, 但局限性也在此. 我想开发一个无需这样繁琐步骤的工具.


## Day109: 阅读CUPID协同fuzz的论文

> 传送门: [Cupid: Automatic Fuzzer Selection for Collaborative Fuzzing](https://www.ei.ruhr-uni-bochum.de/media/emma/veroeffentlichungen/2020/09/26/ACSAC20-Cupid_TiM9H07.pdf)


## Day110-114: 将SnoopSnich源码进行移植

SnoopSnich的代码写的可能不太好,但是感谢里面有足够的错误处理以及相当规范的命名为我省去不少时间. 我主要关注的是其中的patch分析的部分代码但完全足够,其逻辑很简单, 就是用户安装好app后会收集手机的一些信息(主要是SDK的API等级),然后提交信息给服务器, 服务器在获知后会根据API等级下发不同的测试用例.

测试用例完全公开,我称起为chunk, chunk分为两部分,一个是basictest一个是vulnerable. vuln是为各个CVE建立起来的规则, 针对每一个cve有多个basictest,并且这些多个test的结果会有一定的布尔逻辑进行组合. 只有满足的情况下才能被标记为vulnerable/fixed/notaffected. 

而这些结果依然有一些处理的逻辑在里面, 最后才得出是否存在补丁缺失的结果. 而basictest的种类也非常多样, 当然字符串居多了, 但也有不少是校验值/符号的判断. 虽然是静态的分析方法, 但SRLabs长期的运营对规则进行更新, 所以代码其实还是有模有样的. 

值得一提的是Python的bytes是不可变的，因此在累加的时候每次都会拷贝一个副本，这样会造成极大的开销。所以对应的是使用bytearray来实现。