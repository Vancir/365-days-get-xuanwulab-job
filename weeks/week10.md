# Week 10 



## Day64: 学习LLVM

> 传送门: [LLVM Tutorial](https://llvm.org/docs/tutorial/)


## Day65: 编写脚本自动同步GoSSIP的微信推送归档到Github仓库

> 传送门: [GoSSIP-NewsBot](https://github.com/Vancir/GoSSIP-NewsBot)

理论上可以将任何微信公众号的推送定时更新到Github仓库里


## Day66: 阅读论文 FuzzGen: Automatic Fuzzer Generation

> 论文地址：[link](https://www.usenix.org/conference/usenixsecurity20/presentation/ispoglou)

> 项目地址：[link](https://github.com/HexHive/FuzzGen)


## Day67: 编写脚本检测PyPi包名抢注情况

> 项目地址：[link](https://github.com/Vancir/PyPi-Typosquatting-Graph)

![graph.png](https://raw.githubusercontent.com/Vancir/PyPi-Typosquatting-Graph/master/assets/graph.png)

红色点表示PyPi.org的Top4000的Python包, 且红色点越大表示其下载量越高, 绿色点则表示可疑的抢注包. 

图形主要分为三个层次, 最外层的Python包相对安全, 次外层的Python包有中等风险, 最内层的Python包有高的抢注风险


## Day68: 了解遗传算法并使用geatpy进行参数调优

> 源于朋友的一个问题, 朋友有一个疾病传染模型, 需要使用遗传算法进行参数调优

geatpy是一个国人维护的遗传算法工具箱, 具体的内容参考官方仓库里的 [demo](https://github.com/geatpy-dev/geatpy/tree/master/geatpy/demo)即可. 

1. 主要是确定自己的优化目标, 是进行多目标优化还是单目标优化, 来选择相应的算法模板. 
2. 然后确定自己的参数上下界, 参数之间的约束条件, 优化方向, 填入算法模板就可以了. 
3. 了解了下遗传算法的内容, 顺便也学习/重构了朋友的疾病传染模型.


## Day69-70: 编写macOS的内核扩展监控进程行为

> 仅列举编写时参考的资料, 目前可参考的公开资料很少, 除开参考以下内容外, 还需要更多的参考macOS SDK和开源的xnu的源码

1. [Apple's Technical Note TN2127](https://developer.apple.com/library/archive/technotes/tn2127/_index.html)
2. [Learn How to Build Your Own Utility to Monitor Malicious Behaviors of Malware on macOS](https://www.blackhat.com/us-18/arsenal.html#learn-how-to-build-your-own-utility-to-monitor-malicious-behaviors-of-malware-on-macos)
3. [Kemon: An Open-Source Pre and Post Callback-Based Framework for macOS Kernel Monitoring](https://www.blackhat.com/us-18/arsenal/schedule/#kemon-an-open-source-pre-and-post-callback-based-framework-for-macos-kernel-monitoring-12085)
4. [FireEye: Introducing Monitor.app for macOS](https://www.fireeye.com/blog/threat-research/2017/03/introducing_monitor.html)
5. [Objective-See](https://objective-see.com/blog.html)