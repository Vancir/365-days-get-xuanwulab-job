# Week 6

## Day36: 阅读代码相似性检测论文

> 传送门: [BinMatch: A Semantics-based Hybrid Approach on Binary Code Clone Analysis](https://loccs.sjtu.edu.cn/~romangol/publications/icsme18.pdf)

* 使用测试用例执行模板函数并记录运行时的信息(比如函数参数), 然后将信息迁移到每个候选目标函数并模拟执行, 在执行过程中, 记录模板和目标函数的语义签名. 根据比较模板函数和每个目标函数的签名来计算相似度.
* 语义签名, 包含以下特征
  * 读取和写入的值: 该函数在模拟执行期间从内存读取和写入内存的全局(或静态)变量值组成. 当包含特定输入时, 它会包含函数的输入和输出值, 指示函数的语义
  * 比较操作数值: 由比较操作的值组成. 这些操作的结果决定了模拟执行的后续控制流. 它指示了输入值生成输出的路径. 
  * 标准库函数: 标准库为实现用户定义函数提供了基本的函数. 这个特征已被证实跟语义相关, 并对代码克隆分析有效.
* 插装和执行
  * 通过分析汇编, 在语义特征位置处插入代码以获取和生成函数特征. 
  * 同时记录运行时的信息, 比如函数参数, 调用函数地址, 返回值等
* 模拟执行: 相似的函数在相同输入的情况下行为也应当是一致的.
  * 函数参数分配: 克隆函数具有相同的参数数量. 因此在执行时确定函数数量, 数量一致再根据调用约定填入参数
  * 全局变量读取: 不仅要迁移到相同的全局变量, 还要保证全局变量的使用顺序一致. 如果没有足够的全局变量值进行分配, 使用预定义的0xdeadbeef
  * 间接调用/跳转: 通过确认模拟执行期间的调用目标来判断是否是克隆函数. 跳转表保存在.rodata里
  * 标准库函数调用: 记录库函数调用的返回值, 模拟时直接返回就不去执行了. 
  * 使用LCS(最长公共子序列)算法进行相似性测量, 而相似度分数则使用Jaccard Index来衡量.
* 实现: 使用IDA来获取基本块信息, 使用Valgrind进行插装, 基于angr进行模拟执行. 因为签名的内存占用很高, 所以使用Hirschberg算法进行实现LCS, 该算法有着可观的内存占用复杂度. 

> 传送门: [αDiff: Cross-Version Binary Code Similarity Detection with DNN](https://dl.acm.org/doi/pdf/10.1145/3238147.3238199?download=true)

* 提取了3个语义特征: 函数代码特征(函数内), 函数调用特征(函数间)和模块交互特征(模块间). 输入函数的原始字节值给CNN进行训练将其转换成一个embedding(也就是向量), 然后加入到暹罗网络中去. 其次, 在提取函数间特征的时候, 出于性能考虑, 仅提取了调用图中函数节点的入度和出度作为函数特征. 第三, 分析每个函数的导入函数(imports)并将其用作模块间特征, 并设计算法将其嵌入为一个向量来计算距离. 

## Day37: 阅读代码相似性检测论文

> 传送门: [Binary Similarity Detection Using Machine Learning](https://dl.acm.org/doi/10.1145/3264820.3264821)

* 基于并行机器学习的组成原理的相似性, 提出了proc2vec的方法, 将过程(或代码段)表示为向量. proc2vec会将每个过程分解小的段, 将每个段转换为规范形式, 并将其文本表示形式转换成数字, 从而将每个过程转换成向量空间里的embedding. 
* 基于之前统计方法里的`strand`概念, `strand`是代码块中计算某个变量的值所需要的一组指令.
* prov2vec:
  1. 将过程切分成基本块.  
  2. 将基本块切分成strand
  3. 语义相同但语法不同的strand则会转换成相同的文本表示
  4. 使用b-bit MD5哈希算法将文本表示进行处理. ? 迷惑行为, 哈希之后还算什么语义?
  5. 使用哈希值组成向量输入给神经网络.

> 传送门: [VulSeeker: A Semantic Learning Based Vulnerability Seeker for Cross-platform Binary](https://dl.acm.org/doi/10.1145/3238147.3240480)

* VulSeeker, 基于语义学习的跨平台二进制漏洞查找程序. 给定目标函数和易受攻击的函数, VulSeeker首先构造`标记语义流图(LSFG)`(labeled semantic flow graph)并提取基本块特征作为这两个函数的数值向量, 然后将数值变量输入给定制的DNN模型, 生成嵌入向量. 然后基于余弦距离计算两个二进制函数的相似性. 
* LSFG就是结合了CFG和DFG的简化图. 另外提取了8种特征并将其编码组成向量: 栈操作指令数量, 算术指令数量, 逻辑指令数量, 比较指令数量, 库函数调用指令数量, 无条件跳转指令数量, 有条件跳转指令数量, 通用指令数量. 

## Day38: 阅读代码相似性检测论文

> 传送门: [FirmUp: Precise Static Detection of Common Vulnerabilities in Firmware](https://dl.acm.org/doi/10.1145/3296957.3177157)

* 现代二进制程序会需要适应不同的环境和需求进行构建, 从而导致功能上的巨大差异, 比如wget可以在支持/不支持SSL的情况下分别编译, 而cURL也可以在不支持cookie的情况下编译. 这会导致结构上的巨大差异, 并阻碍了达到完全同构的可能. 
1. 在统计篇的基础上, 进一步改进了strand. 
2. 将过程相似性扩展到过程外去观察相邻的过程. 这是实践观察的经验, 观察到过程始终在程序内部进行操作, 因此几乎总是会和相邻的某些过程一起出现. 使用相邻过程的信息可以提高准确性
3. 优化了匹配过程. 受往复博弈(back-and-forth games)的启发, 但匹配的集合非常大(但不是无限)时, 该博弈能更有效低替代全匹配算法. 

> 传送门: [FOSSIL: A Resilient and Efficient System for Identifying FOSS Functions in Malware Binaries](https://dl.acm.org/doi/10.1145/3175492)

* FOSSIL: 包含三部分, 1. 使用隐式马尔科夫链模型统计操作码频率以此来作为函数的句法特征. 2. 应用领域哈希图在CFG上进行随机游走, 以提取函数的语义特征. 3. 使用`z-score`对指令进行规范化, 以提取指令的行为. 然后将这三部分组件使用贝叶斯网络模型整合在一起, 对结果进行综合评估来检测开源软件函数. 
* 汇编指令的规范化: 将常量值和内存应用规范化为V和M来表示. 而寄存器的规范化可以分级别, 比如将所有寄存器都用REG表示, 或者只区分通用寄存器/段寄存器/索引/指针寄存器等, 或者用寄存器的大小分为3类: 32/16/8位寄存器.
* 在CFG上进行随机游走以获得路径序列, 找到两个基本块节点之间的最短路径. 

## Day39: 阅读代码相似性检测论文

> 传送门: [Beyond Precision and Recall: Understanding Uses (and Misuses) of Similarity Hashes in Binary Analysis](https://dl.acm.org/doi/10.1145/3176258.3176306)

* Context-Triggered Piecewise Hashing: CTPH通过局部的相似来推测文件的相似, LBFS通过计算n字节上下文的滑窗进行哈希, 确保插入或删除短字符串仅会更改哈希的几个文件块而其余保持不变. 
* Statistically Improbable Features: sdhash能够寻找统计上的特异字节序列(特征), 比如较长但不寻常的某一共同字符串.
* N-grams: 相似的文件具有相似的n-gram频率分布.  
* 实验表明tlsh和sdhash始终优于ssdeep.

> 传送门: [BCD: Decomposing Binary Code Into Components Using Graph-Based Clustering](https://dl.acm.org/doi/10.1145/3196494.3196504)

* 将binary分解为组件图, 节点为函数, 边表征三种关系: 代码局部性, 数据引用, 函数调用. 然后实验图论方法将函数划分为不相关的组件. 
* Code locality to sequence graph (SG): 程序员开发时会将结构相关的函数放在源代码彼此相近的位置. 
* Data references to data-reference graph (DRG): 处理相同数据的函数更有可能是结构相关的, 因为它们都有相同的数据语义. BCD通过访问相同变量的函数之间添加边来构造数据引用图. 只关注静态数据, 全局变量和字符串. 
* Function calls to call graph (CG): 两个函数之间的调用次数越多, 它们的结构关系越强, 也就增加相应的边的权重

## Day40: 阅读代码相似性检测论文

> 传送门: [Binary code clone detection across architectures and compiling configurations](https://dl.acm.org/doi/10.1109/ICPC.2017.22)

* 将目标与每个模板函数进行比较, 找到最相似的函数. 
* 首先识别函数传递的参数以及switch语句的可能跳转目标. 然后通过IR将不同架构的bianry统一表示起来, 并模拟这些二进制的执行以提取语义签名. 最后, 计算每个模板函数与每个目标函数的相似性分数, 返回分数排序的匹配函数列表. 
* 处理流程: 反汇编二进制代码, 生成CFG, 收集CFG里基本块和边的信息. 然后遍历CFG以识别执行函数所需的参数, 收集所有可能的间接跳转地址(switch语句). 将二进制转换成IR, 接下来, 使用参数和switch的信息, 将IR形式的函数模拟执行起来, 用于生成语义签名.  最后将每个目标函数的签名与模板函数进行比较, 得到相似函数列表. 
  
> 传送门: [Benchmarks for software clone detection: A ten-year retrospective](https://ieeexplore.ieee.org/document/8330194)

> 传送门: [The adverse effects of code duplication in machine learning models of code](https://dl.acm.org/doi/pdf/10.1145/3359591.3359735)

* 论文主要在测量代码重复在机器学习模型中造成的副作用. 代码重复是指大量的几乎没有差别的重复代码片段. 
* 代码重复的问题在于实践中, 研究人员很少通过直接观察其训练模型的结果造成的, 相反常见的作法是将数据集分为两部分, 一部分用作训练一部分用来做测试. 但由于重复数据集的分布方式和非重复数据集的分布方式不同, 因此机器学习模型将学习不同的概率分布进行建模. 而机器学习里的一个重要的假设就是, 每个数据点都必须独立且在使用的数据集上具有等同的分布. 因此在许多机器学习代码检测代码相似的模型里都严重违反了该原则. 
* 三种类型的代码重复: 
  * in-train duplicates: 在训练集里的重复文件
  * in-test duplicates: 在测试集里的重复文件
  * cross-set duplicate: 训练集和测试集均出现的重复文件
* 论文通过修改SourcererCC代码, 对文件进行精确匹配. 而对于那些只有微量改动的重复文件, 则通过构建指纹(标识符和文字), 计算jaccard距离超过阈值(0.7和0.8), 来检测这种重复文件(此外指纹数量少的文件也会直接忽略掉). 

## Day41: 安装和了解Unicorn框架和示例代码

* 安装: `UNICORN_ARCHS="arm aarch64 x86" ./make.sh ; sudo ./make.sh install`. 安装Python binding: `pip install unicorn`
* CPU模拟执行的原理:
  * 给定二进制文件, 将二进制解码成单独的指令
  * 对每一条指令进行模拟, 需要解决ISA引用和内存访问&I/O请求
  * 执行指令更新CPU的上下文(寄存器/内存/等等)
* showcase里的代码释义:
  * `mu = Uc(UC_ARCH_X86, UC_MODE_32)`: 初始化模拟器为x86_32模式
  * `mu.mem_map(ADDRESS, 2 * 1024 * 1024)`: 映射2MB内存用于模拟, Address是模拟的起始内存地址
  * `mu.mem_write(ADDRESS, X86_CODE32)`: 将机器码写入到起始地址内存中
  * `mu.reg_write(UC_X86_REG_ECX, 0x1234)`: 设置寄存器的初始值, 这里是ECX寄存器
  * `mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE32))`: 开始模拟, 参数为内存起始和结束地址
  * `mu.reg_read(UC_X86_REG_ECX)`: 读取寄存器的值
* 阅读仓库内的Python示例代码: [传送门](https://github.com/unicorn-engine/unicorn/blob/master/bindings/python/README.TXT)
  * `mu.hook_add(UC_HOOK_BLOCK, hook_block)`: 添加一个hook, 第一个参数是hook类型, 第二个参数是hook后的回调函数.

## Day42-43: 安装配置Manjaro+i3wm桌面环境

以下是我安装完Manjaro-i3后的配置记录. 我的配置文件存放在: [dotfiles](https://github.com/Vancir/dotfiles)

* 0x01 添加国内源

``` bash
sudo pacman-mirrors -i -c China -m rank
# 选择清华和中科大的源
sudo vim /etc/pacman.conf
## 填入以下内容
[archlinuxcn]
SigLevel = Optional TrustedOnly
Server = https://mirrors.ustc.edu.cn/archlinuxcn/$arch
Server = http://mirrors.tuna.tsinghua.edu.cn/archlinuxcn/$arch

[antergos]
SigLevel = TrustAll
Server = http://mirrors.tuna.tsinghua.edu.cn/antergos/$repo/$arch

[arch4edu]
SigLevel = TrustAll
Server = http://mirrors.tuna.tsinghua.edu.cn/arch4edu/$arch
# 将Color的注释删去

# 运行以下命令进行更新
sudo pacman -Syy
# 导入GPG
sudo pacman -S archlinuxcn-keyring 
sudo pacman -S antergos-keyring
# 更新系统
sudo pacman -Syu
```

* 0x02 安装常用CLI工具及软件

``` bash
sudo pacman -S yay git firefox netease-cloud-music screenkey tmux aria2 google-chrome feh rofi polybar betterlockscreen pywal-git imagemagick thefuck visual-studio-code-bin intellij-idea-ultimate-edition lxappearance deepin-wine-tim deepin-wine-wechat dolphin redshift deepin-screenshot foxitreader p7zip the_silver_searcher tig wps-office ttf-wps-fonts mpv
```

* 0x03 安装设置Rime输入法

``` bash
yay -S fcitx fcitx-im fcitx-configtool fcitx-rime
# 设置环境变量asd
vim ~/.xprofile
## 填入以下内容
export GTK_IM_MODULE=fcitx
export QT_IM_MODULE=fcitx
export XMODIFIERS=@im=fcitx
# 重新启动/重新登录
sudo reboot
# 填写rime输入法的配置文件
vim ~/.config/fcitx/rime/default.custom.yaml
## 填入以下内容重新部署rime/重启fcitx即可生效
patch:
  schema_list:
    - schema: luna_pinyin_simp
    
  "ascii_composer/switch_key":
    Caps_Lock: noop
    Shift_L: commit_code 
    Shift_R: inline_ascii

  "punctuator/full_shape":
    "/": "/"
  "punctuator/half_shape":
    "/": "/"

  "menu/page_size": 9
# 编辑~/.i3/config文件填入下面这行
exec_always --no-startup-id fcitx
```


* 0x04 解决音频输出的问题

``` bash
yay -S pulseaudio pavucontrol
pulseaudio --start
# 打开pavucontrol配合alsamixer将音量调高
# 然后右键下方状态栏最右边的声音按钮, 将输出调为耳机
```

* 0x05 配置NeoVim

``` bash
yay -S neovim
# 安装vim-plug插件. 
sh -c 'curl -fLo "${XDG_DATA_HOME:-$HOME/.local/share}"/nvim/site/autoload/plug.vim --create-dirs \
       https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim'

# 将我的neovim配置复制到~/.config目录下
# 打开neovim执行 :PlugInstall 
```

* 0x06 配置Fish Shell

``` bash
yay -S fish
chsh -s /usr/bin/fish
# 挑一个喜欢的配色和提示符
fish_config 
```

* 0x07 配置ZSH Shell

``` bash
yay -S zsh
# 安装oh my zsh
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
# 安装插件
git clone git://github.com/zsh-users/zsh-autosuggestions $ZSH_CUSTOM/plugins/zsh-autosuggestions
git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting
# 编辑~/.zshrc
ZSH_SHELL="steeef"
plugins=(
	git
	zsh-autosuggestions
	zsh-syntax-highlighting
	z
	extract
	colored-man-pages
	fzf
)
# 修改提示符的样式
PROMPT=$'
%{$purple%}#${PR_RST} %{$orange%}%n${PR_RST} %{$purple%}@${PR_RST} %{$orange%}%m${PR_RST} in %{$limegreen%}%~${PR_RST} %{$limegreen%}$pr_24h_clock${PR_RST} $vcs_info_msg_0_$(virtualenv_info)
%{$hotpink%}$ ${PR_RST}'
```

* 0x08 安装终端软件alacritty

``` bash
yay -S alacritty
vim ~/.config/i3/config
# 将终端修改为alacritty
```

* 设置ZSH配置

``` bash
alias c clear
alias aria2c aira2c -s16 -x16
alias setproxy="export ALL_PROXY=XXXXXXX"
alias unsetproxy="unset ALL_PROXY"
alias ip='curl ip.sb'
alias grep='grep --color=auto'
alias ra='ranger'
```

* 安装字体图标主题等

``` bash
yay -S papirus-icon-theme wqy-microhei ttf-font-awesome

yay -S ttf-linux-libertine ttf-inconsolata ttf-joypixels ttf-twemoji-color noto-fonts-emoji ttf-liberation ttf-droid ttf-fira-code adobe-source-code-pro-fonts

yay -S wqy-bitmapfont wqy-microhei wqy-microhei-lite wqy-zenhei adobe-source-han-mono-cn-fonts adobe-source-han-sans-cn-fonts adobe-source-han-serif-cn-fonts
```

*  配置Rofi

``` bash
yay -S pywal-git
mkdir -p ~/.config/wal/templates
# 使用https://github.com/ameyrk99/no-mans-sky-rice-i3wm里的.i3/rofi.rasi放置在templates目录下
# 并重命名为config.rasi
# 编辑~/.i3/config将mod+d由dmeun修改为rofi
bindsym $mod+d exec rofi -show run
```

* 同步时间

``` bash
sudo hwclock --systohc
sudo ntpdate -u ntp.api.bz
```

* 调准鼠标滚轮速度

``` bash
yay -S imwheel
vim ~/.imwheelrc
# 填入以下内容
".*"
None,      Up,   Button4, 4
None,      Down, Button5, 4
Control_L, Up,   Control_L|Button4
Control_L, Down, Control_L|Button5
Shift_L,   Up,   Shift_L|Button4
Shift_L,   Down, Shift_L|Button5
# 将imwheel写到i3的配置里自动启动, 或者直接执行imwheel也行
imwheel
```

* 配置compton毛玻璃特效

``` bash
# manjaro i3自带compton, 但是该版本只能半透明而无法实现毛玻璃特效
# 我们需要使用另一个分支版的compton
# 卸载预装的compton
yay -Rc picom
# 需要安装asciidoc
yay -S asciidoc
git clone https://github.com/tryone144/compton
cd compton
make 
sudo make install
# 编辑 ~/.config/compton.conf里的opacity
```

* 配置polybar

把配置文件放进去将可以

* 安装WPS

``` bash
sudo pacman -S wps-office
sudo pacman -S ttf-wps-fonts
sudo vim /usr/bin/wps
# 在shebang下面填入
export XMODIFIERS="@im=fcitx"
export QT_IM_MODULE="fcitx"
```
