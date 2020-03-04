# [所有收集类项目](https://github.com/alphaSeclab/all-my-collection-repos)




# DBI


- 跟DBI（Dynamic Binary Instrumentation：动态二进制插桩）逆向有关的资源收集
- [English Version](https://github.com/alphaSeclab/DBI-Stuff/blob/master/Readme_en.md)



# 目录
- [DynamoRIO](#c8cdb0e30f24e9b7394fcd5681f2e419)
    - [DrMemory](#f96730347d78912b366704c9b2fe2b66) ->  [(1)工具](#cd99303796122728f8218787dbf97cbb) [(2)文章](#23907044ce4485548fab953ba46b31dc)
    - [工具](#6c4841dd91cb173093ea2c8d0b557e71)
        - [(9) 新添加的](#ff0abe26a37095f6575195950e0b7f94)
        - [(3) 与其他工具交互](#928642a55eff34b6b52622c6862addd2)
        - [(1) DynamoRIO](#3a912a81e4f71ce722b2ed4b7d64c6c7)
    - [文章](#9479ce9f475e4b9faa4497924a2e40fc)
        - [(4) 新添加](#ecf6662d8b6c6dcdab85873f937fcfc5)
        - [(6) 工具介绍](#8f8764c324010fe81f3bf2bbb16b4203)
        - [(2) Fuzzing](#c0c4356a0f343699ac548228a9cbf901)
- [IntelPin](#7b8a493ca344f41887792fcc008573e7)
    - [工具](#fe5a6d7f16890542c9e60857706edfde)
        - [(19) 新添加的](#78a2edf9aa41eb321436cb150ea70a54)
        - [(8) 其他工具交互](#95adfd425a416ee2a5c48bc1132b5655)
    - [(7) 文章](#226190bea6ceb98ee5e2b939a6515fac)
- [Frida](#f24f1235fd45a1aa8d280eff1f03af7e)
    - [工具](#a5336a0f9e8e55111bda45c8d74924c1)
        - [(1) Frida](#6d3c24e43835420063f9ca50ba805f15)
        - [(128) 新添加的](#54836a155de0c15b56f43634cd9cfecf)
        - [(7) 其他工具交互](#f0b89493b077b82fb0b10fc56fca9faf)
    - [(108) 文章](#a1a7e3dd7091b47384c75dba8f279caf)
- [Valgrind](#8abff248f7dd0b63fde24de6fc9a87b8) ->  [(9)工具](#c5b612f014bbeb313c6e2b80cc5cafe3) [(6)文章](#ac878aff7e9b69738d83059912f2ba07)
- [QBDI](#b2fca17481b109a9b3b0bc290a1a1381) ->  [(1)工具](#e72b766bcd3b868c438a372bc365221e) [(6)文章](#2cf79f93baf02a24d95d227a0a3049d8)
- [ADBI](#8e50e0c1c90258367f1095c61a7f4b82) ->  [(2)工具](#74096de3c5933b67a9fe313f1afbbb6a) [(2)文章](#e39eb06761c41f7534a142e5ffb1dcc4)
- [DBA](#6f79d6b2aa9f3d2daa8629c565f44269)
    - [Triton](#c9b96059b34d508fdb2c202895518fbd) ->  [(6)工具](#1dd4818bf0c90f6c2244362dc1ae1d89) [(13)文章](#c941c67d2b508750b93e88709fd02ebf)
    - [Manticore](#6926f94dd30bc88e4dc975e56f0323dc) ->  [(2)工具](#9d452bb3dd68a493fb3c20a9d884dd38) [(6)文章](#aa7c141a83254ef421b081143f4a0f9f)
    - [(2) 工具](#86fb610cf955224352160b14171bfa86)
    - [(1) 文章](#b6c6d6f1813166e14d971dd448a3f158)
- [其他](#5a9974bfcf7cdf9b05fe7a7dc5272213) ->  [(10)工具](#104bc99e36692f133ba70475ebc8825f) [(6)文章](#8f1b9c5c2737493524809684b934d49a)


# <a id="c8cdb0e30f24e9b7394fcd5681f2e419"></a>DynamoRIO


***


## <a id="f96730347d78912b366704c9b2fe2b66"></a>DrMemory


### <a id="cd99303796122728f8218787dbf97cbb"></a>工具


- [**1425**星][23d] [C] [dynamorio/drmemory](https://github.com/dynamorio/drmemory) Memory Debugger for Windows, Linux, Mac, and Android


### <a id="23907044ce4485548fab953ba46b31dc"></a>文章


- 2016.09 [securitygossip] [Practical Memory Checking With Dr. Memory](http://securitygossip.com/blog/2016/09/12/2016-09-12/)
- 2014.01 [dustri] [Memory debugging under Windows with drmemory](https://dustri.org/b/memory-debugging-under-windows-with-drmemory.html)




***


## <a id="6c4841dd91cb173093ea2c8d0b557e71"></a>工具


### <a id="3a912a81e4f71ce722b2ed4b7d64c6c7"></a>DynamoRIO


- [**1265**星][23d] [C] [dynamorio/dynamorio](https://github.com/dynamorio/dynamorio) Dynamic Instrumentation Tool Platform


### <a id="ff0abe26a37095f6575195950e0b7f94"></a>新添加的


- [**1394**星][22d] [C] [googleprojectzero/winafl](https://github.com/googleprojectzero/winafl) A fork of AFL for fuzzing Windows binaries
- [**253**星][7m] [C] [ampotos/dynstruct](https://github.com/ampotos/dynstruct) Reverse engineering tool for automatic structure recovering and memory use analysis based on DynamoRIO and Capstone
- [**123**星][6m] [C++] [googleprojectzero/drsancov](https://github.com/googleprojectzero/drsancov) DynamoRIO plugin to get ASAN and SanitizerCoverage compatible output for closed-source executables
- [**119**星][5y] [C++] [breakingmalware/selfie](https://github.com/breakingmalware/selfie) 对自修改代码进行脱壳
- [**53**星][4y] [C] [lgeek/dynamorio_pin_escape](https://github.com/lgeek/dynamorio_pin_escape) DynamoRIO 和Intel Pin分析环境逃逸
- [**37**星][1m] [Py] [oddcoder/cutterdrcov](https://github.com/oddcoder/cutterdrcov) DynamoRIO coverage visualization for cutter
- [**17**星][3m] [C] [firodj/bbtrace](https://github.com/firodj/bbtrace) 记录bbtrace
- [**14**星][1m] [C++] [vanhauser-thc/afl-dynamorio](https://github.com/vanhauser-thc/afl-dynamorio) run AFL with dynamorio
- [**10**星][3y] [C++] [atrosinenko/afl-dr](https://github.com/atrosinenko/afl-dr) Experiment in implementation of an instrumentation for American Fuzzy Lop using DynamoRIO


### <a id="928642a55eff34b6b52622c6862addd2"></a>与其他工具交互


- [**52**星][1y] [Py] [cisco-talos/dyndataresolver](https://github.com/cisco-talos/dyndataresolver) 动态数据解析. 在IDA中控制DyRIO执行程序的指定部分, 记录执行过程后传回数据到IDA
    - [DDR](https://github.com/cisco-talos/dyndataresolver/blob/master/VS_project/ddr/ddr.sln) 基于DyRIO的Client
    - [IDA插件](https://github.com/cisco-talos/dyndataresolver/tree/master/IDAplugin) 
- [**20**星][11m] [C++] [secrary/findloop](https://github.com/secrary/findloop) 使用DyRIO查找执行次数过多的代码块
- [**7**星][3y] [C++] [ncatlin/drgat](https://github.com/ncatlin/drgat) The DynamoRIO client for rgat




***


## <a id="9479ce9f475e4b9faa4497924a2e40fc"></a>文章


### <a id="ecf6662d8b6c6dcdab85873f937fcfc5"></a>新添加


- 2018.07 [topsec] [动态二进制插装入门：Pin、DynamoRIO、Frida](http://blog.topsec.com.cn/%e5%8a%a8%e6%80%81%e4%ba%8c%e8%bf%9b%e5%88%b6%e4%bf%ae%e6%94%b9dynamic-binary-instrumentation%e5%85%a5%e9%97%a8%ef%bc%9apin%e3%80%81dynamorio%e3%80%81frida/)
- 2016.08 [n0where] [Dynamic Instrumentation Tool Platform: DynamoRIO](https://n0where.net/dynamic-instrumentation-tool-platform-dynamorio)
- 2012.10 [redplait] [building dynamorio](http://redplait.blogspot.com/2012/10/building-dynamorio.html)
- 2011.06 [redplait] [dynamorio](http://redplait.blogspot.com/2011/06/dynamorio.html)


### <a id="8f8764c324010fe81f3bf2bbb16b4203"></a>工具介绍


- 2019.10 [freebuf] [DrSemu：基于动态行为的恶意软件检测与分类工具](https://www.freebuf.com/sectool/214277.html)
- 2019.06 [freebuf] [Functrace：使用DynamoRIO追踪函数调用](https://www.freebuf.com/sectool/205989.html)
- 2019.01 [360] [深入浅出——基于DynamoRIO的strace和ltrace](https://www.anquanke.com/post/id/169257/)
- 2018.08 [n0where] [Dynamic API Call Tracer for Windows and Linux Applications: Drltrace](https://n0where.net/dynamic-api-call-tracer-for-windows-and-linux-applications-drltrace)
- 2017.04 [pediy] [[原创]通过Selife学习使用DynamoRIO动态插桩](https://bbs.pediy.com/thread-216970.htm)
- 2016.11 [360] [“Selfie”：利用DynamoRIO实现自修改代码自动脱壳的神器](https://www.anquanke.com/post/id/84999/)


### <a id="c0c4356a0f343699ac548228a9cbf901"></a>Fuzzing


- 2017.11 [SECConsult] [The Art of Fuzzing - Demo 10: In-memory Fuzzing HashCalc using DynamoRio](https://www.youtube.com/watch?v=FEJGlgBeUJ8)
- 2017.11 [SECConsult] [The Art of Fuzzing - Demo 6: Extract Coverage Information using DynamoRio](https://www.youtube.com/watch?v=Ur_E9c2vX1A)




# <a id="7b8a493ca344f41887792fcc008573e7"></a>IntelPin


***


## <a id="fe5a6d7f16890542c9e60857706edfde"></a>工具


### <a id="78a2edf9aa41eb321436cb150ea70a54"></a>新添加的


- [**427**星][5y] [C++] [jonathansalwan/pintools](https://github.com/jonathansalwan/pintools) Pintool example and PoC for dynamic binary analysis
- [**306**星][4m] [C] [vusec/vuzzer](https://github.com/vusec/vuzzer) depends heavily on a modeified version of DataTracker, which in turn depends on LibDFT pintool.
- [**148**星][6y] [C++] [f-secure/sulo](https://github.com/f-secure/sulo) Dynamic instrumentation tool for Adobe Flash Player built on Intel Pin
- [**131**星][8m] [C++] [hasherezade/tiny_tracer](https://github.com/hasherezade/tiny_tracer) A Pin Tool for tracing API calls etc
- [**67**星][3y] [C++] [m000/dtracker](https://github.com/m000/dtracker) DataTracker: A Pin tool for collecting high-fidelity data provenance from unmodified programs.
- [**60**星][3y] [C++] [hasherezade/mypintools](https://github.com/hasherezade/mypintools) Tools to run with Intel PIN
- [**50**星][11m] [C++] [angorafuzzer/libdft64](https://github.com/angorafuzzer/libdft64) libdft for Intel Pin 3.x and 64 bit platform. (Dynamic taint tracking, taint analysis)
- [**48**星][7y] [C++] [cr4sh/code-coverage-analysis-tools](https://github.com/cr4sh/code-coverage-analysis-tools) Code coverage analysis tools for the PIN Toolkit
- [**42**星][4y] [C++] [corelan/pin](https://github.com/corelan/pin) Collection of pin tools
- [**36**星][4y] [C++] [paulmehta/ablation](https://github.com/paulmehta/ablation) Augmenting Static Analysis Using Pintool: Ablation
- [**30**星][5y] [C++] [0xddaa/pin](https://github.com/0xddaa/pin) Use Intel Pin tools to analysis binary.
- [**30**星][7y] [C++] [jingpu/pintools](https://github.com/jingpu/pintools) 
- [**28**星][1y] [C++] [fdiskyou/winalloctracer](https://github.com/fdiskyou/WinAllocTracer) Pintool that logs and tracks calls to RtlAllocateHeap, RtlReAllocateHeap, RtlFreeHeap, VirtualAllocEx, and VirtualFreeEx.
- [**26**星][5m] [C++] [boegel/mica](https://github.com/boegel/mica) a Pin tool for collecting microarchitecture-independent workload characteristics
- [**22**星][6y] [C++] [jbremer/pyn](https://github.com/jbremer/pyn) Awesome Python bindings for Pintool
- [**18**星][7m] [bash-c/pin-in-ctf](https://github.com/bash-c/pin-in-ctf) 使用intel pin来求解一部分CTF challenge
- [**13**星][3y] [C++] [netspi/pin](https://github.com/netspi/pin) Intel pin tools
- [**6**星][2y] [C++] [spinpx/afl_pin_mode](https://github.com/spinpx/afl_pin_mode) Yet another AFL instrumentation tool implemented by Intel Pin.
- [**0**星][6m] [Makefile] [barkhat26/pintool-template](https://github.com/barkhat26/pintool-template) PinTool template for Intel Pin 3.11 compatible with VS2019


### <a id="95adfd425a416ee2a5c48bc1132b5655"></a>其他工具交互


- [**971**星][1y] [Py] [gaasedelen/lighthouse](https://github.com/gaasedelen/lighthouse) 从DBI中收集代码覆盖情况，在IDA/Binja中映射、浏览、查看
    - 重复区段: [Frida->工具->其他工具交互](#f0b89493b077b82fb0b10fc56fca9faf) |
    - [coverage-frida](https://github.com/gaasedelen/lighthouse/blob/master/coverage/frida/README.md) 使用Frida收集信息
    - [coverage-pin](https://github.com/gaasedelen/lighthouse/blob/master/coverage/pin/README.md) 使用Pin收集覆盖信息
    - [插件](https://github.com/gaasedelen/lighthouse/blob/master/plugin/lighthouse_plugin.py) 支持IDA和BinNinja
- [**134**星][1y] [Py] [carlosgprado/jarvis](https://github.com/carlosgprado/jarvis) 多功能, 带界面,辅助静态分析、漏洞挖掘、动态追踪(Pin)、导入导出等
    - [IDA插件](https://github.com/carlosgprado/jarvis/tree/master/IDAPlugin) 
    - [PinTracer](https://github.com/carlosgprado/jarvis/tree/master/PinTracer) 
- [**122**星][5y] [C++] [zachriggle/ida-splode](https://github.com/zachriggle/ida-splode) 使用Pin收集动态运行数据, 导入到IDA中查看
    - [IDA插件](https://github.com/zachriggle/ida-splode/tree/master/py) 
    - [PinTool](https://github.com/zachriggle/ida-splode/tree/master/src) 
- [**118**星][2y] [C++] [0xphoenix/mazewalker](https://github.com/0xphoenix/mazewalker) 使用Pin收集数据，导入到IDA中查看
    - [mazeui](https://github.com/0xphoenix/mazewalker/blob/master/MazeUI/mazeui.py) 在IDA中显示界面
    - [PyScripts](https://github.com/0xPhoeniX/MazeWalker/tree/master/MazeTracer/PyScripts) Python脚本，处理收集到的数据
    - [PinClient](https://github.com/0xPhoeniX/MazeWalker/tree/master/MazeTracer/src) 
- [**104**星][6m] [Java] [0ffffffffh/dragondance](https://github.com/0ffffffffh/dragondance) 在Ghidra中进行代码覆盖情况的可视化
    - [Ghidra插件](https://github.com/0ffffffffh/dragondance/blob/master/README.md) 
    - [coverage-pin](https://github.com/0ffffffffh/dragondance/blob/master/coveragetools/README.md) 使用Pin收集信息
- [**93**星][8y] [C] [neuroo/runtime-tracer](https://github.com/neuroo/runtime-tracer) 使用Pin收集运行数据并在IDA中显示
    - [PinTool](https://github.com/neuroo/runtime-tracer/tree/master/tracer) 
    - [IDA插件](https://github.com/neuroo/runtime-tracer/tree/master/ida-pin) 
- [**44**星][3y] [Batchfile] [maldiohead/idapin](https://github.com/maldiohead/idapin) plugin of ida with pin
- [**17**星][1y] [C++] [agustingianni/instrumentation](https://github.com/agustingianni/instrumentation) PinTool收集。收集数据可导入到IDA中
    - [CodeCoverage](https://github.com/agustingianni/instrumentation/tree/master/CodeCoverage) 
    - [Pinnacle](https://github.com/agustingianni/instrumentation/tree/master/Pinnacle) 
    - [Recoverer](https://github.com/agustingianni/instrumentation/tree/master/Recoverer) 
    - [Resolver](https://github.com/agustingianni/instrumentation/tree/master/Resolver) 




***


## <a id="226190bea6ceb98ee5e2b939a6515fac"></a>文章


- 2019.10 [HackersOnBoard] [Black Hat USA 2016 Pindemonium A DBI Based Generic Unpacker for Windows Executable](https://www.youtube.com/watch?v=y4UyS0MGOds)
- 2019.08 [codingvision] [Hot Patching C/C++ Functions with Intel Pin](https://codingvision.net/security/hot-patching-functions-with-intel-pin)
- 2017.07 [gironsec] [Intel PIN, Cheatz, Hax, And Detection Part 2](https://www.gironsec.com/blog/2017/07/intel-pin-cheatz-hax-and-detection-part-2/)
- 2017.05 [netspi] [Dynamic Binary Analysis with Intel Pin](https://blog.netspi.com/dynamic-binary-analysis-intel-pin/)
- 2016.12 [gironsec] [Intel PIN, Cheatz, Hax, And Detection Part 1](https://www.gironsec.com/blog/2016/12/intel-pin-cheatz-hax-and-detection-part-1/)
- 2016.09 [zubcic] [Fixing Intel PIN  Visual Studio project files](http://zubcic.re/blog/fixing-intel-pin-visual-studio-project-files)
- 2014.11 [portcullis] [Using Intel Pin tools for binary instrumentation](https://labs.portcullis.co.uk/blog/using-intel-pin-tools-for-binary-instrumentation/)


# <a id="f24f1235fd45a1aa8d280eff1f03af7e"></a>Frida


***


## <a id="a5336a0f9e8e55111bda45c8d74924c1"></a>工具


### <a id="6d3c24e43835420063f9ca50ba805f15"></a>Frida


- [**4721**星][1m] [Makefile] [frida/frida](https://github.com/frida/frida) Clone this repo to build Frida


### <a id="54836a155de0c15b56f43634cd9cfecf"></a>新添加的


- [**2176**星][22d] [Py] [sensepost/objection](https://github.com/sensepost/objection) runtimemobile exploration
- [**1306**星][4m] [Vue] [chaitin/passionfruit](https://github.com/chaitin/passionfruit) iOSapp 黑盒评估工具。功能丰富，自带基于web的 GUI
- [**1259**星][3m] [dweinstein/awesome-frida](https://github.com/dweinstein/awesome-frida) frida 资源列表
- [**1256**星][2m] [JS] [alonemonkey/frida-ios-dump](https://github.com/alonemonkey/frida-ios-dump) pull decrypted ipa from jailbreak device
- [**988**星][4m] [HTML] [hookmaster/frida-all-in-one](https://github.com/hookmaster/frida-all-in-one) FRIDA操作手册
- [**926**星][7m] [JS] [dpnishant/appmon](https://github.com/dpnishant/appmon) 用于监视和篡改本地macOS，iOS和android应用程序的系统API调用的自动化框架。基于Frida。
- [**696**星][2m] [Py] [igio90/dwarf](https://github.com/igio90/dwarf) Full featured multi arch/os debugger built on top of PyQt5 and frida
- [**643**星][1m] [JS] [nccgroup/house](https://github.com/nccgroup/house) 运行时手机 App 分析工具包, 带Web GUI
- [**564**星][2m] [JS] [iddoeldor/frida-snippets](https://github.com/iddoeldor/frida-snippets) Hand-crafted Frida examples
- [**550**星][7m] [JS] [wooyundota/droidsslunpinning](https://github.com/wooyundota/droidsslunpinning) Android certificate pinning disable tools
- [**510**星][26d] [JS] [lyxhh/lxhtoolhttpdecrypt](https://github.com/lyxhh/lxhtoolhttpdecrypt) Simple Android/iOS protocol analysis and utilization tool
- [**440**星][1y] [Py] [dstmath/frida-unpack](https://github.com/dstmath/frida-unpack) 基于Frida的脱壳工具
- [**432**星][2y] [JS] [0xdea/frida-scripts](https://github.com/0xdea/frida-scripts) A collection of my Frida.re instrumentation scripts to facilitate reverse engineering of mobile apps.
- [**431**星][2m] [C] [frida/frida-python](https://github.com/frida/frida-python) Frida Python bindings
- [**405**星][2y] [C++] [vah13/extracttvpasswords](https://github.com/vah13/extracttvpasswords) tool to extract passwords from TeamViewer memory using Frida
- [**374**星][2m] [JS] [chichou/bagbak](https://github.com/ChiChou/bagbak) Yet another frida based iOS dumpdecrypted, works on iOS 13 with checkra1n and supports decrypting app extensions
- [**327**星][1m] [C] [frida/frida-core](https://github.com/frida/frida-core) Frida core library intended for static linking into bindings
- [**326**星][1y] [C] [smartdone/dexdump](https://github.com/smartdone/dexdump) 一个用来快速脱一代壳的工具（稍微改下就可以脱类抽取那种壳）（Android）
- [**326**星][23d] [JS] [smartdone/frida-scripts](https://github.com/smartdone/frida-scripts) 一些frida脚本
- [**320**星][5y] [C++] [frida/cryptoshark](https://github.com/frida/cryptoshark) Self-optimizing cross-platform code tracer based on dynamic recompilation
- [**307**星][10m] [Py] [nightbringer21/fridump](https://github.com/nightbringer21/fridump) A universal memory dumper using Frida
- [**277**星][2y] [Py] [antojoseph/frida-android-hooks](https://github.com/antojoseph/frida-android-hooks) Lets you hook Method Calls in Frida ( Android )
- [**271**星][23d] [JS] [frenchyeti/dexcalibur](https://github.com/frenchyeti/dexcalibur) Dynamic binary instrumentation tool designed for Android application and powered by Frida. It disassembles dex, analyzes it statically, generates hooks, discovers reflected methods, stores intercepted data and does new things from it. Its aim is to be an all-in-one Android reverse engineering platform.
- [**251**星][2y] [Py] [igio90/frick](https://github.com/igio90/frick) aka the first debugger built on top of frida
- [**248**星][23d] [JS] [we11cheng/wcshadowrocket](https://github.com/we11cheng/wcshadowrocket) iOS Shadowrocket(砸壳重签,仅供参考,添加节点存在问题)。另一个fq项目potatso源码参见:
- [**238**星][1m] [JS] [andreafioraldi/frida-fuzzer](https://github.com/andreafioraldi/frida-fuzzer) This experimetal fuzzer is meant to be used for API in-memory fuzzing.
- [**234**星][1m] [C] [frida/frida-gum](https://github.com/frida/frida-gum) Low-level code instrumentation library used by frida-core
- [**208**星][23d] [JS] [xiaokanghub/frida-android-unpack](https://github.com/xiaokanghub/frida-android-unpack) this unpack script for Android O and Android P
- [**203**星][2y] [ObjC] [alonemonkey/dumpdecrypted](https://github.com/alonemonkey/dumpdecrypted) Dumps decrypted mach-o files from encrypted applications、framework or app extensions.
- [**200**星][7m] [C] [nowsecure/frida-cycript](https://github.com/nowsecure/frida-cycript) Cycript fork powered by Frida.
- [**185**星][2m] [TS] [chame1eon/jnitrace](https://github.com/chame1eon/jnitrace) A Frida based tool that traces usage of the JNI API in Android apps.
- [**179**星][24d] [JS] [interference-security/frida-scripts](https://github.com/interference-security/frida-scripts) Frida Scripts
- [**171**星][3m] [C++] [samyk/frisky](https://github.com/samyk/frisky) Instruments to assist in binary application reversing and augmentation, geared towards walled gardens like iOS and macOS
- [**158**星][30d] [JS] [fuzzysecurity/fermion](https://github.com/fuzzysecurity/fermion) Fermion, an electron wrapper for Frida & Monaco.
- [**142**星][3y] [JS] [as0ler/frida-scripts](https://github.com/as0ler/frida-scripts) Repository including some useful frida script for iOS Reversing
- [**137**星][10m] [enovella/r2frida-wiki](https://github.com/enovella/r2frida-wiki) This repo aims at providing practical examples on how to use r2frida
- [**125**星][3y] [JS] [antojoseph/diff-gui](https://github.com/antojoseph/diff-gui) GUI for Frida -Scripts
- [**123**星][2y] [Java] [brompwnie/uitkyk](https://github.com/brompwnie/uitkyk) Android Frida库, 用于分析App查找恶意行为
- [**115**星][2m] [C++] [frida/frida-node](https://github.com/frida/frida-node) Frida Node.js bindings
- [**114**星][2y] [C] [b-mueller/frida-detection-demo](https://github.com/b-mueller/frida-detection-demo) Some examples for detecting frida on Android
- [**110**星][11m] [Py] [rootbsd/fridump3](https://github.com/rootbsd/fridump3) A universal memory dumper using Frida for Python 3
- [**106**星][23d] [JS] [thecjw/frida-android-scripts](https://github.com/thecjw/frida-android-scripts) Some frida scripts
- [**104**星][2m] [JS] [frida/frida-java-bridge](https://github.com/frida/frida-java-bridge) Java runtime interop from Frida
- [**99**星][2y] [Java] [piasy/fridaandroidtracer](https://github.com/piasy/fridaandroidtracer) A runnable jar that generate Javascript hook script to hook Android classes.
- [**95**星][5m] [Py] [demantz/frizzer](https://github.com/demantz/frizzer) Frida-based general purpose fuzzer
- [**93**星][7m] [TS] [nowsecure/airspy](https://github.com/nowsecure/airspy) AirSpy - Frida-based tool for exploring and tracking the evolution of Apple's AirDrop protocol implementation on i/macOS, from the server's perspective. Released during BH USA 2019 Training
- [**91**星][23d] [TS] [chichou/vscode-frida](https://github.com/chichou/vscode-frida) WIP
- [**90**星][25d] [C] [grimm-co/notquite0dayfriday](https://github.com/grimm-co/notquite0dayfriday) This is a repo which documents real bugs in real software to illustrate trends, learn how to prevent or find them more quickly.
- [**90**星][3y] [JS] [oalabs/frida-extract](https://github.com/oalabs/frida-extract) Frida.re based RunPE (and MapViewOfSection) extraction tool
- [**89**星][3y] [JS] [oalabs/frida-wshook](https://github.com/oalabs/frida-wshook) Script analysis tool based on Frida.re
- [**88**星][2y] [Py] [mind0xp/frida-python-binding](https://github.com/mind0xp/frida-python-binding) Easy to use Frida python binding script
- [**82**星][6m] [C] [oleavr/ios-inject-custom](https://github.com/oleavr/ios-inject-custom) (iOS) 使用Frida注入自定义Payload
- [**81**星][7m] [JS] [frida/frida-presentations](https://github.com/frida/frida-presentations) Public presentations given on Frida at conferences
- [**79**星][11m] [wufengxue/android-reverse](https://github.com/wufengxue/android-reverse) 安卓逆向工具汇总
- [**78**星][4m] [JS] [andreafioraldi/frida-js-afl-instr](https://github.com/andreafioraldi/frida-js-afl-instr) An example on how to do performant in-memory fuzzing with AFL++ and Frida
- [**75**星][4y] [Py] [antojoseph/diff-droid](https://github.com/antojoseph/diff-droid) 使用 Frida对手机渗透测试的若干脚本
- [**74**星][9m] [PHP] [vlucas/pikirasa](https://github.com/vlucas/pikirasa) PKI public/private RSA key encryption using the OpenSSL extension
- [**69**星][5m] [Py] [hamz-a/jeb2frida](https://github.com/hamz-a/jeb2frida) Automated Frida hook generation with JEB
- [**67**星][25d] [Py] [lich4/personal_script](https://github.com/lich4/personal_script) 010Editor/BurpSuite/Frida/IDA等多个工具的多个脚本
    - [010Editor](https://github.com/lich4/personal_script/tree/master/010Editor_Script) 010Editor的多个脚本
    - [ParamChecker](https://github.com/lich4/personal_script/tree/master/BurpSuite_Script) Burp插件
    - [Frida](https://github.com/lich4/personal_script/tree/master/Frida_script) Frida多个脚本
    - [IDA](https://github.com/lich4/personal_script/tree/master/IDA_Script) IDA Scripts
    - [IDA-read_unicode.py](https://github.com/lich4/personal_script/blob/master/IDA_Script/read_unicode.py) IDA插件，识别程序中的中文字符
    - [IDA-add_xref_for_macho](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_xref_for_macho.py) 辅助识别Objective-C成员函数的caller和callee
    - [IDA-add_info_for_androidgdb](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_info_for_androidgdb.py) 使用gdbserver和IDA调试Android时，读取module列表和segment
    - [IDA-trace_instruction](https://github.com/lich4/personal_script/blob/master/IDA_Script/trace_instruction.py) 追踪指令流
    - [IDA-detect_ollvm](https://github.com/lich4/personal_script/blob/master/IDA_Script/detect_ollvm.py) 检测OLLVM，在某些情况下修复（Android/iOS）
    - [IDA-add_block_for_macho](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_block_for_macho.py) 分析macho文件中的block结构
- [**65**星][2m] [C] [darvincisec/detectfrida](https://github.com/darvincisec/detectfrida) Detect Frida for Android
- [**59**星][2y] [Py] [attackercan/teamviewer-dumper](https://github.com/attackercan/teamviewer-dumper) 从内存中转储TeamViewer ID 和密码
- [**57**星][10m] [JS] [hamz-a/frida-android-libbinder](https://github.com/hamz-a/frida-android-libbinder) PoC Frida script to view Android libbinder traffic
- [**56**星][1m] [Py] [frida/frida-tools](https://github.com/frida/frida-tools) Frida CLI tools
- [**55**星][23d] [Java] [igio90/fridaandroidinjector](https://github.com/igio90/fridaandroidinjector) Inject frida agents on local processes through an Android app
- [**54**星][9m] [Py] [bkerler/oppo_decrypt](https://github.com/bkerler/oppo_decrypt) 一加手机固件解密脚本
- [**54**星][1m] [Py] [hamz-a/frida-android-helper](https://github.com/hamz-a/frida-android-helper) Frida Android utilities
- [**52**星][1y] [feicong/zsxq_archives](https://github.com/feicong/zsxq_archives) 【软件安全与知识星球】精华文章列表
- [**52**星][8m] [TS] [igio90/hooah-trace](https://github.com/igio90/hooah-trace) Instructions tracing powered by frida
- [**50**星][1y] [JS] [fortiguard-lion/frida-scripts](https://github.com/fortiguard-lion/frida-scripts) 
- [**50**星][1y] [JS] [maltek/swift-frida](https://github.com/maltek/swift-frida) Frida library for interacting with Swift programs.
- [**48**星][7m] [JS] [nowsecure/frida-trace](https://github.com/nowsecure/frida-trace) Trace APIs declaratively through Frida.
- [**47**星][6m] [Swift] [frida/frida-swift](https://github.com/frida/frida-swift) Frida Swift bindings
- [**46**星][3y] [Py] [ikoz/jdwp-lib-injector](https://github.com/ikoz/jdwp-lib-injector) 
- [**46**星][10m] [C] [sensepost/frida-windows-playground](https://github.com/sensepost/frida-windows-playground) A collection of Frida hooks for experimentation on Windows platforms.
- [**43**星][2y] [HTML] [digitalinterruption/fridaworkshop](https://github.com/digitalinterruption/fridaworkshop) Break Apps with Frida workshop material
- [**43**星][25d] [TS] [oleavr/frida-agent-example](https://github.com/oleavr/frida-agent-example) Example Frida agent written in TypeScript
- [**42**星][3m] [JS] [frida/frida-compile](https://github.com/frida/frida-compile) Compile a Frida script comprised of one or more Node.js modules
- [**40**星][2y] [Py] [agustingianni/memrepl](https://github.com/agustingianni/memrepl) Frida 插件，辅助开发内存崩溃类的漏洞
- [**39**星][1m] [CSS] [frida/frida-website](https://github.com/frida/frida-website) Frida's website
- [**35**星][5m] [Py] [dmaasland/mcfridafee](https://github.com/dmaasland/mcfridafee) 
- [**35**星][2m] [C++] [taviso/sharapi](https://github.com/taviso/sharapi) Simpsons: Hit & Run JavaScript API
- [**31**星][2m] [JS] [fsecurelabs/android-keystore-audit](https://github.com/fsecurelabs/android-keystore-audit) 
- [**30**星][1y] [JS] [ioactive/bluecrawl](https://github.com/ioactive/bluecrawl) Frida (Android) Script for extracting bluetooth information
- [**30**星][8m] [TS] [igio90/frida-onload](https://github.com/igio90/frida-onload) Frida module to hook module initializations on android
- [**29**星][7m] [Java] [dineshshetty/fridaloader](https://github.com/dineshshetty/fridaloader) A quick and dirty app to download and launch Frida on Genymotion
- [**29**星][25d] [C++] [frida/v8](https://github.com/frida/v8) Frida depends on V8
- [**28**星][2y] [JS] [versprite/engage](https://github.com/versprite/engage) Tools and Materials for the Frida Engage Blog Series
- [**27**星][2y] [Py] [androidtamer/frida-push](https://github.com/androidtamer/frida-push) Wrapper tool to identify the remote device and push device specific frida-server binary.
- [**27**星][6m] [C++] [frida/frida-clr](https://github.com/frida/frida-clr) Frida .NET bindings
- [**27**星][2m] [JS] [nowsecure/frida-uikit](https://github.com/nowsecure/frida-uikit) Inspect and manipulate UIKit-based GUIs through Frida.
- [**26**星][2m] [TS] [chame1eon/jnitrace-engine](https://github.com/chame1eon/jnitrace-engine) Engine used by jnitrace to intercept JNI API calls.
- [**25**星][3m] [TS] [woza-lab/woza](https://github.com/woza-lab/woza) [Deprecated]Dump application ipa from jailbroken iOS based on frida. (Node edition)
- [**25**星][2m] [Shell] [virb3/magisk-frida](https://github.com/virb3/magisk-frida) 
- [**21**星][4y] [JS] [dweinstein/node-frida-contrib](https://github.com/dweinstein/node-frida-contrib) frida utility-belt
- [**21**星][28d] [JS] [iddoeldor/mplus](https://github.com/iddoeldor/mplus) Intercept android apps based on unity3d (Mono) using Frida
- [**21**星][7m] [JS] [nowsecure/frida-uiwebview](https://github.com/nowsecure/frida-uiwebview) Inspect and manipulate UIWebView-hosted GUIs through Frida.
- [**20**星][5y] [JS] [frida/aurora](https://github.com/frida/aurora) Proof-of-concept web app built on top of Frida
- [**19**星][2y] [Py] [notsosecure/dynamic-instrumentation-with-frida](https://github.com/notsosecure/dynamic-instrumentation-with-frida) Dynamic Instrumentation with Frida
- [**19**星][7m] [JS] [nowsecure/frida-screenshot](https://github.com/nowsecure/frida-screenshot) Grab screenshots using Frida.
- [**19**星][7m] [JS] [freehuntx/frida-mono-api](https://github.com/freehuntx/frida-mono-api) All the mono c exports, ready to be used in frida!
- [**19**星][3m] [JS] [cynops/frida-hooks](https://github.com/cynops/frida-hooks) 
- [**18**星][3m] [Py] [igio90/fridaandroidtracer](https://github.com/igio90/fridaandroidtracer) Android application tracer powered by Frida
- [**18**星][23d] [Py] [bannsec/revenge](https://github.com/bannsec/revenge) REVerse ENGineering Environment
- [**16**星][7m] [JS] [nowsecure/frida-fs](https://github.com/nowsecure/frida-fs) Create a stream from a filesystem resource.
- [**14**星][2m] [Java] [igio90/snetkiller](https://github.com/igio90/snetkiller) InHouse safetynet killer
- [**14**星][4m] [JS] [woza-lab/woza-desktop](https://github.com/woza-lab/woza-desktop) [Deprecated]Desktop edition of command line tool woza
- [**13**星][5m] [JS] [freehuntx/frida-inject](https://github.com/freehuntx/frida-inject) This module allows you to easily inject javascript using frida and frida-load.
- [**12**星][1y] [JS] [andreafioraldi/taint-with-frida](https://github.com/andreafioraldi/taint-with-frida) just an experiment
- [**12**星][5y] [JS] [frida/cloudspy](https://github.com/frida/cloudspy) Proof-of-concept web app built on top of Frida
- [**11**星][7m] [JS] [nowsecure/mjolner](https://github.com/nowsecure/mjolner) Cycript backend powered by Frida.
- [**11**星][1y] [JS] [rubaljain/frida-jb-bypass](https://github.com/rubaljain/frida-jb-bypass) Frida script to bypass the iOS application Jailbreak Detection
- [**10**星][2y] [JS] [random-robbie/frida-docker](https://github.com/random-robbie/frida-docker) Dockerised Version of Frida
- [**10**星][2m] [Py] [melisska/neomorph](https://github.com/melisska/neomorph) Frida Python Tool
- [**9**星][5m] [JS] [lmangani/node_ssl_logger](https://github.com/lmangani/node_ssl_logger) Decrypt and log process SSL traffic via Frida Injection
- [**9**星][5m] [Py] [c3r34lk1ll3r/binrida](https://github.com/c3r34lk1ll3r/binrida) Plugin for Frida in Binary Ninja
- [**8**星][2y] [Py] [tinyniko/tweakdev](https://github.com/tinyniko/tweakdev) WOWOWOWOOWOWOWOOWOOWOW
- [**7**星][5m] [C++] [jaiverma/headshot](https://github.com/jaiverma/headshot) headshot: Trainer(aimbot and esp) for Assault Cube on macOS
- [**7**星][7m] [JS] [nowsecure/frida-panic](https://github.com/nowsecure/frida-panic) Easy crash-reporting for Frida-based applications.
- [**6**星][7m] [JS] [davuxcom/frida-scripts](https://github.com/davuxcom/frida-scripts) Inject JS and C# into Windows apps, call COM and WinRT APIs
- [**6**星][3y] [JS] [frida/frida-load](https://github.com/frida/frida-load) Load a Frida script comprised of one or more Node.js modules
- [**6**星][4m] [TS] [nowsecure/frida-remote-stream](https://github.com/nowsecure/frida-remote-stream) Create an outbound stream over a message transport.
- [**6**星][1y] [JS] [eybisi/fridascripts](https://github.com/eybisi/fridascripts) 
- [**4**星][7m] [JS] [nowsecure/frida-memory-stream](https://github.com/nowsecure/frida-memory-stream) Create a stream from one or more memory regions.
- [**4**星][3m] [JS] [sipcapture/hepjack.js](https://github.com/sipcapture/hepjack.js) Elegantly Sniff Forward-Secrecy TLS/SIP to HEP at the source using Frida
- [**3**星][2m] [Py] [margular/frida-skeleton](https://github.com/margular/frida-skeleton) This repository is supposed to define infrastructure of frida on hook android including some useful functions
- [**3**星][2y] [JS] [myzhan/frida-examples](https://github.com/myzhan/frida-examples) Examples of using frida.
- [**2**星][1y] [rohanbagwe/kick-off-owasp_webapp_security_vulnerabilities](https://github.com/rohanbagwe/kick-off-OWASP_WebApp_Security_Vulnerabilities) Want to keep your Web application from getting hacked? Here's how to get serious about secure apps. So let's do it! Open Friday, Aug 2016 - Presentation Notes.
- [**1**星][1y] [JS] [ddurando/frida-scripts](https://github.com/ddurando/frida-scripts) 


### <a id="f0b89493b077b82fb0b10fc56fca9faf"></a>其他工具交互


- [**971**星][1y] [Py] [gaasedelen/lighthouse](https://github.com/gaasedelen/lighthouse) 从DBI中收集代码覆盖情况，在IDA/Binja中映射、浏览、查看
    - 重复区段: [IntelPin->工具->其他工具交互](#95adfd425a416ee2a5c48bc1132b5655) |
    - [coverage-frida](https://github.com/gaasedelen/lighthouse/blob/master/coverage/frida/README.md) 使用Frida收集信息
    - [coverage-pin](https://github.com/gaasedelen/lighthouse/blob/master/coverage/pin/README.md) 使用Pin收集覆盖信息
    - [插件](https://github.com/gaasedelen/lighthouse/blob/master/plugin/lighthouse_plugin.py) 支持IDA和BinNinja
- [**609**星][1y] [Java] [federicodotta/brida](https://github.com/federicodotta/brida) The new bridge between Burp Suite and Frida!
- [**414**星][1m] [JS] [nowsecure/r2frida](https://github.com/nowsecure/r2frida) Radare2 and Frida better together.
- [**131**星][3y] [Py] [friedappleteam/frapl](https://github.com/friedappleteam/frapl) 在Frida Client和IDA之间建立连接，将运行时信息直接导入IDA，并可直接在IDA中控制Frida
    - [IDA插件](https://github.com/FriedAppleTeam/FRAPL/tree/master/Framework/FridaLink) 
    - [Frida脚本](https://github.com/FriedAppleTeam/FRAPL/tree/master/Framework/FRAPL) 
- [**86**星][5y] [Py] [techbliss/frida_for_ida_pro](https://github.com/techbliss/frida_for_ida_pro) 在IDA中使用Frida, 主要用于追踪函数
- [**35**星][2m] [CSS] [nowsecure/r2frida-book](https://github.com/nowsecure/r2frida-book) The radare2 + frida book for Mobile Application assessment
- [**8**星][5m] [Py] [c3r34lk1ll3r/binrida](https://github.com/c3r34lk1ll3r/BinRida) Plugin for Frida in Binary Ninja




***


## <a id="a1a7e3dd7091b47384c75dba8f279caf"></a>文章


- 2019.12 [sarang6489] [Root Detection Bypass With Frida.](https://medium.com/p/4a78ad075d09)
- 2019.12 [xakcop] [Cloning RSA tokens with Frida](https://xakcop.com/post/cloning-rsa/)
- 2019.11 [riusksk] [Frida框架在Fuzzing中的应用](http://riusksk.me/2019/11/30/Frida框架在Fuzzing中的应用/)
- 2019.11 [securify] [Android Frida hooking: disabling FLAG_SECURE](https://www.securify.nl/en/blog/SFY20191103/android-frida-hooking_-disabling-flag_secure.html)
- 2019.10 [freebuf] [使用Frida绕过Android App的SSL Pinning](https://www.freebuf.com/articles/terminal/214540.html)
- 2019.10 [securify] [Automated Frida hook generation with JEB](https://www.securify.nl/en/blog/SFY20191006/automated-frida-hook-generation-with-jeb.html)
- 2019.10 [sensepost] [mettle your ios with frida](https://sensepost.com/blog/2019/mettle-your-ios-with-frida/)
- 2019.09 [freebuf] [Dwarf：一款基于Pyqt5和Frida的逆向分析调试工具](https://www.freebuf.com/sectool/212123.html)
- 2019.06 [two06] [Fun With Frida](https://medium.com/p/5d0f55dd331a)
- 2019.05 [nsfocus] [基于Frida进行通信数据“解密”](http://blog.nsfocus.net/communication-data-decryption-based-on-frida/)
- 2019.05 [nsfocus] [Frida应用基础及APP https证书验证破解](http://blog.nsfocus.net/frida-application-foundation-app-https-certificate-verification-cracking/)
- 2019.05 [CodeColorist] [Trace child process with frida on macOS](https://medium.com/p/3b8f0f953f3d)
- 2019.05 [360] [FRIDA脚本系列（四）更新篇：几个主要机制的大更新](https://www.anquanke.com/post/id/177597/)
- 2019.04 [ved] [Hail Frida!! The Universal SSL pinning bypass for Android.](https://medium.com/p/e9e1d733d29)
- 2019.04 [sensepost] [recreating known universal windows password backdoors with Frida](https://sensepost.com/blog/2019/recreating-known-universal-windows-password-backdoors-with-frida/)
- 2019.04 [securify] [Frida Android libbinder](https://www.securify.nl/en/blog/SFY20190424/frida-android-libbinder.html)
- 2019.03 [360] [FRIDA脚本系列（三）超神篇：百度AI“调教”抖音AI](https://www.anquanke.com/post/id/175621/)
- 2019.03 [securityinnovation] [Setting up Frida Without Jailbreak on the Latest iOS 12.1.4 Device](https://blog.securityinnovation.com/frida)
- 2019.02 [nowsecure] [Frida 12.3 Debuts New Crash Reporting Feature](https://www.nowsecure.com/blog/2019/02/07/frida-12-3-debuts-new-crash-reporting-feature/)
- 2019.01 [fuzzysecurity] [Windows Hacking 之：ApplicationIntrospection & Hooking With Frida](http://fuzzysecurity.com/tutorials/29.html)
- 2019.01 [fuping] [安卓APP测试之HOOK大法-Frida篇](https://fuping.site/2019/01/25/Frida-Hook-SoulAPP/)
- 2019.01 [360] [FRIDA脚本系列（二）成长篇：动静态结合逆向WhatsApp](https://www.anquanke.com/post/id/169315/)
- 2019.01 [pediy] [[原创]介召几个frida在安卓逆向中使用的脚本以及延时Hook手法](https://bbs.pediy.com/thread-248848.htm)
- 2018.12 [360] [FRIDA脚本系列（一）入门篇：在安卓8.1上dump蓝牙接口和实例](https://www.anquanke.com/post/id/168152/)
- 2018.12 [pediy] [[原创]CVE-2017-4901 VMware虚拟机逃逸漏洞分析【Frida Windows实例】](https://bbs.pediy.com/thread-248384.htm)
- 2018.12 [freebuf] [一篇文章带你领悟Frida的精髓（基于安卓8.1）](https://www.freebuf.com/articles/system/190565.html)
- 2018.12 [pediy] [[原创] Frida操作手册-Android环境准备](https://bbs.pediy.com/thread-248293.htm)
- 2018.11 [4hou] [使用FRIDA为Android应用进行脱壳的操作指南](http://www.4hou.com/technology/14404.html)
- 2018.11 [pediy] [[原创]Frida Bypass Android SSL pinning example 1](https://bbs.pediy.com/thread-247967.htm)
- 2018.11 [secjuice] [Getting Started With Objection + Frida](https://www.secjuice.com/objection-frida-guide/)
- 2018.11 [insinuator] [使用Frida转储进程中解密后的文档](https://insinuator.net/2018/11/dumping-decrypted-documents-from-a-north-korean-pdf-reader/)
- 2018.11 [BSidesCHS] [BSidesCHS 2018: "Hacking Mobile Apps with Frida" by David Coursey](https://www.youtube.com/watch?v=NRyHP9IJRMs)
- 2018.11 [freebuf] [Frida-Wshook：一款基于Frida.re的脚本分析工具](https://www.freebuf.com/sectool/188726.html)
- 2018.11 [360] [如何使用FRIDA搞定Android加壳应用](https://www.anquanke.com/post/id/163390/)
- 2018.11 [ioactive] [Extracting Bluetooth Metadata in an Object’s Memory Using Frida](https://ioactive.com/extracting-bluetooth-metadata-in-an-objects-memory-using-frida/)
- 2018.11 [fortinet] [How-to Guide: Defeating an Android Packer with FRIDA](https://www.fortinet.com/blog/threat-research/defeating-an-android-packer-with-frida.html)
- 2018.10 [PancakeNopcode] [r2con2018 - Analyzing Swift Apps With swift-frida and radare2 - by Malte Kraus](https://www.youtube.com/watch?v=yp6E9-h6yYQ)
- 2018.10 [serializethoughts] [Bypassing Android FLAG_SECURE using FRIDA](https://serializethoughts.com/2018/10/07/bypassing-android-flag_secure-using-frida/)
- 2018.09 [pediy] [[原创]使用frida来hook加固的Android应用的java层](https://bbs.pediy.com/thread-246767.htm)
- 2018.09 [freebuf] [Frida在爆破Windows程序中的应用](http://www.freebuf.com/articles/system/182112.html)
- 2018.08 [pediy] [[翻译]通过破解游戏学习Frida基础知识](https://bbs.pediy.com/thread-246272.htm)
- 2018.07 [pediy] [[原创]在windows搭建frida hook环境碰到问题](https://bbs.pediy.com/thread-230138.htm)
- 2018.07 [CodeColorist] [《基于 FRIDA 的全平台逆向分析》课件](https://medium.com/p/2918c2b8967d)
- 2018.07 [serializethoughts] [Frida, Magisk and SELinux](https://serializethoughts.com/2018/07/23/frida-magisk-selinux)
- 2018.07 [pediy] [[翻译]在未root的设备上使用frida](https://bbs.pediy.com/thread-229970.htm)
- 2018.07 [pediy] [[原创]进阶Frida--Android逆向之动态加载dex Hook（三）（下篇）](https://bbs.pediy.com/thread-229657.htm)
- 2018.07 [pediy] [[原创]进阶Frida--Android逆向之动态加载dex Hook（三）（上篇）](https://bbs.pediy.com/thread-229597.htm)
- 2018.06 [pediy] [[原创]frida源码阅读之frida-java](https://bbs.pediy.com/thread-229215.htm)
- 2018.06 [4hou] [利用Frida打造ELF解析器](http://www.4hou.com/technology/12197.html)
- 2018.06 [pediy] [[原创]关于android 微信 frida 使用技巧](https://bbs.pediy.com/thread-228746.htm)
- 2018.06 [pediy] [[原创]初识Frida--Android逆向之Java层hook (二)](https://bbs.pediy.com/thread-227233.htm)
- 2018.06 [pediy] [[原创]初识Frida--Android逆向之Java层hook (一)](https://bbs.pediy.com/thread-227232.htm)
- 2018.05 [pediy] [[原创]Frida从入门到入门—安卓逆向菜鸟的frida食用说明](https://bbs.pediy.com/thread-226846.htm)
- 2018.05 [aliyun] [Frida.Android.Practice (ssl unpinning)](https://xz.aliyun.com/t/2336)
- 2018.05 [infosecinstitute] [Frida](http://resources.infosecinstitute.com/frida/)
- 2018.03 [pediy] [[翻译]使用 Frida 逆向分析 Android 应用与 BLE 设备的通信](https://bbs.pediy.com/thread-224926.htm)
- 2018.03 [freebuf] [Frida之Pin码破解实验](http://www.freebuf.com/articles/terminal/163297.html)
- 2018.02 [pentestpartners] [Reverse Engineering BLE from Android apps with Frida](https://www.pentestpartners.com/security-blog/reverse-engineering-ble-from-android-apps-with-frida/)
- 2018.02 [BSidesLeeds] [Prototyping And Reverse Engineering With Frida by Jay Harris](https://www.youtube.com/watch?v=cLUl_jK59EM)
- 2018.02 [libnex] [Hunting for hidden parameters within PHP built-in functions (using frida)](http://www.libnex.org/blog/huntingforhiddenparameterswithinphpbuilt-infunctionsusingfrida)
- 2017.11 [pediy] [[翻译]Frida官方手册中文版](https://bbs.pediy.com/thread-222729.htm)
- 2017.10 [pediy] [[翻译]利用Frida绕过Certificate Pinning](https://bbs.pediy.com/thread-222427.htm)
- 2017.09 [PancakeNopcode] [r2con 2017 - Intro to Frida and Dynamic Machine Code Transformations by Ole Andre](https://www.youtube.com/watch?v=sBcLPLtqGYU)
- 2017.09 [PancakeNopcode] [r2con2017 - r2frida /by @mrmacete](https://www.youtube.com/watch?v=URyd4bcV-Ik)
- 2017.09 [pediy] [[原创] 如何构建一款像 frida 一样的框架](https://bbs.pediy.com/thread-220794.htm)
- 2017.08 [360] [如何利用Frida实现原生Android函数的插桩](https://www.anquanke.com/post/id/86653/)
- 2017.08 [notsosecure] [如何动态调整使用 Android 的NDK 编写的代码，即：使用 Frida Hook C/ C++ 开发的功能。](https://www.notsosecure.com/instrumenting-native-android-functions-using-frida/)
- 2017.08 [freebuf] [Brida：使用Frida进行移动应用渗透测试](http://www.freebuf.com/sectool/143360.html)
- 2017.08 [freebuf] [利用Frida从TeamViewer内存中提取密码](http://www.freebuf.com/sectool/142928.html)
- 2017.08 [360] [联合Frida和BurpSuite的强大扩展--Brida](https://www.anquanke.com/post/id/86567/)
- 2017.08 [4hou] [Brida:将frida与burp结合进行移动app渗透测试](http://www.4hou.com/penetration/6916.html)
- 2017.07 [mediaservice] [Brida 实战](https://techblog.mediaservice.net/2017/07/brida-advanced-mobile-application-penetration-testing-with-frida/)
- 2017.07 [360] [使用Frida绕过Android SSL Re-Pinning](https://www.anquanke.com/post/id/86507/)
- 2017.07 [mediaservice] [使用 Frida 绕过 AndroidSSL Pinning](https://techblog.mediaservice.net/2017/07/universal-android-ssl-pinning-bypass-with-frida/)
- 2017.07 [4hou] [objection - 基于 Frida 的 iOS APP Runtime 探测工具](http://www.4hou.com/tools/6333.html)
- 2017.07 [koz] [无需 Root 向 AndroidApp 中注入原生库（例如 Frida）](https://koz.io/library-injection-for-debuggable-android-apps/)
- 2017.06 [360] [利用FRIDA攻击Android应用程序（四）](https://www.anquanke.com/post/id/86201/)
- 2017.06 [fitblip] [Frida CodeShare: Building a Community of Giants](https://medium.com/p/e84695a16e10)
- 2017.05 [freebuf] [如何在iOS应用程序中用Frida来绕过“越狱检测”?](http://www.freebuf.com/articles/terminal/134111.html)
- 2017.05 [4hou] [Android APP破解利器Frida之反调试对抗](http://www.4hou.com/technology/4584.html)
- 2017.05 [360] [如何使用Frida绕过iOS应用的越狱检测](https://www.anquanke.com/post/id/86068/)
- 2017.05 [4hou] [Frida：一款可以绕过越狱检测的工具](http://www.4hou.com/technology/4675.html)
- 2017.05 [pediy] [[翻译]多种特征检测 Frida](https://bbs.pediy.com/thread-217482.htm)
- 2017.05 [attify] [如何使用Frida绕过iOS应用的越狱检测](http://blog.attify.com/2017/05/06/bypass-jailbreak-detection-frida-ios-applications/)
- 2017.05 [pediy] [[翻译]OWASP iOS crackme 的教程：使用Frida来解决](https://bbs.pediy.com/thread-217448.htm)
- 2017.05 [attify] [Bypass Jailbreak Detection with Frida in iOS applications](https://blog.attify.com/bypass-jailbreak-detection-frida-ios-applications/)
- 2017.05 [pediy] [[翻译]用Frida来hack 安卓应用III—— OWASP UNCRACKABLE 2](https://bbs.pediy.com/thread-217424.htm)
- 2017.05 [360] [利用FRIDA攻击Android应用程序（三）](https://www.anquanke.com/post/id/85996/)
- 2017.04 [codemetrix] [Hacking Android apps with FRIDA III - OWASP UnCrackable 2](https://codemetrix.net/hacking-android-apps-with-frida-3/)
- 2017.04 [4hou] [安卓APP破解利器Frida之破解实战](http://www.4hou.com/technology/4392.html)
- 2017.04 [4hou] [安卓APP破解利器之FRIDA](http://www.4hou.com/info/news/4113.html)
- 2017.04 [koz] [不用Root就可以在安卓上使用Frida。](https://koz.io/using-frida-on-android-without-root/)
- 2017.04 [pediy] [[翻译]使用Frida来hack安卓APP（二）-crackme](https://bbs.pediy.com/thread-216893.htm)
- 2017.04 [fuping] [Android HOOK 技术之Frida的初级使用](https://fuping.site/2017/04/01/Android-HOOK-%E6%8A%80%E6%9C%AF%E4%B9%8BFrida%E7%9A%84%E5%88%9D%E7%BA%A7%E4%BD%BF%E7%94%A8/)
- 2017.03 [pediy] [[翻译] 使用Frida来hack安卓APP（一）](https://bbs.pediy.com/thread-216645.htm)
- 2017.03 [360] [利用FRIDA攻击Android应用程序（二）](https://www.anquanke.com/post/id/85759/)
- 2017.03 [360] [利用FRIDA攻击Android应用程序（一）](https://www.anquanke.com/post/id/85758/)
- 2017.03 [notsosecure] [使用 Frida 审计安卓App和安全漏洞](https://www.notsosecure.com/pentesting-android-apps-using-frida/)
- 2017.03 [codemetrix] [使用Frida Hack安卓App（Part 2）](https://codemetrix.net/hacking-android-apps-with-frida-2/)
- 2017.03 [codemetrix] [使用Frida Hack安卓App（Part 1）](https://codemetrix.net/hacking-android-apps-with-frida-1/)
- 2017.01 [freebuf] [使用Frida配合Burp Suite追踪API调用](http://www.freebuf.com/articles/web/125260.html)
- 2016.09 [PancakeNopcode] [r2con 2016 -- oleavr - r2frida](https://www.youtube.com/watch?v=ivCucqeVeZI)
- 2016.09 [n0where] [RunPE Extraction Tool: FridaExtract](https://n0where.net/runpe-extraction-tool-fridaextract)
- 2015.11 [crackinglandia] [Anti-instrumentation techniques: I know you’re there, Frida!](https://crackinglandia.wordpress.com/2015/11/10/anti-instrumentation-techniques-i-know-youre-there-frida/)
- 2014.08 [3xp10it] [frida用法](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2017/12/29/frida%E7%94%A8%E6%B3%95/)
- 2014.08 [3xp10it] [frida用法](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2017/12/29/frida%E7%94%A8%E6%B3%95/)
- 2014.08 [3xp10it] [frida开启ios app签名服务](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2019/08/13/frida%E5%BC%80%E5%90%AFios-app%E7%AD%BE%E5%90%8D%E6%9C%8D%E5%8A%A1/)
- 2014.02 [silentsignal] [From Read to Domain Admin – Abusing Symantec Backup Exec with Frida](https://blog.silentsignal.eu/2014/02/27/from-read-to-domain-admin-abusing-symantec-backup-exec-with-frida/)


# <a id="8abff248f7dd0b63fde24de6fc9a87b8"></a>Valgrind


***


## <a id="c5b612f014bbeb313c6e2b80cc5cafe3"></a>工具


- [**188**星][26d] [Py] [angr/pyvex](https://github.com/angr/pyvex) Python bindings for Valgrind's VEX IR.
- [**152**星][1m] [C] [wmkhoo/taintgrind](https://github.com/wmkhoo/taintgrind) A taint-tracking plugin for the Valgrind memory checking tool
- [**128**星][9y] [C] [agl/ctgrind](https://github.com/agl/ctgrind) Checking that functions are constant time with Valgrind
- [**35**星][8m] [C] [pmem/valgrind](https://github.com/pmem/valgrind) Enhanced Valgrind for Persistent Memory
- [**29**星][11y] [C] [dmolnar/smartfuzz](https://github.com/dmolnar/smartfuzz) Valgrind extension for whitebox fuzz testing
- [**7**星][2m] [C] [yugr/valgrind-preload](https://github.com/yugr/valgrind-preload) LD_PRELOAD-able library which runs all spawned processes under Valgrind.
- [**6**星][1m] [C] [kristerw/deadstores](https://github.com/kristerw/deadstores) A Valgrind tool for finding redundant loads/stores
- [**0**星][2y] [C] [daveti/valgrind](https://github.com/daveti/valgrind) Valgrind hacking from daveti
- [**0**星][2y] [C] [daveti/valtrap](https://github.com/daveti/valtrap) valgrind trapdoor


***


## <a id="ac878aff7e9b69738d83059912f2ba07"></a>文章


- 2018.07 [davejingtian] [Hacking Valgrind](https://davejingtian.org/2018/07/07/hacking-valgrind/)
- 2017.03 [csyssec] [如何使用Valgrind memcheck工具进行C/C++的内存漏洞检测](http://www.csyssec.org/20170315/valgrind-memcheck/)
- 2015.05 [Roland] [使用Valgrind找出Android中Native程序内存泄露问题](https://blog.csdn.net/Roland_Sun/article/details/46049485)
- 2012.08 [dndxhej] [linux下valgrind的使用概述](https://blog.csdn.net/dndxhej/article/details/7855520)
- 2010.07 [jinzhuojun] [性能优化工具gprof & 内存检测工具Valgrind 用法](https://blog.csdn.net/jinzhuojun/article/details/5720382)
- 2008.06 [kesalin] [Valgrind--Linux下的内存调试和代码解剖工具](https://blog.csdn.net/kesalin/article/details/2593958)


# <a id="b2fca17481b109a9b3b0bc290a1a1381"></a>QBDI


***


## <a id="e72b766bcd3b868c438a372bc365221e"></a>工具


- [**589**星][1y] [C++] [qbdi/qbdi](https://github.com/QBDI/QBDI) A Dynamic Binary Instrumentation framework based on LLVM.


***


## <a id="2cf79f93baf02a24d95d227a0a3049d8"></a>文章


- 2019.09 [quarkslab] [QBDI 0.7.0](https://blog.quarkslab.com/qbdi-070.html)
- 2019.07 [freebuf] [教你如何使用QBDI动态二进制检测框架](https://www.freebuf.com/sectool/207898.html)
- 2019.06 [quarkslab] [Android Native Library Analysis with QBDI](https://blog.quarkslab.com/android-native-library-analysis-with-qbdi.html)
- 2018.01 [quarkslab] [Slaying Dragons with QBDI](https://blog.quarkslab.com/slaying-dragons-with-qbdi.html)
- 2018.01 [pentesttoolz] [QBDI – QuarkslaB Dynamic binary Instrumentation](https://pentesttoolz.com/2018/01/13/qbdi-quarkslab-dynamic-binary-instrumentation/)
- 2018.01 [n0where] [QuarkslaB Dynamic binary Instrumentation: QBDI](https://n0where.net/quarkslab-dynamic-binary-instrumentation-qbdi)


# <a id="8e50e0c1c90258367f1095c61a7f4b82"></a>ADBI


***


## <a id="74096de3c5933b67a9fe313f1afbbb6a"></a>工具


- [**1057**星][5y] [C] [crmulliner/adbi](https://github.com/crmulliner/adbi) Android Dynamic Binary Instrumentation Toolkit
- [**429**星][4y] [Makefile] [mindmac/androideagleeye](https://github.com/mindmac/androideagleeye) An Xposed and adbi based module which is capable of hooking both Java and Native methods targeting Android OS.


***


## <a id="e39eb06761c41f7534a142e5ffb1dcc4"></a>文章


- 2014.06 [Roland] [Android平台下hook框架adbi的研究（下）](https://blog.csdn.net/Roland_Sun/article/details/36049307)
- 2014.06 [Roland] [Android平台下hook框架adbi的研究（上）](https://blog.csdn.net/Roland_Sun/article/details/34109569)


# <a id="6f79d6b2aa9f3d2daa8629c565f44269"></a>DBA


***


## <a id="c9b96059b34d508fdb2c202895518fbd"></a>Triton


### <a id="1dd4818bf0c90f6c2244362dc1ae1d89"></a>工具


- [**1433**星][24d] [C++] [jonathansalwan/triton](https://github.com/jonathansalwan/triton) DBA框架，内置：动态符号执行引擎、动态污点引擎、AST（x86, x86-64, AArch64）指令集，SMT simplification passes, an SMT solver interface，Python绑定
- [**61**星][3y] [Py] [cifasis/nosy-newt](https://github.com/cifasis/nosy-newt) Nosy Newt is a simple concolic execution tool for exploring the input space of a binary executable program based in Triton
- [**24**星][1y] [Py] [cosine0/amphitrite](https://github.com/cosine0/amphitrite) Symbolic debugging tool using JonathanSalwan/Triton
- [**24**星][7m] [Py] [jonathansalwan/x-tunnel-opaque-predicates](https://github.com/jonathansalwan/x-tunnel-opaque-predicates) IDA+Triton plugin in order to extract opaque predicates using a Forward-Bounded DSE. Example with X-Tunnel.
- [**17**星][5m] [Py] [macaron-et/wasabi-aeg](https://github.com/macaron-et/wasabi-aeg) Yet another implementation of AEG (Automated Exploit Generation) using symbolic execution engine Triton.
- [**2**星][5m] [Pascal] [pigrecos/triton4delphi](https://github.com/pigrecos/triton4delphi) The Triton - Dynamic Binary Analysis (DBA) framework - by JonathanSalwan binding for Delphi


### <a id="c941c67d2b508750b93e88709fd02ebf"></a>文章


- 2019.05 [aliyun] [Triton 学习 - pintool 篇](https://xz.aliyun.com/t/5100)
- 2019.05 [aliyun] [Triton 学习](https://xz.aliyun.com/t/5093)
- 2018.05 [360] [DEFCON CHINA议题解读 | Triton和符号执行在 GDB 上](https://www.anquanke.com/post/id/144984/)
- 2018.02 [HITCON] [[HITCON CMT 2017] R0D202 - 陳威伯 - Triton and Symbolic execution on GDB](https://www.youtube.com/watch?v=LOTQIAVXdCI)
- 2017.09 [PancakeNopcode] [r2con2017 - Pimp my Triton](https://www.youtube.com/watch?v=YVZgXqfqekE)
- 2017.09 [quarkslab] [Mistreating Triton](https://blog.quarkslab.com/mistreating-triton.html)
- 2017.04 [0x48] [Triton学习笔记(三)](http://0x48.pw/2017/04/05/0x32/)
- 2017.04 [0x48] [Triton学习笔记(三)](https://nobb.site/2017/04/05/0x32/)
- 2017.04 [0x48] [Triton学习笔记(二)](http://0x48.pw/2017/04/03/0x31/)
- 2017.04 [0x48] [Triton学习笔记(二)](https://nobb.site/2017/04/03/0x31/)
- 2017.04 [0x48] [Triton学习笔记(一)](http://0x48.pw/2017/04/02/0x30/)
- 2017.04 [0x48] [Triton学习笔记(一)](https://nobb.site/2017/04/02/0x30/)
- 2015.06 [quarkslab] [Triton under the hood](https://blog.quarkslab.com/triton-under-the-hood.html)




***


## <a id="6926f94dd30bc88e4dc975e56f0323dc"></a>Manticore


### <a id="9d452bb3dd68a493fb3c20a9d884dd38"></a>工具


- [**1867**星][26d] [Py] [trailofbits/manticore](https://github.com/trailofbits/manticore) 动态二进制分析工具，支持符号执行（symbolic execution）、污点分析（taint analysis）、运行时修改。
- [**42**星][1m] [Py] [trailofbits/manticore-examples](https://github.com/trailofbits/manticore-examples) Example Manticore scripts


### <a id="aa7c141a83254ef421b081143f4a0f9f"></a>文章


- 2020.01 [trailofbits] [Symbolically Executing WebAssembly in Manticore](https://blog.trailofbits.com/2020/01/31/symbolically-executing-webassembly-in-manticore/)
- 2019.07 [arxiv] [[1907.03890] Manticore: A User-Friendly Symbolic Execution Framework for Binaries and Smart Contracts](https://arxiv.org/abs/1907.03890)
- 2019.06 [trailofbits] [Announcing Manticore 0.3.0](https://blog.trailofbits.com/2019/06/07/announcing-manticore-0-3-0/)
- 2019.01 [trailofbits] [Symbolic Path Merging in Manticore](https://blog.trailofbits.com/2019/01/25/symbolic-path-merging-in-manticore/)
- 2017.06 [n0where] [Dynamic Binary Analysis Tool: Manticore](https://n0where.net/dynamic-binary-analysis-tool-manticore)
- 2017.05 [4hou] [Manticore：次世代二进制分析工具](http://www.4hou.com/technology/4822.html)




***


## <a id="86fb610cf955224352160b14171bfa86"></a>工具


- [**644**星][1y] [Go] [lunixbochs/usercorn](https://github.com/lunixbochs/usercorn) 通过模拟器对二进制文件进行动态分析
- [**50**星][1y] [Py] [hrkfdn/deckard](https://github.com/hrkfdn/deckard) Deckard performs static and dynamic binary analysis on Android APKs to extract Xposed hooks


***


## <a id="b6c6d6f1813166e14d971dd448a3f158"></a>文章


- 2013.03 [guidovranken] [Dynamic binary analysis using myrrh](https://guidovranken.wordpress.com/2013/03/01/dynamic-binary-analysis-using-myrrh/)


# <a id="5a9974bfcf7cdf9b05fe7a7dc5272213"></a>其他


***


## <a id="104bc99e36692f133ba70475ebc8825f"></a>工具


- [**272**星][4y] [C] [samsung/adbi](https://github.com/samsung/adbi) Android Dynamic Binary Instrumentation tool for tracing Android native layer
- [**187**星][2y] [C++] [sidechannelmarvels/tracer](https://github.com/sidechannelmarvels/tracer) Set of Dynamic Binary Instrumentation and visualization tools for execution traces.
- [**173**星][1m] [C] [beehive-lab/mambo](https://github.com/beehive-lab/mambo) ARM运行时二进制文件修改工具，低耗版。
- [**109**星][2y] [C++] [joxeankoret/membugtool](https://github.com/joxeankoret/membugtool) A DBI tool to discover heap memory related bugs
- [**77**星][3y] [Py] [carlosgprado/brundlefuzz](https://github.com/carlosgprado/brundlefuzz) BrundleFuzz is a distributed fuzzer for Windows and Linux using dynamic binary instrumentation.
- [**71**星][22d] [Py] [birchjd/piobdii](https://github.com/birchjd/piobdii) ODBII graphic interface on a Raspberry Pi computer, using an ELM327 Bluetooth/USB device. Read and display engine data, OBDII Trouble Codes & Descriptions Using Python. YouTube video:
- [**60**星][2y] [C] [zhechkoz/pwin](https://github.com/zhechkoz/pwin) Security Evaluation of Dynamic Binary Instrumentation Engines
- [**36**星][2y] [C++] [fdiskyou/dbi](https://github.com/fdiskyou/dbi) Files for
- [**18**星][7y] [C] [pleed/pyqemu](https://github.com/pleed/pyqemu) Dynamic binary instrumentation based crypto detection framework. Implementation of
- [**6**星][4y] [C++] [crackinglandia/exait-plugins](https://github.com/crackinglandia/exait-plugins) Anti-Dynamic binary instrumentation plugins for eXait (


***


## <a id="8f1b9c5c2737493524809684b934d49a"></a>文章


- 2018.08 [4hou] [动态二进制插桩的原理和基本实现过程（一）](http://www.4hou.com/binary/13026.html)
- 2018.07 [deniable] [Dynamic Binary Instrumentation Primer](http://deniable.org/reversing/binary-instrumentation)
- 2017.11 [rootedconmadrid] [Ricardo J. Rodríguez - Mejora en el Proceso de Desempacado usando Técnicas DBI [RootedCON 2012]](https://www.youtube.com/watch?v=PVQ_sYNuTVY)
- 2017.05 [yurichev] [30-May-2017: Using PIN DBI for XOR interception](https://yurichev.com/blog/PIN_XOR/)
- 2013.12 [corelan] [Using DBI for solving Reverse Engineering 101 – Newbie Contest from eLearnSecurity](https://www.corelan.be/index.php/2013/12/10/using-dbi-for-solving-reverse-engineering-101-newbie-contest-from-elearnsecurity/)
- 2012.04 [talosintelligence] [Prototyping Mitigations with DBI Frameworks](https://blog.talosintelligence.com/2012/04/prototyping-mitigations-with-dbi.html)


# 贡献
内容为系统自动导出, 有任何问题请提issue