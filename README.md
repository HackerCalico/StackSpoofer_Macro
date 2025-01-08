# StackSpoofer_Macro

### 请给我 Star 🌟，非常感谢！这对我很重要！

### Please give me Star 🌟, thank you very much! It is very important to me!

### 1. 介绍

经过改造的栈欺骗技术，易于使用且功能强大。

https://github.com/HackerCalico/StackSpoofer_Macro

![spoof.jpg](https://raw.githubusercontent.com/HackerCalico/StackSpoofer_Macro/refs/heads/main/spoof.png)

### 2. 效果 & 优势

(1) 通过 SPOOF(函数名, 参数个数, 参数...) 宏可以简单对任意函数进行栈欺骗调用。

(2) 从线程的栈空间中寻找 RtlUserThreadStart 和 BaseThreadInitThunk 的栈帧，避免了不同 Windows 版本的函数有差异的问题。

(3) 通过自定义 DLL 实现 Gadget，避免了 Gadget 形式固定和返回位置不存在 call 的特征。

(4) 通过 OBF("xxx") 宏可以简单对任意字符串进行编译时加密，运行时解密。

### 3. 注意事项

(1) SPOOF 宏的参数中不能存在函数调用，例如 SPOOF(func1, func2())。

(2) 如果 Gadget 栈帧大小 < 参数总大小则直接调用函数，不会进入栈欺骗分支。

(3) Visual Studio Installer ---> 单个组件 ---> LLVM (clang-cl) 和 Clang ---> 安装

(4) 计算栈帧大小的算法比较复杂，在计算 RtlUserThreadStart 和 BaseThreadInitThunk 以外的函数的栈帧大小时不保证准确，比如自定义的 Gadget 函数存在特殊的栈操作时，请在 Process Hacker 中检验欺骗情况。