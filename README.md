# StackSpoof_Macro

### 请给我 Star 🌟，非常感谢！这对我很重要！

### Please give me Star 🌟, thank you very much! It is very important to me!

### 1. 介绍

https://github.com/HackerCalico/StackSpoof_Macro

经过改造的栈欺骗技术。

![spoof.jpg](https://raw.githubusercontent.com/HackerCalico/StackSpoof_Macro/refs/heads/main/spoof.png)

### 2. 效果 & 优势

(1) 通过 SPOOF(函数名, 参数...) 宏可以简单对任意函数进行栈欺骗调用。

(2) 从线程的栈空间中寻找 BaseThreadInitThunk 和 RtlUserThreadStart 的栈帧，避免了不同 Windows 版本的函数有差异的问题。

(3) 通过自定义 DLL 实现 Gadget，避免了 Gadget 形式固定和返回位置不存在 call 的特征。

(4) 通过 OBF("xxx") 宏可以简单对任意字符串进行编译时加密，运行时解密。

### 3. 注意事项

(1) Visual Studio Installer ---> 单个组件 ---> LLVM (clang-cl) 和 Clang ---> 安装

(2) 栈欺骗调用的函数的参数总大小不能超过 MinGadgetStackSize，这个值可以结合 DLL 随意改变，默认是 200 bit。