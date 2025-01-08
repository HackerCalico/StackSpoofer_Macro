#include "Bypass.h"
#include "Obfuscator.h"
#include "StackSpoofer.h"

/*
* ⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️
* 1.Release
* 2.常规: 平台工具集(LLVM (clang-cl))
* 3.C/C++
* 优化: 优化(已禁用)
* 代码生成: 运行库(多线程)
* 4.链接器
* 清单文件: 生成清单(否)
* 调试: 生成调试信息(否)
*/

int Test(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j) {
	return a + b + c + d + e + f + g + h + i + j;
}

int main() {
	// spoof.dll 是一个栈欺骗辅助 DLL, 其中含有一个 Gadget 函数, 该函数的栈帧大到可以存储任意函数的参数
	// 如果你不喜欢这个设计, 你完全可以从其他地方寻找 Gadget, 比如可以把 Gadget 定义在 Loader 中
	LoadLibraryA(OBF("spoof"));
	char* content = OBF("content");
	SPOOF(MessageBoxA, 4, 0, content, content, MB_ICONINFORMATION);
	cout << SPOOF(Test, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10) << endl;
}