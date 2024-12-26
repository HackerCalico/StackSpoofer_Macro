﻿#pragma once

#define UWOP_PUSH_NONVOL 0
#define UWOP_ALLOC_LARGE 1
#define UWOP_ALLOC_SMALL 2
#define UWOP_SET_FPREG 3
#define UWOP_SAVE_NONVOL 4
#define UWOP_SAVE_NONVOL_FAR 5
#define UWOP_SAVE_XMM128 8
#define UWOP_SAVE_XMM128_FAR 9
#define UWOP_PUSH_MACHFRAME 10

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef union _UNWIND_CODE {
    struct {
        unsigned char CodeOffset;
        unsigned char UnwindOp : 4;
        unsigned char OpInfo : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, * PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    unsigned char Version : 3;
    unsigned char Flags : 5;
    unsigned char SizeOfProlog;
    unsigned char CountOfCodes;
    unsigned char FrameRegister : 4;
    unsigned char FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];
} UNWIND_INFO, * PUNWIND_INFO;

BYTE initStack[400];
int initStackSize = 0;
PBYTE pGadget = NULL;
int gadgetStackSize = 0;
#define MinGadgetStackSize 200

int GetStackSize(PBYTE pDll, PBYTE pFunc) {
    // 定位 pdata
    PBYTE pPDATA = NULL;
    int pdataSize = LocateSection(pDll, OBF(".pdata"), pPDATA);
    if (pPDATA == NULL) {
        return 0;
    }

    // 查找函数 RUNTIME_FUNCTION
    PRUNTIME_FUNCTION pRuntimeFunction = (PRUNTIME_FUNCTION)pPDATA;
    while (pRuntimeFunction->BeginAddress && (PBYTE)pRuntimeFunction + sizeof(RUNTIME_FUNCTION) <= pPDATA + pdataSize) {
        if (pDll + pRuntimeFunction->BeginAddress <= pFunc && pDll + pRuntimeFunction->EndAddress >= pFunc) {
            break;
        }
        pRuntimeFunction++;
    }
    if (!pRuntimeFunction->BeginAddress || (PBYTE)pRuntimeFunction + sizeof(RUNTIME_FUNCTION) > pPDATA + pdataSize) {
        return 0;
    }

    // 计算栈帧大小
    int stackSize = 0;
    int UWOP_SET_FPREG_HIT = 0;
    PUNWIND_INFO pUnwindInfo = (PUNWIND_INFO)(pDll + pRuntimeFunction->UnwindData);
    for (int i = 0; i < pUnwindInfo->CountOfCodes; i++) {
        ULONG unwindOp = pUnwindInfo->UnwindCode[i].UnwindOp;
        ULONG opInfo = pUnwindInfo->UnwindCode[i].OpInfo;
        if (unwindOp == UWOP_PUSH_NONVOL) {
            if (opInfo == 4 && !UWOP_SET_FPREG_HIT) {
                return 0;
            }
            stackSize += 8;
        }
        else if (unwindOp == UWOP_ALLOC_LARGE) {
            i++;
            ULONG frameOffset = pUnwindInfo->UnwindCode[i].FrameOffset;
            if (!opInfo) {
                frameOffset *= 8;
            }
            else {
                i++;
                frameOffset += (pUnwindInfo->UnwindCode[i].FrameOffset << 16);
            }
            stackSize += frameOffset;
        }
        else if (unwindOp == UWOP_ALLOC_SMALL) {
            stackSize += (opInfo + 1) * 8;
        }
        else if (unwindOp == UWOP_SET_FPREG) {
            if ((pUnwindInfo->Flags & UNW_FLAG_EHANDLER) && (pUnwindInfo->Flags & UNW_FLAG_CHAININFO)) {
                return 0;
            }
            UWOP_SET_FPREG_HIT = 1;
            ULONG frameOffset = -0x10 * (pUnwindInfo->FrameOffset);
            stackSize += frameOffset;
        }
        else if (unwindOp == UWOP_SAVE_NONVOL) {
            if (opInfo == 4 || opInfo == 5) {
                return 0;
            }
            i++;
        }
        else if (unwindOp == UWOP_SAVE_NONVOL_FAR) {
            if (opInfo == 4 || opInfo == 5) {
                return 0;
            }
            i += 2;
        }
        else if (unwindOp == UWOP_SAVE_XMM128) {
            i++;
        }
        else if (unwindOp == UWOP_SAVE_XMM128_FAR) {
            i += 2;
        }
        else if (unwindOp == UWOP_PUSH_MACHFRAME) {
            if (!opInfo) {
                stackSize += 0x40;
            }
            else {
                stackSize += 0x48;
            }
        }
        else {
            return 0;
        }
    }
    if (pUnwindInfo->Flags & UNW_FLAG_CHAININFO) {
        return 0;
    }
    return stackSize + sizeof(DWORD_PTR);
}

void FindGadget(PBYTE pSpoof) {
    PBYTE pTEXT = NULL;
    char* gadgetSig = OBF("\x48\x8B\x1B\xFF\xE3");
    int gadgetSigLen = strlen(gadgetSig);
    int textSize = LocateSection(pSpoof, OBF(".text"), pTEXT);
    if (pTEXT != NULL) {
        for (int i = 0; i < textSize - gadgetSigLen; i++) {
            int isFind = 1;
            for (int j = 0; j < gadgetSigLen; j++) {
                if (*(pTEXT + i + j) != (BYTE) * (gadgetSig + j)) {
                    isFind = 0;
                    break;
                }
            }
            if (isFind) {
                int curGadgetStackSize = GetStackSize(pSpoof, pTEXT + i);
                if (curGadgetStackSize > gadgetStackSize && curGadgetStackSize > MinGadgetStackSize) {
                    pGadget = pTEXT + i;
                    gadgetStackSize = curGadgetStackSize;
                }
            }
        }
    }
}

int GetSpoofStack() {
    if (pGadget != NULL) {
        return 1;
    }
    // 获取 BaseThreadInitThunk RtlUserThreadStart 地址
    DWORD_PTR _PEB = __readgsqword(0x60);
    DWORD_PTR _PEB_LDR_DATA = *(PDWORD_PTR)(_PEB + 0x18);
    PLIST_ENTRY pInInitializationOrderModuleList = (PLIST_ENTRY) * (PDWORD_PTR)(_PEB_LDR_DATA + 0x30);
    PLIST_ENTRY pNode = pInInitializationOrderModuleList;
    PBYTE pNtdll = NULL;
    PBYTE pKernel32 = NULL;
    PBYTE pSpoof = NULL;
    do {
        char dllName[20];
        PUNICODE_STRING string = (PUNICODE_STRING)((PBYTE)pNode + 0x38);
        int dllNameLen = string->Length / 2 - 4;
        if (dllNameLen < sizeof(dllName)) {
            for (int i = 0; i < dllNameLen; i++) {
                dllName[i] = string->Buffer[i];
            }
            dllName[dllNameLen] = '\0';
            DWORD_PTR dllBase = *(PDWORD_PTR)((PBYTE)pNode + 0x10);
            if (!strcmp(dllName, OBF("ntdll")) || !strcmp(dllName, OBF("NTDLL"))) {
                pNtdll = (PBYTE)dllBase;
            }
            else if (!strcmp(dllName, OBF("KERNEL32")) || !strcmp(dllName, OBF("kernel32"))) {
                pKernel32 = (PBYTE)dllBase;
            }
            else if (!strcmp(dllName, OBF("spoof"))) {
                pSpoof = (PBYTE)dllBase;
            }
        }
        pNode = pNode->Flink;
    } while (pNode->Flink != pInInitializationOrderModuleList);
    if (pNtdll == NULL || pKernel32 == NULL || pSpoof == NULL) {
        return 0;
    }
    PBYTE pRtlUserThreadStart = FindExpFuncAddr(pNtdll, OBF("RtlUserThreadStart"));
    PBYTE pBaseThreadInitThunk = FindExpFuncAddr(pKernel32, OBF("BaseThreadInitThunk"));
    if (pRtlUserThreadStart == NULL || pBaseThreadInitThunk == NULL) {
        return 0;
    }

    // 计算 BaseThreadInitThunk RtlUserThreadStart 栈帧大小
    int rutsStackSize = GetStackSize(pNtdll, pRtlUserThreadStart);
    int btitStackSize = GetStackSize(pKernel32, pBaseThreadInitThunk);
    initStackSize = rutsStackSize + btitStackSize;
    if (!rutsStackSize || !btitStackSize || initStackSize > sizeof(initStack)) {
        return 0;
    }

    // 查找并复制 BaseThreadInitThunk RtlUserThreadStart 栈帧
    DWORD_PTR _TEB = __readgsqword(0x30);
    DWORD_PTR stackBase = *(PDWORD_PTR)(_TEB + 8);
    DWORD_PTR stacklimit = *(PDWORD_PTR)(_TEB + 16);
    DWORD_PTR stack = stackBase - sizeof(DWORD_PTR);
    PBYTE pInitStack = NULL;
    while (stacklimit < stack - rutsStackSize - btitStackSize) {
        if (*(PDWORD_PTR)stack == 0x00) {
            DWORD_PTR addr = *(PDWORD_PTR)(stack - rutsStackSize);
            if (addr > (DWORD_PTR)pRtlUserThreadStart && addr < (DWORD_PTR)pRtlUserThreadStart + 0xFF) {
                addr = *(PDWORD_PTR)(stack - rutsStackSize - btitStackSize);
                if (addr > (DWORD_PTR)pBaseThreadInitThunk && addr < (DWORD_PTR)pBaseThreadInitThunk + 0xFF) {
                    pInitStack = (PBYTE)stack - rutsStackSize - btitStackSize;
                }
            }
        }
        stack -= sizeof(DWORD_PTR);
    }
    if (pInitStack == NULL) {
        return 0;
    }
    XorData((char*)pInitStack, (char*)initStack, initStackSize);

    // 在 spoof.dll 查找 Gadget
    FindGadget(pSpoof);
    if (pGadget == NULL) {
        return 0;
    }
    return 1;
}

template<typename T>
__attribute__((naked)) T RetValue() {
    __asm {
        ret
    }
}

__attribute__((naked)) void FixRSP(...) {
    __asm {
        add rsp, initStackSize
        add rsp, gadgetStackSize
        add rsp, 0x98
        ret
    }
}

PVOID pFixRSP = FixRSP;

__attribute__((naked)) void JmpToFunc(...) {
    __asm {
        lea rbx, [pFixRSP]
        mov rax, pGadget
        mov qword ptr[rsp], rax
        sub rsp, 0x08
        ret
    }
}

void SetSpoofStack(PBYTE& pSpoofStack) {
    pSpoofStack -= (initStackSize + sizeof(DWORD_PTR) * 20);
    XorData((char*)initStack, (char*)pSpoofStack, initStackSize);
    *(PDWORD_PTR)(pSpoofStack + initStackSize) = 0x00;
    pSpoofStack -= gadgetStackSize;
}

__attribute__((naked)) void GetRetAddr() {
    __asm {
        mov rax, qword ptr[rsp]
        push rax
        ret
    }
}

// 参数总大小不能超过 MinGadgetStackSize
#define SPOOF(pFunc, ...) ({ \
    int result = GetSpoofStack(); \
    using retType = decltype(((decltype(pFunc)*)pFunc)(__VA_ARGS__)); \
    if (result) { \
        int getRetAddr = 1; \
        while (1) { \
            if (!getRetAddr) { \
                PBYTE pSpoofStack; \
                __asm { \
                    mov pSpoofStack, rsp \
                } \
                SetSpoofStack(pSpoofStack); \
                __asm { \
                    mov rsp, pSpoofStack \
                } \
                __asm { \
                    lea rax, [pFunc] \
                } \
                __asm { \
                    mov qword ptr[rsp - 0x08], rax \
                } \
                __asm { \
                    pop rax \
                } \
                JmpToFunc(__VA_ARGS__); \
            } \
            __asm { \
                call GetRetAddr \
            } \
            if (!getRetAddr) { \
                break; \
            } \
            getRetAddr = 0; \
        } \
    } \
    if (!result) { \
        ((decltype(pFunc)*)pFunc)(__VA_ARGS__); \
    } \
    RetValue<retType>(); \
})