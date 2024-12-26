#pragma once

#include <iostream>
#include <windows.h>

using namespace std;

int LocateSection(PBYTE pDll, char* sectionName, PBYTE& pSection) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pDll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDll + pDos->e_lfanew);
    WORD numberOfSections = pNt->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER pSectionTable = (PIMAGE_SECTION_HEADER)((DWORD_PTR) & (pNt->OptionalHeader) + pNt->FileHeader.SizeOfOptionalHeader);
    for (int i = 0; i < numberOfSections; i++) {
        if (!strcmp((char*)pSectionTable[i].Name, sectionName)) {
            pSection = pDll + pSectionTable[i].VirtualAddress;
            return pSectionTable[i].SizeOfRawData;
        }
    }
    return 0;
}

PBYTE FindExpFuncAddr(PBYTE pDll, char* funcName) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pDll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDll + pDos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(pDll + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD numberOfNames = pExportDir->NumberOfNames;
    PDWORD pAddressOfFunctions = (PDWORD)(pDll + pExportDir->AddressOfFunctions);
    PDWORD pAddressOfNames = (PDWORD)(pDll + pExportDir->AddressOfNames);
    PWORD pAddressOfNameOrdinals = (PWORD)(pDll + pExportDir->AddressOfNameOrdinals);
    for (int i = 0; i < numberOfNames; i++) {
        PBYTE pFuncName = pDll + pAddressOfNames[i];
        if (!strcmp((char*)pFuncName, funcName)) {
            return pDll + pAddressOfFunctions[pAddressOfNameOrdinals[i]];
        }
    }
    return NULL;
}