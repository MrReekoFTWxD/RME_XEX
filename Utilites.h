#ifndef _UTILITIES_H
#define _UTILITIES_H

#include <xtl.h>
#include <xboxmath.h>
#include <stdio.h>
#include <time.h>

#define GetPointer(X) *(PDWORD)(X)
#define CSleep(X) Sleep(X * 1000)

// Hooking
VOID PatchInJump(PDWORD Address, DWORD Destination, BOOL Linked);
VOID HookRegistertionStart(PDWORD Address, PDWORD SaveStub, DWORD Destination);
DWORD PatchModuleImport(PCHAR Module, PCHAR ImportedModuleName, DWORD Ordinal, DWORD PatchAddress);
DWORD PatchModuleImport(PLDR_DATA_TABLE_ENTRY Module, PCHAR ImportedModuleName, DWORD Ordinal, DWORD PatchAddress);

// File Stuff
BOOL FileExists(PCHAR Path);
BOOL ReadFileAlt(PCHAR Path, LPVOID Buffer, DWORD dwBytesToRead);
BOOL WriteFileAlt(PCHAR Path, LPCVOID Buffer, DWORD dwBytesToWrite);

// Misc
DWORD ResolveRegistertion(PCHAR ModuleName, DWORD Ordinal);
VOID XNotify(CONST PWCHAR NotifyText);
BOOL IsEmpty(PBYTE Buffer, DWORD Size);
extern VOID(__cdecl *Keyboardd)(int LocalClientNum, wchar_t *Title, wchar_t *PresetMessage, int Length, void(*CompleteFunction)(int LocalClientNum, const wchar_t * wString, int Length), int PanelMode);

#endif // _UTILITIES_H
