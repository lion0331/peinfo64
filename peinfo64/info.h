#pragma once
#pragma execution_character_set("utf-8")
#ifndef INFO_H_
#define INFO_H_

#include <windows.h>
#include <richedit.h>
#include <commctrl.h>
#pragma comment(lib,"comctl32.lib")
#include <strsafe.h>
#include <stdlib.h>

/* 安全限制常量 — 防止恶意/损坏 PE 文件导致无限循环 */
#define IMPORT_THUNK_LIMIT     10000
#define IMPORT_DESC_LIMIT      1000
#define EXPORT_FUNC_LIMIT      100000
#define RELOC_BLOCK_LIMIT      10000

BOOL CALLBACK DlgProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
void init();
void _OpenFile();
DWORD RVAToOffset(IMAGE_DOS_HEADER* lpFileHead, DWORD dwRVA);
IMAGE_SECTION_HEADER* GetRVASectionHeader(IMAGE_DOS_HEADER* lpFileHead, DWORD dwRVA);
int CALLBACK _Handler(EXCEPTION_POINTERS* lpExceptionPoint);
void ShowErrMsg();
BOOL WriteTextToDump(HANDLE hFile, const TCHAR* text);
void CopySectionName(const IMAGE_SECTION_HEADER* section, TCHAR* buffer, size_t bufferCount);
void CopyAnsiToWide(const char* source, TCHAR* buffer, size_t bufferCount);
BOOL IsPe64(const IMAGE_NT_HEADERS* ntHeader);
PBYTE OffsetToPtr(PBYTE fileBase, DWORD fileOffset);

void _getMainInfo(PBYTE, IMAGE_NT_HEADERS*, int);
void _getImportInfo(PBYTE, IMAGE_NT_HEADERS*, int);
void _getExportInfo(PBYTE, IMAGE_NT_HEADERS*, int);
void _getRelocInfo(PBYTE, IMAGE_NT_HEADERS*, int);
void _getResourceInfo(PBYTE, IMAGE_NT_HEADERS*, int);

void _readToRichEdit();

#endif
