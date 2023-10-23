#include <stdio.h>
#include <Windows.h>
#include <string>  
#include <vector>  
#include <iostream>  
#include <TlHelp32.h>
#include <Psapi.h> 

#pragma comment (lib,"Psapi.lib")  
#pragma comment(lib, "Version.lib")

using namespace std;

ULONG64 GetProcessImageBase(DWORD dwProcessId, const wchar_t* dllName)
{

	ULONG64 pProcessImageBase = NULL;
	MODULEENTRY32 me32 = { 0 };
	me32.dwSize = sizeof(MODULEENTRY32);

	HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, dwProcessId);
	if (INVALID_HANDLE_VALUE == hModuleSnap)
	{
		return 0;
	}

	BOOL bRet = Module32First(hModuleSnap, &me32);
	while (bRet)
	{
		if (!wcscmp(me32.szModule, dllName)) {
			break;
		}

		bRet = Module32Next(hModuleSnap, &me32);
	}
	pProcessImageBase = (ULONG64)me32.modBaseAddr;
	CloseHandle(hModuleSnap);

	return pProcessImageBase;
}

int SundaySearch(byte* s, int sn, byte* t, int tn) {


	if (sn <= 0 || tn <= 0)
		return -1;
	int i = 0, j = 0, k;
	int m = tn;
	for (; i < sn;) {
		if (s[i] != t[j]) {
			for (k = tn - 1; k >= 0; k--) {
				if (t[k] == s[m])
					break;
			}
			i = m - k;
			j = 0;
			m = i + tn;
		}
		else {
			if (j == tn - 1)
				return i - j;
			i++;
			j++;
		}
	}
}

ULONG64 GetKeysAddr(HANDLE mProc, ULONG64 base_addr)
{
	byte* pHeaderMem = (byte*)malloc(0x400);
	ReadProcessMemory(mProc, (LPCVOID)base_addr, pHeaderMem, 0x400, NULL);

	PIMAGE_DOS_HEADER pDOS_Header = (PIMAGE_DOS_HEADER)pHeaderMem;
	PIMAGE_NT_HEADERS pNT_Header = (PIMAGE_NT_HEADERS)(pHeaderMem + pDOS_Header->e_lfanew);
	PIMAGE_SECTION_HEADER pSECTION_Header = (PIMAGE_SECTION_HEADER)((LPBYTE)pNT_Header + sizeof(IMAGE_NT_HEADERS64));

	DWORD pDATASection = 0;
	DWORD DATASectionSize = 0;
	for (int i = 0; i < pNT_Header->FileHeader.NumberOfSections; i++) {
		if (!strcmp((char*)(pSECTION_Header[i].Name), ".data")) {
			pDATASection = pSECTION_Header[i].VirtualAddress;
			DATASectionSize = pSECTION_Header[i].Misc.VirtualSize;
			break;
		}
	}

	free(pHeaderMem);

	if (!pDATASection) {
		return 0;
	}

	byte* pMem = (byte*)malloc(DATASectionSize);

	ReadProcessMemory(mProc, (LPCVOID)(pDATASection + base_addr), pMem, DATASectionSize, NULL);

	unsigned char addrSign[] = { 0x20, 0x00 , 0x00 , 0x00 };
	unsigned char iphone[] = { 0x69, 0x70 , 0x68 , 0x6F , 0x6E ,0x65 };
	unsigned char Android[] = { 0x61, 0x6e , 0x64 , 0x72 , 0x6F , 0x69, 0x64 };

	DWORD pos = SundaySearch(pMem, DATASectionSize, iphone, sizeof(iphone));

	if (pos == DATASectionSize)
	{
		pos = SundaySearch(pMem, DATASectionSize, Android, sizeof(Android));
	}


	while (1)
	{
		pos--;

		if (!memcmp((pMem + pos), addrSign, 4))
		{
			break;
		}

	}

	LONGLONG paddr = NULL;
	paddr = *(PLONGLONG)(pMem + pos - sizeof(LONGLONG));

	free(pMem);
	return paddr;

}


int main(int argc, char** argv)
{
	HWND phandle = FindWindowA("WeChatMainWndForPC", NULL);
	if (!phandle)
	{
		return 0;
	}

	DWORD pid;
	GetWindowThreadProcessId(phandle, &pid);

	if (!pid)
	{
		return 0;
	}
	printf("[*] pid = %d\n", pid);

	HANDLE mProc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if (mProc == NULL)
	{
		return 0;
	}

	ULONG64 base_address = (ULONG64)GetProcessImageBase(pid, L"WeChatWin.dll");
	printf("[*] WeChatWin Address: 0x%08x\n", (DWORD)base_address);

	ULONG64 dwKeyAddr = GetKeysAddr(mProc, base_address);
	printf("[*] Key Addr: 0x%08x\n", (DWORD)dwKeyAddr);

	byte databasekey[0x20];
	memset(databasekey, 0, 0x20);
	ReadProcessMemory(mProc, (LPCVOID)dwKeyAddr, databasekey, 0x20, NULL);
	CloseHandle(mProc);

	printf("[*] Key:\n");
	for (unsigned int i = 0; i < 0x20; i++)
	{
		printf("%02x ", databasekey[i]);

	}

	return 0;
}