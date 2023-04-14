#include <iostream>
#include <Windows.h>

HANDLE hHandle = NULL;

bool GetDriverHandle() 
{
	hHandle = CreateFileW(L"\\\\.\\microsofthelperdriver", GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hHandle == INVALID_HANDLE_VALUE)
	{
		printf("Failed to get a handle to driver\n");
		return false;
	}
	
	return true;
}

ULONG EncryptRequestCode(ULONG ioctl) {
	/*
		v4 = __ROR4__(a2->Tail.Overlay.CurrentStackLocation->Parameters.Read.ByteOffset.LowPart ^ 0xE4938CDF, 8) ^ 0xE4938CDF;
	*/

	const ULONG key = 0xE4938CDF; // decryption key
	ULONG encrypted_value = ioctl ^ key; // value xor key
	encrypted_value = (encrypted_value << 8) | (encrypted_value >> 24); // bitwise rotation, shift 8 bits to the left, shift 24 to right
	encrypted_value = encrypted_value ^ key; // 1, 3
	return encrypted_value;
}

#define IOCTL_PsGetProcessSectionBaseAddress 0x13370400
#define IOCTL_ReadProcessMemory 0x13370800
#define IOCTL_WriteProcessMemory 0x13370C00

typedef struct _readmem
{
	/*
	00000000 _IRP            struc ; (sizeof=0xD0, align=0x10, copyof_14)
	processid       dw ?
	sourceaddress   dq ?                    ; offset
	buffer          dd ?
	size            dw ?
	*/

	int processid;
	uintptr_t sourceaddress;
	uintptr_t buffer;
	size_t size;

} readmem, *preadmem;

typedef struct _base
{
	/* 
	00000000 processid       dw ?
	00000010 buffer          dd ?
	*/
	int processid;
	uintptr_t buffer;

} base, * p_base;

uintptr_t GetProcessSectionBaseAddress(int pid)
{
	base req;
	req.processid = pid;

	auto code = EncryptRequestCode(IOCTL_PsGetProcessSectionBaseAddress);

	DeviceIoControl(hHandle, code, &req, sizeof(req), &req, sizeof(req), 0, 0);

	return req.buffer;
}

template<typename T>
T Read(int pid, uintptr_t address)
{
	T buffer;

	readmem req;
	req.processid = pid;
	req.sourceaddress = address;
	req.buffer = (uintptr_t)&buffer;
	req.size = sizeof(T);

	auto code = EncryptRequestCode(IOCTL_ReadProcessMemory);

	DeviceIoControl(hHandle, code, &req, sizeof(req), &req, sizeof(req), 0, 0);

	return buffer;
}

template<typename T>
void Write(int pid, uintptr_t address, T val)
{
	readmem req;
	req.processid = pid;
	req.sourceaddress = address;
	req.buffer = (uintptr_t)&val;
	req.size = sizeof(T);

	auto code = EncryptRequestCode(IOCTL_WriteProcessMemory);

	DeviceIoControl(hHandle, code, &req, sizeof(req), &req, sizeof(req), 0, 0);
}

#include <TlHelp32.h>

DWORD GetProcessId(const std::wstring processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processesSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processesSnapshot);
	return 0;
}


int main()
{
	if (GetDriverHandle()) 
	{
		printf("hHandle: %p\n", hHandle);

		auto ProcessID = GetProcessId(L"explorer.exe");
		printf("ProcessID: %i\n", ProcessID);

		uintptr_t BaseTest = GetProcessSectionBaseAddress(ProcessID);
		uintptr_t ReadTest = Read<uintptr_t>(ProcessID, BaseTest);

		printf("GetProcessSectionBaseAddress: %p\n", BaseTest);
		printf("ReadProcessMemory: %p\n", ReadTest);
	}

	getchar();

	return 0;
}
