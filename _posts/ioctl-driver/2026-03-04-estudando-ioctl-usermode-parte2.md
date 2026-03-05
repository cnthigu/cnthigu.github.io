---
title: "Estudando IOCTL: Cliente usermode (Parte 2)"
date: 2026-03-04 15:00:00 -0300
categories: [Segurança, Kernel Development]
tags: [ioctl, usermode, driver, windows, c++, comunicação]
permalink: /estudando-ioctl-usermode-parte2/
---

## Introdução

Este post é a continuação de "[Estudando IOCTL: Criando o driver (Parte 1)](/estudando-ioctl-driver-parte1/)", onde criamos o driver kernel com IOCTL_ADD, IOCTL_READ e IOCTL_WRITE. Agora desenvolvemos o **cliente usermode** que abre o device e usa `ReadMemory`/`WriteMemory` para ler e escrever na **memória de outro processo** (notepad.exe).

O foco aqui é explicar **por que** cada parte existe e **como** obter PID e base de módulo de um processo externo. *Código baseado no projeto `krnl-ioctl-demo`.*

> ⚠️ **Aviso**: Este conteúdo é **exclusivamente educacional**. Use apenas em ambientes controlados (VMs) e para fins de aprendizado.

## Arquitetura do sistema

```
┌────────────────────────────────────────────────┐
│           USERMODE (user_mode.exe)             │
├────────────────────────────────────────────────┤
│ 1. CreateFileA("\\\\.\\SimpleDriver")          │
│ 2. GetPidByName("notepad.exe")                │
│ 3. GetModuleBase(pid, "notepad.exe")           │
│ 4. ReadMemory(addr = base, 2 bytes) → MZ       │
│ 5. WriteMemory(addr = base+0xD000, 666)        │
│ 6. ReadMemory(verify)                          │
│ 7. CloseHandle(handle)                         │
└───────────────────┬────────────────────────────┘
                    │
                    ▼
┌───────────────────────────────────────────────┐
│        KERNEL (kernel_mode.sys)               │
├───────────────────────────────────────────────┤
│ IRP_MJ_DEVICE_CONTROL                         │
│   IOCTL_READ  → MmCopyVirtualMemory (ler)     │
│   IOCTL_WRITE → MmCopyVirtualMemory (escrever)│
└───────────────────────────────────────────────┘
```

---

## headers.h (usermode)

Criamos um header para centralizar os IOCTLs, as structs, `ReadMemory`/`WriteMemory` e as funções auxiliares `GetPidByName` e `GetModuleBase`.

**Por que as structs precisam ser idênticas ao driver?** O `DeviceIoControl` envia bytes; o driver interpreta esses bytes. Se o layout for diferente (ex: um usa `#pragma pack(1)` e o outro não), os offsets dos campos mudam: o driver lê PID, Address, etc. nos lugares errados, o que pode causar **BSOD**. Veja a [explicação detalhada sobre `#pragma pack` na Parte 1](/estudando-ioctl-driver-parte1/#pragma-pack).

**GetPidByName e GetModuleBase**: Usam `CreateToolhelp32Snapshot` + `Process32FirstW`/`Process32NextW` e `Module32FirstW`/`Module32NextW` para enumerar processos e módulos. Retornam PID e endereço base do executável ou DLL.

```cpp
#pragma once
#include <iostream>
#include <windows.h>
#include <winioctl.h>
#include <tlhelp32.h>
#include <stdio.h>

#define IOCTL_ADD   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 1)
typedef struct _KERNEL_READ_REQUEST {
	ULONG ProcessId;
	ULONG_PTR Address;
	ULONG_PTR Response;
	SIZE_T Size;
} KERNEL_READ_REQUEST, * PKERNEL_READ_REQUEST;

typedef struct _KERNEL_WRITE_REQUEST {
	ULONG ProcessId;
	ULONG_PTR Address;
	ULONG_PTR Value;
	SIZE_T Size;
} KERNEL_WRITE_REQUEST, * PKERNEL_WRITE_REQUEST;
#pragma pack(pop)

bool ReadMemory(HANDLE hDevice, ULONG ProcessId, ULONG_PTR Address, SIZE_T Size, ULONG_PTR* pOutValue)
{
	KERNEL_READ_REQUEST req = { 0 };
	req.ProcessId = ProcessId;
	req.Address = Address;
	req.Size = Size;

	DWORD cbReturned = 0;

	BOOL ok = DeviceIoControl(hDevice, IOCTL_READ,
		&req, sizeof(req),
		&req, sizeof(req),
		&cbReturned,
		nullptr);

	if (ok && pOutValue)
		*pOutValue = req.Response;

	return ok != FALSE;
}

bool WriteMemory(HANDLE hDevice, ULONG ProcessId, ULONG_PTR Address, ULONG_PTR Value, SIZE_T Size)
{
	KERNEL_WRITE_REQUEST req = { 0 };
	req.ProcessId = ProcessId;
	req.Address = Address;
	req.Value = Value;
	req.Size = Size;

	DWORD cbReturned = 0;
	return DeviceIoControl(hDevice, IOCTL_WRITE, &req, sizeof(req), &req, sizeof(req), &cbReturned, nullptr) != FALSE;
}

static ULONG GetPidByName(const wchar_t* processName)
{
	ULONG pid = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	PROCESSENTRY32W pe = { sizeof(pe) };
	if (Process32FirstW(hSnapshot, &pe))
	{
		do
		{
			if (_wcsicmp(pe.szExeFile, processName) == 0)
			{
				pid = pe.th32ProcessID;
				break;
			}
		} while (Process32NextW(hSnapshot, &pe));
	}
	CloseHandle(hSnapshot);
	return pid;
}

static ULONG_PTR GetModuleBase(ULONG pid, const wchar_t* moduleName)
{
	ULONG_PTR base = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	MODULEENTRY32W me = { sizeof(me) };
	if (Module32FirstW(hSnapshot, &me))
	{
		do
		{
			if (moduleName == nullptr || _wcsicmp(me.szModule, moduleName) == 0)
			{
				base = (ULONG_PTR)me.modBaseAddr;
				break;
			}
		} while (Module32NextW(hSnapshot, &me));
	}
	CloseHandle(hSnapshot);
	return base;
}
```

---

## main.cpp: Demo com notepad.exe

O exemplo usa **notepad.exe** como processo alvo. Abra o Notepad antes de executar. O fluxo:
1. Obtém o PID com `GetPidByName(L"notepad.exe")`
2. Obtém o endereço base do executável com `GetModuleBase(pid, L"notepad.exe")`
3. Lê os 2 primeiros bytes no base (assinatura MZ de PE)
4. Tenta escrever em `base + 0xD000` (o endereço é arbitrário, só pra demonstração; o WRITE pode falhar)
5. Lê de novo para confirmar (se a escrita falhou, o valor pode não ser 666)

**Por que base + 0xD000?** É um offset qualquer. Estamos usando endereço fictício só pra mostrar o fluxo; no notepad essa região costuma ser readonly (código). Pode falhar, e está ok: o importante é ver a comunicação funcionando.

```cpp
#include "headers.h"

int main()
{
	printf("[+] SimpleDriver - Read/Write external process (notepad)\n\n");

	HANDLE hDevice = CreateFileA("\\\\.\\SimpleDriver",
		GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("[!] CreateFile failed (%lu). Driver loaded?\n", GetLastError());
		system("pause");
		return 1;
	}

	ULONG pid = GetPidByName(L"notepad.exe");
	if (pid == 0)
	{
		printf("[!] Run notepad.exe before starting.\n");
		CloseHandle(hDevice);
		system("pause");
		return 1;
	}

	ULONG_PTR base = GetModuleBase(pid, L"notepad.exe");
	if (base == 0)
	{
		printf("[!] Could not get module base.\n");
		CloseHandle(hDevice);
		system("pause");
		return 1;
	}

	printf("[+] Target: notepad.exe PID %lu base %p\n", pid, (void*)base);

	ULONG_PTR valueRead = 0;
	if (ReadMemory(hDevice, pid, base, 2, &valueRead))
	{
		WORD mz = (WORD)valueRead;
		printf("[+] READ: MZ 0x%04X (%c%c)\n", mz, (char)(mz & 0xFF), (char)(mz >> 8));
	}
	else
		printf("[!] READ failed %lu\n", GetLastError());

	// base+0xD000 é endereço arbitrário pra demo; WRITE pode falhar
	ULONG_PTR writeAddr = base + 0xD000;
	const int testValue = 666;
	if (WriteMemory(hDevice, pid, writeAddr, testValue, sizeof(int)))
		printf("[+] WRITE: %d -> %p\n", testValue, (void*)writeAddr);
	else
		printf("[!] WRITE failed (addr invalid for notepad, demo only)\n");

	valueRead = 0;
	if (ReadMemory(hDevice, pid, writeAddr, sizeof(int), &valueRead))
		printf("[+] READ verify: %llu\n", (unsigned long long)valueRead);

	CloseHandle(hDevice);
	printf("\n[+] Done\n");
	system("pause");
	return 0;
}
```

---

## GetPidByName e GetModuleBase: O que fazem

**GetPidByName**: `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` cria um snapshot de todos os processos. `Process32FirstW`/`Process32NextW` iteram; `_wcsicmp` compara o nome (case insensitive). Retorna `th32ProcessID` do processo encontrado.

**GetModuleBase**: `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)` lista os módulos (DLLs e exe) do processo. `Module32FirstW`/`Module32NextW` iteram; `modBaseAddr` é o endereço base. Se `moduleName` for o exe (ex: `notepad.exe`), retorna a base do executável.

---

## Parâmetros principais

### ReadMemory

| Parâmetro | Tipo | Descrição |
|-----------|------|-----------|
| hDevice | HANDLE | Handle do CreateFile |
| ProcessId | ULONG | PID do processo alvo |
| Address | ULONG_PTR | Endereço virtual no processo |
| Size | SIZE_T | Bytes a ler |
| pOutValue | ULONG_PTR* | Ponteiro onde o valor lido é escrito |

### WriteMemory

| Parâmetro | Tipo | Descrição |
|-----------|------|-----------|
| hDevice | HANDLE | Handle do CreateFile |
| ProcessId | ULONG | PID do processo alvo |
| Address | ULONG_PTR | Endereço destino no processo |
| Value | ULONG_PTR | Valor a escrever |
| Size | SIZE_T | Bytes a escrever |

---

## Fluxo resumido

1. **CreateFile**: Abre `\\.\SimpleDriver`
2. **GetPidByName**: Encontra notepad.exe
3. **GetModuleBase**: Obtém base do notepad.exe
4. **ReadMemory**: Lê 2 bytes no base (MZ)
5. **WriteMemory**: Escreve 666 em base+0xD000 (endereço fake, pode falhar)
6. **ReadMemory**: Confere o valor escrito
7. **CloseHandle**: Fecha o device

---

## Como estender o cliente

| Objetivo | O que fazer |
|----------|-------------|
| Outro processo | Troque `L"notepad.exe"` em `GetPidByName` e `GetModuleBase` pelo nome do executável ou DLL |
| Base de DLL | Use `GetModuleBase(pid, L"kernel32.dll")` para obter a base de uma DLL |
| Offsets dinâmicos | Use pattern scan ou cheats/engine para encontrar endereços; some ao base |
| Tratar erros | Verifique retorno de `DeviceIoControl`; use `GetLastError()` para detalhes |

---

## Resultado

Usermode abrindo o device e enviando IOCTLs; WinDbg exibindo os logs do driver:

![Usermode comunicando com driver: WinDbg com logs](/assets/img/screenshot.png)

---

## Posts relacionados

- [Estudando IOCTL: Criando o driver (Parte 1)](/estudando-ioctl-driver-parte1/)
