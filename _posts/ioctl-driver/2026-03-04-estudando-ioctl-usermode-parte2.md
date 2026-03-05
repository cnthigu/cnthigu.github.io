---
title: "Estudando IOCTL Cliente usermode (Parte 2)"
date: 2026-03-04 15:00:00 -0300
categories: [Segurança, Kernel Development]
tags: [ioctl, usermode, driver, windows, c++, comunicação]
permalink: /estudando-ioctl-usermode-parte2/
---

## Introdução

Este post é a continuação de "[Estudando IOCTL  Criando o driver (Parte 1)](/estudando-ioctl-driver-parte1/)", onde criamos o driver kernel com IOCTL_ADD, IOCTL_READ e IOCTL_WRITE. Agora desenvolvemos o **cliente usermode** que abre o device e usa `ReadMemory`/`WriteMemory` para ler e escrever na memória do próprio processo.

O foco aqui é explicar **por que** cada parte existe e **como** adaptar para outros cenários (ler outro processo, novos IOCTLs, etc.).

> ⚠️ **Aviso**: Este conteúdo é **exclusivamente educacional**. Use apenas em ambientes controlados (VMs) e para fins de aprendizado.

## Arquitetura do sistema

```
┌────────────────────────────────────────────────┐
│           USERMODE (user_mode.exe)             │
├────────────────────────────────────────────────┤
│ 1. CreateFileA("\\\\.\\SimpleDriver")          │
│ 2. ReadMemory(hDevice, pid, addr, size, &out)  │
│ 3. WriteMemory(hDevice, pid, addr, value, size)│
│ 4. ReadMemory(...) para confirmar              │
│ 5. CloseHandle(handle)                         │
└───────────────────┬────────────────────────────┘
                    │
                    ▼
┌───────────────────────────────────────────────┐
│        KERNEL (testeioclt.sys)                │
├───────────────────────────────────────────────┤
│ IRP_MJ_DEVICE_CONTROL                         │
│   IOCTL_READ  → MmCopyVirtualMemory (ler)     │
│   IOCTL_WRITE → MmCopyVirtualMemory (escrever)│
└───────────────────────────────────────────────┘
```

---

## headers.h (usermode)

Criamos um header para centralizar os IOCTLs, as structs e as funções `ReadMemory`/`WriteMemory`. Assim o `main.cpp` fica limpo e qualquer alteração (novo IOCTL, nova struct) fica em um só lugar.

**Por que as structs precisam ser idênticas ao driver?** O `DeviceIoControl` envia bytes; o driver interpreta esses bytes como `KERNEL_READ_REQUEST` ou `KERNEL_WRITE_REQUEST`. Se o layout for diferente, os campos ficarão desalinhados.

**Por que `ReadMemory` recebe `pOutValue` como ponteiro?** O valor lido vem *do kernel*; a função precisa *escrever* no endereço que o chamador passa. Sem `ULONG_PTR*`, só poderíamos retornar um valor mas `bool` já é o retorno (sucesso/falha). O `*pOutValue` é a forma de devolver o valor lido.

**Por que o mesmo buffer para input e output em `DeviceIoControl`?** Em READ, a struct tem `ProcessId`, `Address`, `Size` (entrada) e `Response` (saída). O driver preenche `Response` e o I/O Manager copia a struct inteira de volta. Usar `&req` nos dois lados economiza alocação e simplifica.

```cpp
#pragma once
#include <iostream>
#include <windows.h>
#include <winioctl.h>

#define IOCTL_ADD   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 1)
typedef struct _KERNEL_READ_REQUEST {
	ULONG ProcessId;
	ULONG_PTR Address;
	ULONG_PTR Response;
	SIZE_T Size;
} KERNEL_READ_REQUEST, *PKERNEL_READ_REQUEST;

typedef struct _KERNEL_WRITE_REQUEST {
	ULONG ProcessId;
	ULONG_PTR Address;
	ULONG_PTR Value;
	SIZE_T Size;
} KERNEL_WRITE_REQUEST, *PKERNEL_WRITE_REQUEST;
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
		&cbReturned, nullptr);

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
```

---

## main.cpp Fluxo de teste

O exemplo lê e escreve na **memória do próprio processo** para simplificar: não precisamos encontrar outro PID nem obter endereços de outro executable. Usamos `GetCurrentProcessId()` e `&meuInt` (endereço de uma variável local).

**Por que `\\.\SimpleDriver`?** O prefixo `\\.\` é usado para abrir devices. O Windows resolve para `\DosDevices\SimpleDriver`, que é o symlink que o driver criou.

**Por que `GENERIC_READ | GENERIC_WRITE`?** `DeviceIoControl` com IOCTLs de leitura/escrita exige essas permissões. Sem elas, a chamada pode falhar com ACCESS_DENIED.

**Como ler outro processo?** Troque `GetCurrentProcessId()` pelo PID do processo alvo (ex: via `CreateToolhelp32Snapshot` + `Process32First`/`Process32Next`) e use o endereço virtual dentro daquele processo (ex: base de uma DLL + offset).

```cpp
#include "headers.h"

int main()
{
	printf("[+] Iniciando...\n");

	HANDLE hDevice = CreateFileA("\\\\.\\SimpleDriver",
		GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("[+] CreateFile FALHOU: %lu\n", GetLastError());
		system("pause");
		return 1;
	}

	ULONG pid = GetCurrentProcessId();
	int meuInt = 100;
	ULONG_PTR addr = (ULONG_PTR)&meuInt;
	ULONG_PTR valorLido = 0;

	if (ReadMemory(hDevice, pid, addr, sizeof(int), &valorLido))
	{
		printf("[+] Read OK: endereco %p = %llu\n", (void*)addr, (unsigned long long)valorLido);
	}
	else
	{
		printf("[+] Read FALHOU: %lu\n", GetLastError());
	}

	if (WriteMemory(hDevice, pid, addr, 666, sizeof(int)))
	{
		printf("[+] Write OK: 666 -> endereco %p\n", (void*)addr);
	}
	else
	{
		printf("[+] Write FALHOU: %lu\n", GetLastError());
	}

	if (ReadMemory(hDevice, pid, addr, sizeof(int), &valorLido))
	{
		printf("[+] Read OK: endereco %p agora = %llu\n", (void*)addr, (unsigned long long)valorLido);
	}
	else
	{
		printf("[+] Read FALHOU: %lu\n", GetLastError());
	}

	CloseHandle(hDevice);
	printf("[+] Fim\n");
	system("pause");
	return 0;
}
```

---

## Parâmetros principais — O que cada um faz

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

### DeviceIoControl  Parâmetros

```
DeviceIoControl(
    hDevice,           // handle do CreateFile
    IOCTL_READ,        // código que identifica a operação
    &req, sizeof(req), // buffer de entrada + tamanho
    &req, sizeof(req), // buffer de saída + tamanho (mesmo buffer = req)
    &cbReturned,       // a API escreve aqui quantos bytes retornou
    nullptr            // overlapped = nullptr para chamada síncrona (bloqueia até terminar)
);
```

O mesmo buffer `req` é usado para entrada e saída. Em READ, o driver preenche `req.Response`; o I/O Manager copia a struct inteira de volta. O `cbReturned` é preenchido pela API — útil para saber se o driver retornou dados.

---

## Fluxo resumido

1. **CreateFile** — Abre `\\.\SimpleDriver` (symlink para `\Device\SimpleDriver`)
2. **ReadMemory** — Monta `KERNEL_READ_REQUEST`, chama `DeviceIoControl(IOCTL_READ)`, recebe `Response`
3. **WriteMemory** — Monta `KERNEL_WRITE_REQUEST`, chama `DeviceIoControl(IOCTL_WRITE)`
4. **CloseHandle** — Fecha o device

---

## Como estender o cliente

| Objetivo | O que fazer |
|----------|-------------|
| Ler outro processo | Use `CreateToolhelp32Snapshot` + `Process32First`/`Process32Next` para obter o PID; passe esse PID em `ReadMemory`/`WriteMemory` |
| Obter endereço de variável em outro processo | Use pattern scan, base de DLL + offset, ou (em contexto educacional) Cheat Engine para achar o endereço |
| Novo IOCTL (ex: IOCTL_ADD) | Adicione o `#define` no headers.h (igual ao driver) e chame `DeviceIoControl` com o código e buffers apropriados |
| Tratar erros | Verifique o retorno de `DeviceIoControl` (BOOL); use `GetLastError()` para códigos de erro detalhados |

---

## Resultado

Usermode abrindo o device e enviando IOCTLs; WinDbg exibindo os logs do driver:

![Usermode comunicando com driver — WinDbg com logs](/assets/img/screenshot.png)

---

## Posts relacionados

- [Estudando IOCTL — Criando o driver (Parte 1)](/estudando-ioctl-driver-parte1/)
