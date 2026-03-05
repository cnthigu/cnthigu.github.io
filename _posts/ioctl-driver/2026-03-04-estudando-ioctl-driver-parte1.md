---
title: "Estudando IOCTL Criando o driver (Parte 1)"
date: 2026-03-04 14:00:00 -0300
categories: [Segurança, Kernel Development]
tags: [ioctl, driver, kernel, windows, c++, wdm]
permalink: /estudando-ioctl-driver-parte1/
---

## Introdução

Anotações de estudo sobre **IOCTL** (Input/Output Control): a forma oficial e documentada do Windows para comunicação entre aplicações usermode e drivers kernel. Nesta **Parte 1** focamos no **driver kernel**: criar o device, receber códigos IOCTL e implementar operações de ADD, READ e WRITE de memória.

*Código baseado no projeto `krnl-ioctl-demo`.*

O objetivo aqui não é só mostrar o código, mas explicar **por que** cada parte existe e **como** adaptar para outros casos.

> ⚠️ **Aviso**: Este conteúdo é **exclusivamente educacional**. Use apenas em ambientes controlados (VMs) e para fins de aprendizado.

## O que é IOCTL?

**IOCTL** permite que um programa usermode envie comandos para um driver kernel através de um código numérico. Cada código representa uma operação: 0x801 = ADD (soma 1), 0x802 = READ (ler memória de processo), 0x803 = WRITE (escrever memória em processo).

### Fluxo resumido

```
Usermode                                  Kernel
    |                                       |
    |  CreateFile("\\\\.\\SimpleDriver")    →  IRP_MJ_CREATE
    |                                       |
    |  DeviceIoControl(IOCTL_READ, struct)  →  IRP_MJ_DEVICE_CONTROL
    |                                       |  MmCopyVirtualMemory (ler processo)
    |  ← struct com Response preenchido     |
    |                                       |
    |  CloseHandle()                        →  IRP_MJ_CLOSE
```

---

## Códigos IOCTL:  Por que precisamos deles?

O usermode envia um **número** (ex: 0x801) e o driver faz um `switch` para decidir o que fazer. Sem esse código, o driver não saberia se deve somar, ler ou escrever. A macro `CTL_CODE` gera um valor único que combina vários campos; o importante é que **driver e usermode usem exatamente as mesmas definições**.

### Parâmetros CTL_CODE

| Parâmetro | Valor | Significado |
|-----------|-------|-------------|
| DeviceType | `FILE_DEVICE_UNKNOWN` | Device genérico (não é disco, teclado, etc.) |
| Function | `0x801`–`0x803` | Código da operação. 0x800–0xFFF = faixa para drivers customizados |
| Method | `METHOD_BUFFERED` | Kernel copia buffer user ↔ kernel (mais seguro) |
| Access | `FILE_ANY_ACCESS` | Qualquer nível de acesso |

**Como adicionar outro IOCTL?** Defina um novo `#define` com outro Function (ex: 0x804) e um novo `case` no switch do `DeviceControl`.

---

## Estruturas compartilhadas: Por que kernel e usermode precisam da mesma struct?

O usermode envia bytes no buffer; o kernel recebe esses mesmos bytes. Se o layout for diferente, o driver interpreta os bytes nos offsets errados: e isso pode causar **BSOD** (tela azul). Por isso: mesma struct e mesmo packing.

---

## `#pragma pack(push, 1)`: Por que é crítico (e o que acontece se não usar) {: #pragma-pack}

**Onde usamos:** Nas structs `KERNEL_READ_REQUEST` e `KERNEL_WRITE_REQUEST`, tanto no driver quanto no usermode. Sempre rodeadas por `#pragma pack(push, 1)` e `#pragma pack(pop)`.

**O que faz:** O compilador C/C++ insere **padding** (bytes extras) entre os campos das structs para alinhamento. CPUs acessam memória mais rápido quando os dados estão alinhados (ex: um `ULONG_PTR` de 8 bytes em endereço múltiplo de 8). Sem `pack(1)`, o compilador faz isso automaticamente: e o layout da struct muda.

**Exemplo:** Em x64, sem pack:
```
KERNEL_READ_REQUEST (sem pack):
Offset 0:  ProcessId (4 bytes)
Offset 4:  [4 bytes de PADDING]  ← compilador insere
Offset 8:  Address (8 bytes)
Offset 16: Response (8 bytes)
Offset 24: Size (8 bytes)
Total: 32 bytes
```

**Com `pack(1)`:** Nenhum padding. Campos grudados:
```
KERNEL_READ_REQUEST (pack 1):
Offset 0:  ProcessId (4 bytes)
Offset 4:  Address (8 bytes)
Offset 12: Response (8 bytes)
Offset 20: Size (8 bytes)
Total: 28 bytes
```

**O problema:** Se o usermode envia 28 bytes (pack 1) e o driver espera 32 bytes (sem pack), ele lê `Address` no offset 8 em vez de 4. O valor lido é lixo ou parte de outro campo. O driver pode:

- Usar um **PID ou endereço inválido** → `PsLookupProcessByProcessId` falha, ou pior
- Passar endereços **errados** para `MmCopyVirtualMemory` → acessa memória inválida
- Escrever em **endereços incorretos** → corrupção de memória do kernel

No kernel, acesso a memória inválida ou corrupção costuma resultar em **BSOD**. Por isso o layout **precisa ser idêntico** nos dois lados.

**Resumo:** `#pragma pack(push, 1)` força alinhamento de 1 byte (sem padding). Driver e usermode passam a ver os mesmos bytes nos mesmos offsets. Sem isso, o risco de crash no kernel é alto.

---

```cpp
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
```

---

## Criando o Driver

Criamos um **headers.h** no projeto do driver para centralizar defines, structs e declarações. Assim o `driver.cpp` fica limpo e qualquer alteração (novo IOCTL, nova struct) fica em um só lugar.

### 1. headers.h (driver)

**Por que um header separado?** Centraliza defines e declarações. O `driver.cpp` só inclui `headers.h` e tem acesso a tudo. Se adicionar um novo IOCTL, muda em um lugar só.

**`#pragma once`** Evita que o header seja incluído mais de uma vez (problema de redefinição).

**`#include <ntddk.h>` e `<wdm.h>`** Headers do WDK (Windows Driver Kit). Trazem `NTSTATUS`, `PIRP`, `PDEVICE_OBJECT`, `IoCreateDevice`, etc.

**IOCTLs e nomes do device** Os defines precisam ser **idênticos** ao usermode. O `L"..."` indica string Unicode (wide string) exigida pelas APIs do kernel.

**Declarações `extern "C"`** Essas funções não vêm dos nossos .cpp; elas estão em `ntoskrnl.exe`. Declaramos para o linker encontrar. O `extern "C"` evita *name mangling* do C++ (o nome da função no binário fica exato: `IoCreateDriver`, `PsLookupProcessByProcessId`, etc.).

| Declaração | Onde está | Para que serve |
|------------|-----------|----------------|
| `IoCreateDriver` | ntoskrnl | Usada quando o driver é carregado por manual mapper (DriverObject == NULL). Cria o driver “por baixo dos panos”. |
| `PsLookupProcessByProcessId` | ntoskrnl | Converte PID em ponteiro `PEPROCESS`. Precisamos disso para acessar a memória de outro processo. |
| `MmCopyVirtualMemory` | ntoskrnl | **Não documentada.** Copia bytes entre espaços de memória de processos. Usada para Read/Write de memória. |

**Structs** Mesmo layout do usermode. `Response` em READ é preenchido pelo driver; o I/O Manager copia a struct de volta.

**ReadProcessMemory / WriteProcessMemory** São nossas funções auxiliares, implementadas em `headers.h`. Encapsulam a chamada a `MmCopyVirtualMemory` com os parâmetros na ordem correta (origem → destino).

```cpp
#pragma once

#include <ntddk.h>
#include <wdm.h>

#define IOCTL_ADD   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define DEVICE_NAME  L"\\Device\\SimpleDriver"
#define SYMLINK_NAME L"\\DosDevices\\SimpleDriver"

extern "C" NTKERNELAPI NTSTATUS IoCreateDriver(
	_In_opt_ PUNICODE_STRING DriverName,
	_In_ PDRIVER_INITIALIZE InitializationFunction);

extern "C" NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
	_In_ HANDLE ProcessId,
	_Outptr_ PEPROCESS* Process);

extern "C" NTSTATUS NTAPI MmCopyVirtualMemory(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize);

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

NTSTATUS ReadProcessMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	PEPROCESS SourceProcess = Process;
	PEPROCESS TargetProcess = PsGetCurrentProcess();
	SIZE_T BytesWritten = 0;

	NTSTATUS status = MmCopyVirtualMemory(
		SourceProcess, SourceAddress,
		TargetProcess, TargetAddress,
		Size, KernelMode, &BytesWritten);

	return status;
}

NTSTATUS WriteProcessMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	PEPROCESS SourceProcess = PsGetCurrentProcess();
	PEPROCESS TargetProcess = Process;
	SIZE_T BytesWritten = 0;

	NTSTATUS status = MmCopyVirtualMemory(
		SourceProcess, SourceAddress,
		TargetProcess, TargetAddress,
		Size, KernelMode, &BytesWritten);

	return status;
}
```

### 2. CreateClose

O kernel dispara `IRP_MJ_CREATE` quando o usermode chama `CreateFile`, e `IRP_MJ_CLOSE` quando chama `CloseHandle`. Em muitos drivers simples, não precisamos fazer nada especial: só retornar sucesso. Por isso usamos a **mesma função** para os dois evita duplicar código.

**O que faz cada linha:**
- `Irp->IoStatus.Status = STATUS_SUCCESS` Indica que a operação deu certo.
- `Irp->IoStatus.Information = 0` Nenhum byte de retorno (não é leitura/escrita).
- `IoCompleteRequest` **Obrigatório.** Sinaliza ao I/O Manager que terminamos. Sem isso, o usermode fica esperando para sempre.

```cpp
NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}
```

### 3. DeviceControl IOCTL_ADD (o caso mais simples)

IOCTL_ADD é bom para entender o fluxo: o usermode envia um `int`, o driver soma 1 e devolve no mesmo buffer. Com `METHOD_BUFFERED`, o I/O Manager já copiou os bytes para `pSystemBuffer`. Fazemos um cast para `int*`, modificamos o valor, e informamos quantos bytes retornar (`cbBytesReturned`). O I/O Manager copia de volta para o buffer do usermode.

```cpp
case IOCTL_ADD:
{
	if (cbInputBufferLength >= sizeof(int) && cbOutputBufferLength >= sizeof(int) && pSystemBuffer != NULL)
	{
		int* pValue = (int*)pSystemBuffer;
		*pValue = *pValue + 1;
		cbBytesReturned = sizeof(int);
		status = STATUS_SUCCESS;
		DbgPrint("[+] IOCTL_ADD: %d -> %d\n", *pValue - 1, *pValue);
	}
	else
		status = STATUS_BUFFER_TOO_SMALL;
	break;
}
```

### 4. DeviceControl IOCTL_READ (ler memória de outro processo)

O usermode envia `KERNEL_READ_REQUEST` com `ProcessId`, `Address` e `Size`. O driver:
1. Obtém o `PEPROCESS` do processo alvo com `PsLookupProcessByProcessId`.
2. Chama `ReadProcessMemory` (que usa `MmCopyVirtualMemory`) para copiar bytes do processo alvo para o campo `Response` da nossa struct.
3. Chama `ObfDereferenceObject(Process)` **importante** para evitar leak de referência.
4. Define `cbBytesReturned = sizeof(KERNEL_READ_REQUEST)` para o I/O Manager copiar a struct inteira (com `Response` preenchido) de volta.

```cpp
case IOCTL_READ:
{
    if (cbInputBufferLength >= sizeof(KERNEL_READ_REQUEST) && cbOutputBufferLength >= sizeof(KERNEL_READ_REQUEST) && pSystemBuffer != NULL)
    {
        PKERNEL_READ_REQUEST ReadRequest = (PKERNEL_READ_REQUEST)pSystemBuffer;
        PEPROCESS Process = NULL;

        status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ReadRequest->ProcessId, &Process);

        if (NT_SUCCESS(status))
        {
            status = ReadProcessMemory(Process,
                (PVOID)ReadRequest->Address,
                (PVOID)&ReadRequest->Response,
                ReadRequest->Size);

            ObfDereferenceObject(Process);

            if (NT_SUCCESS(status))
            {
                cbBytesReturned = sizeof(KERNEL_READ_REQUEST);
            }
        }
    }
    else
    {
        status = STATUS_BUFFER_TOO_SMALL;
    }
    break;
}
```

### 5. DeviceControl IOCTL_WRITE (escrever memória em outro processo)

Similar ao READ, mas o fluxo é invertido: copiamos *de* nosso buffer (onde está `Value`) *para* o endereço `Address` no processo alvo. `WriteProcessMemory` usa `MmCopyVirtualMemory` com origem = nosso processo, destino = processo alvo.

**Na demo:** o usermode envia um endereço qualquer (ex: `base + 0xD000`) só pra testar o fluxo. Esse endereço pode ser inválido ou readonly; se o WRITE falhar, é esperado.

```cpp
case IOCTL_WRITE:
{
    if (cbInputBufferLength >= sizeof(KERNEL_WRITE_REQUEST) && cbOutputBufferLength >= sizeof(KERNEL_WRITE_REQUEST) && pSystemBuffer != NULL)
    {
        PKERNEL_WRITE_REQUEST WriteRequest = (PKERNEL_WRITE_REQUEST)pSystemBuffer;
        PEPROCESS Process = NULL;

        status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)WriteRequest->ProcessId, &Process);

        if (NT_SUCCESS(status))
        {
            status = WriteProcessMemory(Process,
                (PVOID)&WriteRequest->Value,
                (PVOID)WriteRequest->Address,
                WriteRequest->Size);

            ObfDereferenceObject(Process);

            if (NT_SUCCESS(status))
            {
                cbBytesReturned = sizeof(KERNEL_WRITE_REQUEST);
            }
        }
    }
    else
    {
        status = STATUS_BUFFER_TOO_SMALL;
    }
    break;
}
```

### 6. ReadProcessMemory e WriteProcessMemory Encapsulando MmCopyVirtualMemory

`MmCopyVirtualMemory` é a API de baixo nível. Ela recebe: processo origem, endereço origem, processo destino, endereço destino, tamanho. Para **Read**: origem = processo alvo, destino = nosso (driver). Para **Write**: origem = nosso, destino = processo alvo. Criar essas funções auxiliares deixa o `DeviceControl` mais legível.

**Por que `PsGetCurrentProcess()`?** O driver roda no contexto do kernel; `PsGetCurrentProcess()` retorna o "processo" do kernel (ou do sistema). Usamos como processo de origem/destino quando os dados estão no nosso lado.

```cpp
NTSTATUS ReadProcessMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	PEPROCESS SourceProcess = Process;
	PEPROCESS TargetProcess = PsGetCurrentProcess();
	SIZE_T BytesWritten = 0;

	NTSTATUS status = MmCopyVirtualMemory(
		SourceProcess, SourceAddress,
		TargetProcess, TargetAddress,
		Size, KernelMode, &BytesWritten);

	return status;
}

NTSTATUS WriteProcessMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	PEPROCESS SourceProcess = PsGetCurrentProcess();
	PEPROCESS TargetProcess = Process;
	SIZE_T BytesWritten = 0;

	NTSTATUS status = MmCopyVirtualMemory(
		SourceProcess, SourceAddress,
		TargetProcess, TargetAddress,
		Size, KernelMode, &BytesWritten);

	return status;
}
```

### 7. UnloadDriver Limpeza ao descarregar

Quando o driver é descarregado (ex: `sc stop` ou manual mapper unload), o sistema chama `UnloadDriver`. Precisamos:
1. Remover o **symlink** primeiro (`IoDeleteSymbolicLink`) senão ficam referências ao device.
2. Remover o **device** (`IoDeleteDevice`). A ordem importa: symlink antes do device.

```cpp
VOID UnloadDriver(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING sym;
    RtlInitUnicodeString(&sym, SYMLINK_NAME);
    IoDeleteSymbolicLink(&sym);

    if (DriverObject->DeviceObject != NULL)
    {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}
```

### 8. DriverInitialize Registrar handlers e criar o device

Aqui configuramos o driver:
- **MajorFunction** Array de ponteiros para funções. Diz ao kernel: "quando chegar IRP_MJ_CREATE, chame CreateClose; quando chegar IRP_MJ_DEVICE_CONTROL, chame DeviceControl".
- **IoCreateDevice** Cria o dispositivo `\Device\SimpleDriver`. O nome é interno; o usermode não acessa diretamente.
- **IoCreateSymbolicLink** Cria `\DosDevices\SimpleDriver` apontando para o device. O usermode abre com `\\.\SimpleDriver`, que resolve para esse symlink.
- **DO_BUFFERED_IO** Usa buffered I/O (compatível com METHOD_BUFFERED).
- **DO_DEVICE_INITIALIZING** Removemos essa flag para que o device aceite I/O. Durante a criação, ela impede acesso; depois de configurado, desligamos.

**Como criar outro device?** Basta alterar `DEVICE_NAME` e `SYMLINK_NAME` e usar nomes diferentes (ex: `SimpleDriver2`).

```cpp
NTSTATUS DriverInitialize(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    DriverObject->DriverUnload = UnloadDriver;

    UNICODE_STRING dev, sym;
    PDEVICE_OBJECT pDevice = NULL;

    RtlInitUnicodeString(&dev, DEVICE_NAME);

    NTSTATUS status = IoCreateDevice(DriverObject, 0, &dev,
        FILE_DEVICE_UNKNOWN, 0, TRUE, &pDevice);

    if (!NT_SUCCESS(status))
        return status;

    RtlInitUnicodeString(&sym, SYMLINK_NAME);
    status = IoCreateSymbolicLink(&sym, &dev);

    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(pDevice);
        return status;
    }

    pDevice->Flags |= DO_BUFFERED_IO;
    pDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}
```

### 9. DriverEntry Ponto de entrada e suporte a manual mapping

`DriverEntry` é chamado quando o driver é carregado. Existem dois cenários:
1. **Loader tradicional** (sc load, SCM) O sistema passa um `DriverObject` válido. Chamamos `DriverInitialize` diretamente.
2. **Manual mapper** (kdmapper, etc.) O loader passa `DriverObject == NULL`. Nesse caso, usamos `IoCreateDriver` para criar o driver internamente; ele chama nossa `DriverInitialize` com um novo `DriverObject`.

**Por que `extern "C"`?** O loader procura o símbolo `DriverEntry` pelo nome exato. C++ faz *name mangling* (ex: `DriverEntry` vira `?DriverEntry@@...`). Com `extern "C"`, o nome fica `DriverEntry` e o loader encontra.

```cpp
extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    if (!DriverObject)
    {
        UNICODE_STRING driverName;
        RtlInitUnicodeString(&driverName, L"\\Driver\\SimpleDriver");
        return IoCreateDriver(&driverName, &DriverInitialize);
    }
    return DriverInitialize(DriverObject, RegistryPath);
}
```

---

## DeviceControl Obtendo buffer e parâmetros

No início do `DeviceControl`, precisamos dos dados enviados pelo usermode:

- **`IoGetCurrentIrpStackLocation`** Cada driver na pilha tem uma "stack location" no IRP. Os parâmetros do `DeviceIoControl` (InputBufferLength, OutputBufferLength, IoControlCode) ficam lá.
- **`Irp->AssociatedIrp.SystemBuffer`** Com `METHOD_BUFFERED`, o I/O Manager aloca um buffer e copia os dados do usermode para cá. É um `PVOID`; fazemos cast para a struct ou tipo correto.
- **Validar tamanhos** Sempre checar `cbInputBufferLength >= sizeof(struct)` e `pSystemBuffer != NULL` antes de acessar. Buffer pequeno ou nulo pode causar BSOD.

```cpp
PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(Irp);
PVOID pSystemBuffer = Irp->AssociatedIrp.SystemBuffer;
ULONG cbInputBufferLength = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
ULONG cbOutputBufferLength = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
ULONG IoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
```

Ao final:

```cpp
Irp->IoStatus.Status = status;
Irp->IoStatus.Information = cbBytesReturned;
IoCompleteRequest(Irp, IO_NO_INCREMENT);
return status;
```

---

## METHOD_BUFFERED Por que usar?

`METHOD_BUFFERED` é o mais seguro para começar: o I/O Manager cuida de tudo. O usermode passa um buffer; o kernel **copia** esse buffer para memória kernel (`SystemBuffer`). O driver trabalha apenas com a cópia não acessa memória do usermode diretamente. Depois, o I/O Manager copia de volta (até `IoStatus.Information` bytes) para o buffer de saída do usermode. Se precisar de buffers grandes ou zerocopy, estude `METHOD_IN_DIRECT` / `METHOD_OUT_DIRECT`.

---

## Como estender este driver

| Objetivo | O que fazer |
|----------|-------------|
| Novo IOCTL (ex: obter base de DLL) | Adicione `#define IOCTL_GET_BASE 0x804`, crie struct com PID + nome do módulo, adicione `case IOCTL_GET_BASE` no switch |
| Ler/escrever em outro processo | Use o PID do processo alvo em `KERNEL_READ_REQUEST` / `KERNEL_WRITE_REQUEST`; o fluxo já suporta |
| Validar PID antes de usar | Chame `PsLookupProcessByProcessId` e verifique `NT_SUCCESS(status)` antes de qualquer acesso |
| Buffers maiores | Considere `METHOD_IN_DIRECT` ou `METHOD_OUT_DIRECT` para evitar cópia dupla |

---

## Código completo do driver (driver.cpp)

*Projeto: `krnl-ioctl-demo/kernel_mode`*

```cpp
#include "headers.h"

NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(Irp);
	PVOID pSystemBuffer = Irp->AssociatedIrp.SystemBuffer;

	ULONG cbInputBufferLength = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	ULONG cbOutputBufferLength = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	ULONG IoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;

	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	ULONG cbBytesReturned = 0;

	switch (IoControlCode)
	{
	case IOCTL_ADD:
	{
		if (cbInputBufferLength >= sizeof(int) && cbOutputBufferLength >= sizeof(int) && pSystemBuffer != NULL)
		{
			int* pValue = (int*)pSystemBuffer;
			*pValue = *pValue + 1;
			cbBytesReturned = sizeof(int);
			status = STATUS_SUCCESS;
			DbgPrint("[+] IOCTL_ADD: %d -> %d\n", *pValue - 1, *pValue);
		}
		else
		{
			status = STATUS_BUFFER_TOO_SMALL;
		}
		break;
	}

	case IOCTL_READ:
	{
		if (cbInputBufferLength >= sizeof(KERNEL_READ_REQUEST) && cbOutputBufferLength >= sizeof(KERNEL_READ_REQUEST) && pSystemBuffer != NULL)
		{
			PKERNEL_READ_REQUEST ReadRequest = (PKERNEL_READ_REQUEST)pSystemBuffer;
			PEPROCESS Process = NULL;

			status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ReadRequest->ProcessId, &Process);
			if (!NT_SUCCESS(status))
			{
				DbgPrint("[+] READ: PID %lu not found 0x%08X\n", ReadRequest->ProcessId, status);
				break;
			}

			status = ReadProcessMemory(Process,
				(PVOID)ReadRequest->Address,
				(PVOID)&ReadRequest->Response,
				ReadRequest->Size);

			ObfDereferenceObject(Process);

			if (NT_SUCCESS(status))
			{
				cbBytesReturned = sizeof(KERNEL_READ_REQUEST);
				DbgPrint("[+] READ: PID %lu addr %p -> %llu bytes\n", ReadRequest->ProcessId, (void*)ReadRequest->Address, (unsigned long long)ReadRequest->Size);
			}
			else
			{
				DbgPrint("[+] READ: MmCopyVirtualMemory failed 0x%08X\n", status);
			}
		}
		else
			status = STATUS_BUFFER_TOO_SMALL;
		break;
	}

	case IOCTL_WRITE:
	{
		if (cbInputBufferLength >= sizeof(KERNEL_WRITE_REQUEST) && cbOutputBufferLength >= sizeof(KERNEL_WRITE_REQUEST) && pSystemBuffer != NULL)
		{
			PKERNEL_WRITE_REQUEST WriteRequest = (PKERNEL_WRITE_REQUEST)pSystemBuffer;
			PEPROCESS Process = NULL;

			status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)WriteRequest->ProcessId, &Process);
			if (!NT_SUCCESS(status))
			{
				DbgPrint("[+] WRITE: PID %lu not found 0x%08X\n", WriteRequest->ProcessId, status);
				break;
			}

			status = WriteProcessMemory(Process,
				(PVOID)&WriteRequest->Value,
				(PVOID)WriteRequest->Address,
				WriteRequest->Size);

			ObfDereferenceObject(Process);

			if (NT_SUCCESS(status))
			{
				cbBytesReturned = sizeof(KERNEL_WRITE_REQUEST);
				DbgPrint("[+] WRITE: PID %lu addr %p %llu bytes\n", WriteRequest->ProcessId, (void*)WriteRequest->Address, (unsigned long long)WriteRequest->Size);
			}
			else
			{
				DbgPrint("[+] WRITE: failed 0x%08X (addr fake/arbitrário na demo, pode falhar)\n", status);
			}
		}
		else
			status = STATUS_BUFFER_TOO_SMALL;
		break;
	}

	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = cbBytesReturned;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

VOID UnloadDriver(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING sym;
	RtlInitUnicodeString(&sym, SYMLINK_NAME);
	IoDeleteSymbolicLink(&sym);

	if (DriverObject->DeviceObject != NULL)
	{
		IoDeleteDevice(DriverObject->DeviceObject);
	}

	DbgPrint("[+] UnloadDriver: device removed\n");
}

NTSTATUS DriverInitialize(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
	DriverObject->DriverUnload = UnloadDriver;

	UNICODE_STRING dev, sym;
	PDEVICE_OBJECT pDevice = NULL;

	RtlInitUnicodeString(&dev, DEVICE_NAME);

	NTSTATUS status = IoCreateDevice(DriverObject, 0, &dev,
		FILE_DEVICE_UNKNOWN, 0, TRUE, &pDevice);

	if (!NT_SUCCESS(status))
		return status;

	RtlInitUnicodeString(&sym, SYMLINK_NAME);
	status = IoCreateSymbolicLink(&sym, &dev);

	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDevice);
		return status;
	}

	pDevice->Flags |= DO_BUFFERED_IO;
	pDevice->Flags &= ~DO_DEVICE_INITIALIZING;

	DbgPrint("[+] Driver loaded\n");

	return STATUS_SUCCESS;
}

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	if (!DriverObject)
	{
		UNICODE_STRING driverName;
		RtlInitUnicodeString(&driverName, L"\\Driver\\SimpleDriver");
		return IoCreateDriver(&driverName, &DriverInitialize);
	}
	return DriverInitialize(DriverObject, RegistryPath);
}
```

---

**Próximo post:** [Estudando IOCTL: Cliente usermode (Parte 2)](/estudando-ioctl-usermode-parte2/)
