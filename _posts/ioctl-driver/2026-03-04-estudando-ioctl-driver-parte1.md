---
title: "Estudando IOCTL Criando o driver (Parte 1)"
date: 2026-03-04 14:00:00 -0300
categories: [Segurança, Kernel Development]
tags: [ioctl, driver, kernel, windows, c++, wdm]
permalink: /estudando-ioctl-driver-parte1/
---

## Introdução

Anotações de estudo sobre **IOCTL** (Input/Output Control) A forma oficial e documentada do Windows para comunicação entre aplicações usermode e drivers kernel. Nesta **Parte 1** focamos no **driver kernel**: criar o device, receber códigos IOCTL (0x801–0x804) e responder às requisições.

> **Aviso**: Este conteúdo é **exclusivamente educacional** para fins de aprendizado.

## O que é IOCTL?

**IOCTL** permite que um programa usermode envie "comandos" para um driver kernel através de um código numérico. Cada código representa uma operação diferente (ex: 0x801 = soma, 0x802 = subtração). O driver recebe o código e executa a lógica correspondente.

### Fluxo resumido

```
Usermode                          Kernel
    |                                |
    |  CreateFile("\\\\.\\SimpleDriver")  →  IRP_MJ_CREATE
    |                                |
    |  DeviceIoControl(IOCTL_ADD, ...)    →  IRP_MJ_DEVICE_CONTROL
    |                                |      switch(0x801) → executa ADD
    |  ← resultado no buffer         |
    |                                |
    |  CloseHandle()                 →  IRP_MJ_CLOSE
```

---

## Códigos IOCTL: A macro CTL_CODE e a faixa 0x800

Os códigos que nosso driver recebe são definidos pela macro `CTL_CODE`:

```cpp
#define CTL_CODE(DeviceType, Function, Method, Access)

#define IOCTL_ADD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

### Parâmetros

| Parâmetro | Nosso valor | Significado |
|-----------|-------------|-------------|
| DeviceType | `FILE_DEVICE_UNKNOWN` (0x22) | Tipo de device; UNKNOWN = device genérico |
| Function | `0x801`, `0x802`, etc. | Código da operação (0x800–0xFFF = custom) |
| Method | `METHOD_BUFFERED` | Como dados in/out são transferidos |
| Access | `FILE_ANY_ACCESS` | Nível de acesso (qualquer) |

### Faixa 0x800

Os **function codes** entre **0x800** e **0xFFF** são reservados para drivers customizados. A Microsoft usa a faixa 0x000 - 0x7FF. Por isso usamos 0x801, 0x802, 0x803, 0x804 são códigos "nos nossos".

### Nossos códigos

| Define | Function | Operação |
|--------|----------|----------|
| IOCTL_ADD | 0x801 | Soma |
| IOCTL_SUB | 0x802 | Subtração |
| IOCTL_MUL | 0x803 | Multiplicação |
| IOCTL_DIV | 0x804 | Divisão |

---

## Criando o Driver — Passo a Passo

### 1. Definições e Device/Symlink

```cpp
#define IOCTL_ADD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SUB CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MUL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIV CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define DEVICE_NAME L"\\Device\\SimpleDriver"
#define SYMLINK_NAME L"\\DosDevices\\SimpleDriver"
```

- **Device**: `\Device\SimpleDriver` = nome interno no kernel
- **Symlink**: `\DosDevices\SimpleDriver` = permite ao usermode abrir via `\\.\SimpleDriver`

### 2. Create/Close — Abertura e fechamento de handle

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

Tanto `CreateFile` quanto `CloseHandle` do usermode disparam IRPs que vão para a mesma função. Só retornamos sucesso.

### 3. DeviceControl — Onde os IOCTLs são processados

```cpp
NTSTATUS DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG bytes = 0;

    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_ADD:
        DbgPrint("[+] IOCTL_ADD received\n");
        break;
    case IOCTL_SUB:
        DbgPrint("[+] IOCTL_SUB received\n");
        break;
    case IOCTL_MUL:
        DbgPrint("[+] IOCTL_MUL received\n");
        break;
    case IOCTL_DIV:
        DbgPrint("[+] IOCTL_DIV received\n");
        break;
    default:
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytes;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
```

- `IoGetCurrentIrpStackLocation` : pega a pilha do IRP atual
- `IoControlCode` : valor enviado pelo usermode (0x801, 0x802, etc.)
- `IoCompleteRequest` : finaliza o IRP (obrigatório)

### 4. UnloadDriver — Limpeza ao descarregar

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

    DbgPrint("[+] Unload Driver...");
}
```

Ordem: remove symlink primeiro, depois o device.

### 5. DriverInitialize — Registrar device e handlers

```cpp
NTSTATUS DriverInitialize(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    DriverObject->DriverUnload = UnloadDriver;

    UNICODE_STRING dev, sym;
    PDEVICE_OBJECT pDevice;

    RtlInitUnicodeString(&dev, DEVICE_NAME);

    NTSTATUS status = IoCreateDevice(DriverObject, 0, &dev,
        FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, TRUE, &pDevice);

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

    DbgPrint("[+] Driver Initialize...");

    return STATUS_SUCCESS;
}
```

- **DO_BUFFERED_IO**: I/O Manager copia dados usermode ↔ buffer kernel. Compatível com `METHOD_BUFFERED`.
- **DO_DEVICE_INITIALIZING**: Remove essa flag para permitir handles.

### 6. DriverEntry Suporte a manual mapping

```cpp
extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    // Padrão: loaders como kdmapper passam NULL; usa IoCreateDriver
    if (!DriverObject)
    {
        UNICODE_STRING driverName;
        RtlInitUnicodeString(&driverName, L"\\Driver\\SimpleDriver");
        return IoCreateDriver(&driverName, &DriverInitialize);
    }

    DbgPrint("[+] Driver Entry...");
    return DriverInitialize(DriverObject, RegistryPath);
}
```

Quando o driver é carregado via manual mapper (kdmapper, etc.), `DriverObject` vem `NULL`. Nesse caso usamos `IoCreateDriver`.

---

## METHOD_BUFFERED  Transferência de dados

Com `METHOD_BUFFERED`:
- O I/O Manager aloca um buffer no kernel
- Copia os dados de entrada do usermode para esse buffer
- O driver lê de `Irp->AssociatedIrp.SystemBuffer`
- Para saída, o driver escreve no mesmo buffer; o I/O Manager copia de volta

| Method | Input | Output |
|--------|-------|--------|
| METHOD_BUFFERED | SystemBuffer | SystemBuffer |
| METHOD_IN_DIRECT | SystemBuffer | MDL (user buffer mapeado) |
| METHOD_OUT_DIRECT | SystemBuffer | MDL |
| METHOD_NEITHER | User buffer direto | User buffer direto |

---

## Código completo do driver (driver.cpp)

```cpp
#include <ntddk.h>

extern "C" NTKERNELAPI NTSTATUS IoCreateDriver(
    _In_opt_ PUNICODE_STRING DriverName,
    _In_ PDRIVER_INITIALIZE InitializationFunction);

#define IOCTL_ADD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SUB CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MUL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIV CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define DEVICE_NAME L"\\Device\\SimpleDriver"
#define SYMLINK_NAME L"\\DosDevices\\SimpleDriver"

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
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG bytes = 0;

    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_ADD:
        DbgPrint("[+] IOCTL_ADD received\n");
        break;
    case IOCTL_SUB:
        DbgPrint("[+] IOCTL_SUB received\n");
        break;
    case IOCTL_MUL:
        DbgPrint("[+] IOCTL_MUL received\n");
        break;
    case IOCTL_DIV:
        DbgPrint("[+] IOCTL_DIV received\n");
        break;
    default:
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytes;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

VOID UnloadDriver(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING sym;
    RtlInitUnicodeString(&sym, SYMLINK_NAME);
    IoDeleteSymbolicLink(&sym);
    if (DriverObject->DeviceObject != NULL)
        IoDeleteDevice(DriverObject->DeviceObject);
    DbgPrint("[+] Unload Driver...");
}

NTSTATUS DriverInitialize(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    DriverObject->DriverUnload = UnloadDriver;

    UNICODE_STRING dev, sym;
    PDEVICE_OBJECT pDevice;
    RtlInitUnicodeString(&dev, DEVICE_NAME);

    NTSTATUS status = IoCreateDevice(DriverObject, 0, &dev,
        FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, TRUE, &pDevice);

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
    DbgPrint("[+] Driver Initialize...");
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
    DbgPrint("[+] Driver Entry...");
    return DriverInitialize(DriverObject, RegistryPath);
}
```
---

**Próximo post:** [Estudando IOCTL — Cliente usermode (Parte 2)](/estudando-ioctl-usermode-parte2/)