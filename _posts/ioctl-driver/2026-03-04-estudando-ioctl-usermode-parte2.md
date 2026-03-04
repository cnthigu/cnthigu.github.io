---
title: "Estudando IOCTL Cliente usermode (Parte 2)"
date: 2026-03-04 15:00:00 -0300
categories: [Segurança, Kernel Development]
tags: [ioctl, usermode, driver, windows, c++, comunicação]
permalink: /estudando-ioctl-usermode-parte2/
---

## Introdução

Este post é a continuação de "[Estudando IOCTL — Criando o driver (Parte 1)](/estudando-ioctl-driver-parte1/)", onde criamos o driver kernel que recebe códigos IOCTL. Agora vamos desenvolver o **cliente usermode** que abre o device e envia os comandos via `DeviceIoControl`.

> ⚠️ **Aviso**: Este conteúdo é **exclusivamente educacional** para fins de aprendizado.

## Arquitetura do sistema

```
┌─────────────────────────────────────────────┐
│           USERMODE (user_mode.exe)          │
├─────────────────────────────────────────────┤
│ 1. CreateFileA("\\\\.\\SimpleDriver")       │
│ 2. DeviceIoControl(handle, IOCTL_ADD, ...)  │
│ 3. DeviceIoControl(handle, IOCTL_SUB, ...)  │
│    ...                                      │
│ 4. CloseHandle(handle)                      │
└──────────────────┬──────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────┐
│        KERNEL (testeioclt.sys)              │
├─────────────────────────────────────────────┤
│ IRP_MJ_DEVICE_CONTROL                       │
│   switch(IoControlCode)                     │
│     case 0x801: IOCTL_ADD                   │
│     case 0x802: IOCTL_SUB                   │
│     case 0x803: IOCTL_MUL                   │
│     case 0x804: IOCTL_DIV                   │
└─────────────────────────────────────────────┘
```

---

## Abrindo o device

```cpp
HANDLE hDevice = CreateFileA("\\\\.\\SimpleDriver",
    GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
```

- `\\\\.\\` — prefixo para devices (dois backslashes escapados em C/C++)
- `\\.\SimpleDriver` → resolve para `\DosDevices\SimpleDriver` → `\Device\SimpleDriver`
- Se o driver não estiver carregado: `CreateFile` falha (erro 2, FILE_NOT_FOUND)

---

## Enviando IOCTL

```cpp
DeviceIoControl(hDevice, IOCTL_ADD, &numero, sizeof(numero), &numero, sizeof(numero), &bytes, nullptr);
```

Assinatura:

```
DeviceIoControl(
    Handle,           // handle do CreateFile
    IoControlCode,    // 0x801, 0x802, etc.
    InputBuffer,      // dados enviados ao driver
    InputSize,
    OutputBuffer,     // onde o driver escreve a resposta
    OutputSize,
    &BytesReturned,  // bytes escritos no output
    Overlapped       // nullptr para operação síncrona
);
```

---

## Código completo do cliente

```cpp
#include <iostream>
#include <windows.h>

#define IOCTL_ADD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SUB CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MUL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIV CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

int main()
{
    printf("[+] Opening device...\n");

    HANDLE hDevice = CreateFileA("\\\\.\\SimpleDriver",
        GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("Erro CreateFile: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Device opened!\n");

    int numero = 5;
    DWORD bytes;

    DeviceIoControl(hDevice, IOCTL_ADD, &numero, sizeof(numero), &numero, sizeof(numero), &bytes, nullptr);
    printf("[+] Sent IOCTL_ADD\n");
    std::cout << "Result: " << numero << std::endl;

    DeviceIoControl(hDevice, IOCTL_SUB, &numero, sizeof(numero), &numero, sizeof(numero), &bytes, nullptr);
    printf("[+] Sent IOCTL_SUB\n");
    std::cout << "Result: " << numero << std::endl;

    DeviceIoControl(hDevice, IOCTL_MUL, &numero, sizeof(numero), &numero, sizeof(numero), &bytes, nullptr);
    printf("[+] Sent IOCTL_MUL\n");
    std::cout << "Result: " << numero << std::endl;

    DeviceIoControl(hDevice, IOCTL_DIV, &numero, sizeof(numero), &numero, sizeof(numero), &bytes, nullptr);
    printf("[+] Sent IOCTL_DIV\n");
    std::cout << "Result: " << numero << std::endl;

    CloseHandle(hDevice);
    return 0;
}
```

> **Observação:** O código acima foi feito só para exemplo/demonstração. Cabe a você evoluir: melhorar a estrutura, criar novas funções, tratar erros, usar estruturas para input/output, etc.

Importante: as `#define` de `IOCTL_*` precisam ser **idênticas** no driver e no usermode. O header `winioctl.h` (incluído por `windows.h`) define `CTL_CODE`, `FILE_DEVICE_UNKNOWN`, `METHOD_BUFFERED` e `FILE_ANY_ACCESS`.

---

## Explicação do fluxo

### 1. CreateFile

Ao abrir `\\.\SimpleDriver`, o I/O Manager:
1. Resolve o symlink para `\Device\SimpleDriver`
2. Envia `IRP_MJ_CREATE` ao driver
3. Retorna um handle válido ao usermode

### 2. DeviceIoControl

Cada chamada:
1. Envia `IRP_MJ_DEVICE_CONTROL` com `IoControlCode` (0x801–0x804)
2. Com `METHOD_BUFFERED`, o I/O Manager copia o input para `SystemBuffer`
3. O driver processa no switch e chama `IoCompleteRequest`
4. O I/O Manager copia o output (se houver) de volta para o buffer do usermode

### 3. CloseHandle

Envia `IRP_MJ_CLOSE` ao driver e libera o handle.

---

## Fluxo completo (diagrama)

```
┌─────────────────────────────────────────────────────────────────┐
│                      USERMODE (user_mode.exe)                   │
├─────────────────────────────────────────────────────────────────┤
│  1. CreateFileA("\\\\.\\SimpleDriver")                          │
│     └─> Se sucesso: handle válido                               │
│                                                                 │
│  2. DeviceIoControl(handle, IOCTL_ADD, &num, 4, &num, 4, &bytes)│
│     └─> Envia código 0x801 + buffer com "5"                     │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                      KERNEL (testeioclt.sys)                    │
├─────────────────────────────────────────────────────────────────┤
│  IRP_MJ_DEVICE_CONTROL recebido                                 │
│  stack->Parameters.DeviceIoControl.IoControlCode == 0x801       │
│  switch → case IOCTL_ADD: DbgPrint("[+] IOCTL_ADD received")    │
│  IoCompleteRequest(Irp)                                         │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                      USERMODE                                   │
├─────────────────────────────────────────────────────────────────┤
│  DeviceIoControl retorna                                        │
│  (quando implementar ADD/SUB: numero teria novo valor)          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Conceitos importantes

### winioctl.h

Incluído via `windows.h`, traz:
- `CTL_CODE`
- `FILE_DEVICE_UNKNOWN`
- `METHOD_BUFFERED`
- `FILE_ANY_ACCESS`

---

## Resultado

Usermode abrindo o device e enviando IOCTLs; WinDbg exibindo os logs do driver ao receber cada código:

![Usermode comunicando com driver — WinDbg com logs](/assets/img/screenshot.png)

---

## Posts relacionados

- [Estudando IOCTL — Criando o driver (Parte 1)](/estudando-ioctl-driver-parte1/)
