---
title: "Desenvolvendo Driver de Function Hooking em Kernel Mode - Parte 2"
date: 2025-01-20 09:00:00 -0300
categories: [Segurança, Kernel Development]
tags: [driver, kernel, function-hooking, c++, assembly, windows, reverse-engineering]
---

## Introdução

Este post é a continuação de "[Encontrando Funções no Windows com WinDbg](/encontrando-funcoes-windbg/)", onde aprendemos a usar o WinDbg para analisar funções do kernel. Agora, vamos mergulhar no desenvolvimento de um driver kernel que implementa a técnica de **Function Hooking**.

> ⚠️ **Aviso**: Este conteúdo é **exclusivamente educacional**. Use apenas em ambientes controlados (VMs) e para fins de aprendizado.

## O que é Function Hooking?

Um **function hook** substitui os primeiros bytes de uma função com um jump (salto) para sua própria função. É como colocar um "desvio" no código original.

### Exemplo Visual

**Antes do Hook:**
```assembly
NtOpenCompositionSurfaceSectionInfo:
    xor     eax, eax          ; Código original
    ret                       ; Retorna
```

**Depois do Hook:**
```assembly
NtOpenCompositionSurfaceSectionInfo:
    mov     rax, 0x1234567890ABCDEF  ; 48 B8 [8 bytes de endereço]
    jmp     rax                       ; FF E0
    ; (resto sobrescrito)
```

## Arquitetura do Projeto

O projeto consiste em **dois componentes**:

1. **Driver Kernel** (`driver.sys`) - Roda em Ring 0
2. **Aplicação Usermode** (`cheat.exe`) - Roda em Ring 3

### Comunicação Kernel ↔ Usermode

```
cheat.exe → win32u.dll → Função Hookada → Driver Kernel
                                      ↓
                               Nosso Shellcode
                                      ↓
                               hook_handle()
```

A comunicação acontece através de uma estrutura compartilhada (`NULL_MEMORY`) que permite operações como:
- **req_base**: Obter endereço base de DLLs
- **read**: Ler memória de processos
- **write**: Escrever memória em processos

## Desenvolvendo o Driver Passo a Passo

Vamos criar o driver seguindo uma ordem lógica de desenvolvimento. Cada arquivo será criado na sequência correta para evitar erros de compilação.

### Passo 1: Configuração do Projeto

**1.1. Criar Projeto no Visual Studio**
- Abra o Visual Studio 2019/2022
- Clique em **Create a new project**
- Procure por **"Kernel Mode Driver, Empty (KMDF)"**
- Nome: `KernelCheatYT`

**1.2. Configurações Iniciais**
- **Release** (ao invés de Debug)
- **x64** (plataforma 64 bits)

**Propriedades do Projeto:**
```
Configuration Properties → Advanced
├── Character Set → Not Set

Configuration Properties → Driver Install
└── Run InitialCat → No

Configuration Properties → Driver Signing
└── Sign Mode → Off

Configuration Properties → Linker → Advanced
└── Entry Point → DriverEntry
```

### Passo 2: Criando definitions.h

Este é o **primeiro arquivo** que vamos criar. Ele contém todas as definições, estruturas e declarações de funções não documentadas do Windows.

```cpp
#pragma once
#ifndef DEFINITIONS_H
#define DEFINITIONS_H

#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntstrsafe.h>
#include <wdm.h>
#pragma comment(lib, "ntoskrnl.lib")

// Define apenas se ainda não estiver definido nos headers do sistema
#ifndef _SYSTEM_INFOMATION_CLASS_DEFINED
#define _SYSTEM_INFOMATION_CLASS_DEFINED
typedef enum _SYSTEM_INFOMATION_CLASS 
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPatchInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation = 0x0B
} SYSTEM_INFORMATION_CLASS, 
* PSYSTEM_INFORMATION_CLASS;
#endif

#ifndef _RTL_PROCESS_MODULE_INFORMATION_DEFINED
#define _RTL_PROCESS_MODULE_INFORMATION_DEFINED
typedef struct _RTL_PROCESS_MODULE_INFORMATION 
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION,
* PRTL_PROCESS_MODULE_INFORMATION;
#endif

#ifndef _RTL_PROCESS_MODULES_DEFINED
#define _RTL_PROCESS_MODULES_DEFINED
typedef struct _RTL_PROCESS_MODULES 
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;
#endif

extern "C" __declspec(dllimport) 
NTSTATUS NTAPI ZwProtectVirtualMemomry(
	HANDLE ProcessHandle,
	PVOID* BaseAndress,
	PULONG ProtectSize, 
	ULONG NewProject,
	PULONG OldProject
);

extern "C" NTKERNELAPI
PVOID 
NTAPI
RtlFindExportedRoutineByName(
	_In_ PVOID ImageBase,
	_In_ PCCH RoutineName
);

extern "C" NTSTATUS ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLengh);

extern "C" NTKERNELAPI
PPEB
PsGetProcessPeb(
	_In_ PEPROCESS Process
);	

extern "C" NTSTATUS NTAPI MmCopyVirtualMemory
(
	PEPROCESS FromProcess,
	PVOID FromAddress,
	PEPROCESS ToProcess,
	PVOID ToAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);

#pragma warning(push)
#pragma warning(disable: 4995) // Ignora warnings de função deprecated
extern "C" NTSTATUS NTAPI ZwQueryVirtualMemory(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	MEMORY_INFORMATION_CLASS MemoryInformationClass,
	PVOID MemoryInformation,
	SIZE_T MemoryInformationLength,
	PSIZE_T ReturnLength
);
#pragma warning(pop)

// ========================================
// TYPEDEF: PPS_POST_PROCESS_INIT_ROUTINE
// ========================================
typedef VOID(*PPS_POST_PROCESS_INIT_ROUTINE)(VOID);

// ========================================
// STRUCT: RTL_USER_PROCESS_PARAMETERS
// ========================================
#ifndef _RTL_USER_PROCESS_PARAMETERS_DEFINED
#define _RTL_USER_PROCESS_PARAMETERS_DEFINED
typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;
#endif

// ========================================
// STRUCT: PEB_LDR_DATA
// ========================================
#ifndef _PEB_LDR_DATA_DEFINED
#define _PEB_LDR_DATA_DEFINED
typedef struct _PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;
#endif

// ========================================
// STRUCT: PEB (Process Environment Block)
// ========================================
#ifndef _PEB_DEFINED
#define _PEB_DEFINED
typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	BYTE Reserved4[104];
	PVOID Reserved5[52];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE Reserved6[128];
	PVOID Reserved7[1];
	ULONG SessionId;
} PEB, * PPEB;
#endif

// ========================================
// STRUCT: LDR_DATA_TABLE_ENTRY
// ========================================
#ifndef _LDR_DATA_TABLE_ENTRY_DEFINED
#define _LDR_DATA_TABLE_ENTRY_DEFINED
typedef struct _LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID Reserved3[2];
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;  // ADICIONADO: Nome base da DLL
	BYTE Reserved4[8];
	PVOID Reserved5[3];
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	};
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
#endif

#endif // DEFINITIONS_H
```

### Passo 3: Criando memory.h

```cpp
#pragma once
#include "definitions.h"

typedef struct _NULL_MEMORY
{
	void* buffer_address;
	UINT_PTR address;
	ULONGLONG size;
	ULONG pid;
	BOOLEAN write;
	BOOLEAN read;
	BOOLEAN req_base;
	void* output;
	const char* module_name;
	ULONG64 base_adress;
}NULL_MEMORY;


// Encontra o endereço base de um módulo (driver) do sistema
PVOID get_system_module_base(const char* module_name);

// Encontra uma função exportada dentro de um módulo
PVOID get_system_module_export(const char* module_name, LPCSTR routime_name);

// Escreve dados em um endereço de memória
bool write_memory(void* address, void* buffer, size_t size);

// Escreve dados em memória protegida (read-only) usando MDL
bool write_to_readonly_memory(void* address, void* buffer, size_t size);

// Pega o endereço base de um módulo (DLL) carregado em um processo usermode
ULONG64 get_module_base_x64(PEPROCESS proc, UNICODE_STRING module_name);

// Lê memória de um processo
bool read_kernel_memory(HANDLE pid, UINT_PTR address, void* buffer, SIZE_T size);

// Escreve memória em um processo
bool write_kernel_memory(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size);
```

### Passo 4: Criando memory.cpp

```cpp
#include "memory.h"


PVOID get_system_module_base(const char* module_name) 
{
	ULONG bytes = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, NULL, bytes, &bytes);

	if (!bytes) 
		return NULL;

	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x6e756c6c);

	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);	

	if(!NT_SUCCESS(status))
		return NULL;

	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;

	PVOID module_base = 0, module_size = 0;

	for (ULONG i = 0; i < modules->NumberOfModules; i++) 
	{
		if (_stricmp((char*)module[i].FullPathName, module_name) == NULL)
		{
			module_base = module[i].ImageBase;
			module_size = (PVOID)module[i].ImageSize;	
			break;
		}
	}

	if (modules)
		ExFreePoolWithTag(modules, NULL);
	
	if(module_base <= NULL)
		return NULL;

	return module_base;
}

PVOID get_system_module_export(const char* module_name, LPCSTR routime_name) 
{
	PVOID lpModule = get_system_module_base(module_name);

	if (lpModule <= NULL)
		return NULL;

	return RtlFindExportedRoutineByName(lpModule, routime_name);
}

bool write_memory(void* address, void* buffer, size_t size) 
{
	if (!RtlCopyMemory(address, buffer, size))
	{
		return false;
	}
	else
	{
		return true;
	}
}
	
bool write_to_readonly_memory(void* address, void* buffer, size_t size)
{
	PMDL Mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);
	
	if(!Mdl)
		return false;

	MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
	PVOID Mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	MmProtectMdlSystemAddress(Mdl, PAGE_EXECUTE_READWRITE);

	write_memory(Mapping, buffer, size);

	MmUnmapLockedPages(Mapping, Mdl);
	MmUnlockPages(Mdl);
	IoFreeMdl(Mdl);

	return true;
}


ULONG64 get_module_base_x64(PEPROCESS proc, UNICODE_STRING module_name)
{
	PPEB pPeb = PsGetProcessPeb(proc);

	if (!pPeb)
		return NULL;

	KAPC_STATE state;
	KeStackAttachProcess(proc, &state);

	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;	
	
	if(!pLdr)
	{
		KeUnstackDetachProcess(&state);
		return NULL;
	}

	// Iterar pela lista de módulos carregados no processo
	for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->InMemoryOrderModuleList.Flink; 
		 list != &pLdr->InMemoryOrderModuleList; 
		 list = (PLIST_ENTRY)list->Flink)
	{
		// Pegar a entrada da tabela LDR a partir do link
		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		// Comparar o nome da DLL
		if (RtlCompareUnicodeString(&pEntry->BaseDllName, &module_name, TRUE) == 0) 
		{
			ULONG64 base_address = (ULONG64)pEntry->DllBase;
			KeUnstackDetachProcess(&state);
			return base_address;
		}
	}

	KeUnstackDetachProcess(&state);
	return NULL;
}

bool read_kernel_memory(HANDLE pid, UINT_PTR address, void* buffer, SIZE_T size) 
{
	DbgPrint("[MEMORY] === LEITURA DE MEMORIA ===\n");
	DbgPrint("[MEMORY] PID: %d | Endereco: 0x%llx | Tamanho: %d bytes\n", pid, address, size);
	
	if (!address || !buffer || !size)
	{
		DbgPrint("[MEMORY] ERRO: Parametros invalidos\n");
		return false;
	}

	SIZE_T bytes = 0;
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process;
	
	DbgPrint("[MEMORY] Procurando processo PID: %d\n", pid);
	status = PsLookupProcessByProcessId((HANDLE)pid, &process);
	
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[MEMORY] ERRO: Processo nao encontrado: 0x%X\n", status);
		return false;
	}
	
	DbgPrint("[MEMORY] Processo encontrado! Executando MmCopyVirtualMemory...\n");
	status = MmCopyVirtualMemory(process, (void*)address, (PEPROCESS)PsGetCurrentProcess(), (void*)buffer, size, KernelMode, &bytes);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("[MEMORY] ERRO: Falha na leitura: 0x%X | Bytes lidos: %d\n", status, bytes);
		return false;
	}
	else
	{
		DbgPrint("[MEMORY] SUCESSO: Leitura concluida! Bytes lidos: %d\n", bytes);
		return true;
	}
}

bool write_kernel_memory(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size)
{
	DbgPrint("[MEMORY] === ESCRITA DE MEMORIA ===\n");
	DbgPrint("[MEMORY] PID: %d | Endereco: 0x%llx | Tamanho: %d bytes\n", pid, address, size);
	
	if (!address || !buffer || !size)
	{
		DbgPrint("[MEMORY] ERRO: Parametros invalidos\n");
		return false;
	}

	SIZE_T bytes = 0;
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process;
	
	DbgPrint("[MEMORY] Procurando processo PID: %d\n", pid);
	status = PsLookupProcessByProcessId((HANDLE)pid, &process);
	
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[MEMORY] ERRO: Processo nao encontrado: 0x%X\n", status);
		return false;
	}
	
	DbgPrint("[MEMORY] Processo encontrado! Anexando ao contexto do processo...\n");
	KAPC_STATE state;
	KeStackAttachProcess((PEPROCESS)process, &state);

	MEMORY_BASIC_INFORMATION info;
	DbgPrint("[MEMORY] Verificando informacoes de memoria no endereco: 0x%llx\n", address);

	status = ZwQueryVirtualMemory(ZwCurrentProcess(), (PVOID)address, MemoryBasicInformation, &info, sizeof(info), NULL);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("[MEMORY] ERRO: Falha ao obter informacoes de memoria: 0x%X\n", status);
		KeUnstackDetachProcess(&state);
		return false;
	}

	DbgPrint("[MEMORY] Regiao de memoria: Base=0x%llx | Tamanho=%d | Protecao=0x%X\n", 
			 info.BaseAddress, info.RegionSize, info.Protect);

	if (((uintptr_t)info.BaseAddress + info.RegionSize) < (address + size))
	{
		DbgPrint("[MEMORY] ERRO: Regiao insuficiente para escrita\n");
		KeUnstackDetachProcess(&state);
		return false;
	}

	if(!(info.State & MEM_COMMIT) || (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
	{
		DbgPrint("[MEMORY] ERRO: Regiao nao commitada ou sem acesso\n");
		KeUnstackDetachProcess(&state);
		return false;
	}

	if ((info.Protect & PAGE_EXECUTE_READWRITE) || (info.Protect & PAGE_EXECUTE_WRITECOPY)
		|| (info.Protect & PAGE_READWRITE) || (info.Protect & PAGE_WRITECOPY))
	{
		DbgPrint("[MEMORY] Protecao valida! Executando RtlCopyMemory...\n");
		RtlCopyMemory((void*)address, buffer, size);
		DbgPrint("[MEMORY] SUCESSO: Escrita concluida!\n");
		KeUnstackDetachProcess(&state);
		return true;
	}
	else
	{
		DbgPrint("[MEMORY] ERRO: Protecao de memoria nao permite escrita: 0x%X\n", info.Protect);
	}

	KeUnstackDetachProcess(&state);
	return false;
}
```

### Passo 5: Criando hook.h

```cpp
#pragma once
#include "definitions.h"
#include "memory.h"

namespace nullhook
{
	bool call_kernel_function(void* kernel_function_address);
	NTSTATUS hook_handle(PVOID called_param);
}
```

### Passo 6: Criando hook.cpp

```cpp
#include "hook.h"

bool nullhook::call_kernel_function(void* kernel_function_address) 
{
	if (!kernel_function_address)
	{
		return false;
	}

	PVOID* function = reinterpret_cast<PVOID*>(get_system_module_export("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", 
																	"NtOpenCompositionSurfaceSectionInfo"));
	
	if (!function)
	{
		return false;
	}

	BYTE orig[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	// isso é um jump e isso é um rax
	BYTE shell_code[] = { 0x48, 0xB8 };
	// isso e um jum rax -> ele vai pular para nossa function
	BYTE shell_code_end[] = { 0xFF, 0xE0 };

	RtlSecureZeroMemory(orig, sizeof(orig));
	memcpy((PVOID)((ULONG_PTR)orig), &shell_code, sizeof(shell_code));
	uintptr_t hook_address = reinterpret_cast<uintptr_t>(kernel_function_address);
	memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code)), &hook_address, sizeof(void*));
	memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code) + sizeof(void*)), &shell_code_end, sizeof(shell_code_end));

	bool result = write_to_readonly_memory(function, &orig, sizeof(orig));
	
	return result;
}

NTSTATUS nullhook::hook_handle(PVOID called_param) 
{
	
	// Validar ponteiro
	if (!called_param)
	{
		return STATUS_INVALID_PARAMETER;
	}

	NULL_MEMORY* instructions = (NULL_MEMORY*)called_param;

	if (instructions->req_base == TRUE)
	{
		
		ANSI_STRING AS;
		UNICODE_STRING ModuleName;
		
		RtlInitAnsiString(&AS, instructions->module_name);
		
		NTSTATUS status = RtlAnsiStringToUnicodeString(&ModuleName, &AS, TRUE);
		if (!NT_SUCCESS(status))
		{

			return status;
		}


		PEPROCESS process = NULL;
		status = PsLookupProcessByProcessId((HANDLE)instructions->pid, &process);
		
		if (!NT_SUCCESS(status) || !process)
		{
			RtlFreeUnicodeString(&ModuleName);
			return status;
		}

		ULONG64 base_address64 = 0;	
		base_address64 = get_module_base_x64(process, ModuleName);
		instructions->base_adress = base_address64;
		
		
		ObDereferenceObject(process);
		RtlFreeUnicodeString(&ModuleName);
		return STATUS_SUCCESS;
	}	

	if (instructions->write == TRUE) 
	{

				 instructions->pid, instructions->address, instructions->size);
		
		if (instructions->address < 0x7FFFFFFFFFFF && instructions->address > 0)
		{

			PVOID kernelBuff = ExAllocatePool(NonPagedPool, instructions->size);

			if (!kernelBuff) 
			{

				return STATUS_INSUFFICIENT_RESOURCES;
			}

			if (!memcpy(kernelBuff, instructions->buffer_address, instructions->size))
			{

				return STATUS_UNSUCCESSFUL;
			}


			PEPROCESS process;
			
			PsLookupProcessByProcessId((HANDLE)instructions->pid, &process);
			bool write_result = write_kernel_memory((HANDLE)instructions->pid, instructions->address, kernelBuff, instructions->size);
				
			ExFreePool(kernelBuff);
		}
		else
		{
			DbgPrint("[HOOK] ERRO: Endereco invalido: 0x%llx\n", instructions->address);
		}
	}

	if(instructions->read == TRUE) 
	{

				 instructions->pid, instructions->address, instructions->size);
		
		if (instructions->address < 0x7FFFFFFFFFFF && instructions->address > 0)
		{

			bool read_result = read_kernel_memory((HANDLE)instructions->pid, instructions->address, instructions->output, instructions->size);
			
		}
		else
		{
			DbgPrint("[HOOK] ERRO: Endereco invalido: 0x%llx\n", instructions->address);
		}
	}
	
	return STATUS_SUCCESS;
}
```

### Passo 7: Criando main.cpp

```cpp
#include "hook.h"

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING reg_path) 
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(reg_path);
	
	bool hook_result = nullhook::call_kernel_function(&nullhook::hook_handle);

	return STATUS_SUCCESS;
}

### Passo 8: Compilando o Projeto

**Se der erro de compilação:**
1. Botão direito no projeto → **Properties**
2. **C/C++** → **General**
3. **Treat Warnings As Errors** → **No (/WX-)**

**Compilar:**
1. **Build** → **Build Solution** (Ctrl+Shift+B)
2. O driver será gerado em: `x64\Release\KernelCheatYT\KernelCheatYT.sys`

## Desafios e Soluções (Lições Aprendidas)

Durante o desenvolvimento, enfrentei alguns desafios importantes. Compartilho aqui as soluções que encontrei:

### 1. Validação e Error Handling

Aprendi da forma difícil: **sempre validar ponteiros** e usar `__try/__except` para código perigoso. Um erro no kernel pode causar uma tela azul (BSOD)!

```cpp
// Sempre validar PEPROCESS e liberar com ObDereferenceObject!
PEPROCESS process = NULL;
NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &process);

if (NT_SUCCESS(status) && process)
{
    // Usar o process...
    ObDereferenceObject(process);  // CRÍTICO: Evita memory leak!
}

// Usar __try/__except para código perigoso
__try
{
    // Código que pode crashar
    PPEB pPeb = PsGetProcessPeb(proc);
}
__except (EXCEPTION_EXECUTE_HANDLER)
{
    // Tratar o erro sem crashar o sistema
    return 0;
}

// Sempre validar ponteiros antes de usar!
if (!MmIsAddressValid(pPeb))
{
    KeUnstackDetachProcess(&state);
    return 0;
}
```

### 2. KernelCallbackTable

Descobri que o usermode travava ao chamar o hook. A solução foi **carregar `user32.dll` ANTES de qualquer coisa** no `main()`:

```cpp
int main() 
{
    // CRÍTICO: Sem isso, o programa trava!
    // Deve ser a PRIMEIRA coisa no main()
    LoadLibraryA("user32.dll");
    
    // ... resto do código
}
```

**Por que é necessário?**

O `user32.dll` inicializa a `KernelCallbackTable` no PEB (Process Environment Block). Esta tabela é essencial para a comunicação entre usermode e kernel através de callbacks. Sem ela, quando nosso programa tenta chamar a função hookada, o sistema não consegue fazer a transição para o kernel mode, causando travamento.

**IMPORTANTE:** Deve ser carregado **no início do main()**, antes de qualquer outra operação que possa usar callbacks do kernel.

### 3. Prevenir Loops Infinitos

Em loops que interagem com o kernel, é crucial adicionar um contador para evitar travamentos:

```cpp
ULONG max_iterations = 500;
ULONG current_iteration = 0;

for (...; ...; current_iteration++)
{
    if (current_iteration >= max_iterations)
        break;  // Prevenir loop infinito!
}
```

### 4. Debug com DbgPrint

Para entender o que está acontecendo no kernel, `DbgPrint` é seu melhor amigo. As mensagens aparecem no WinDbg:

```cpp
DbgPrint("[HOOK] req_base request for: %s (PID: %d)\n", 
         module_name, pid);
DbgPrint("[HOOK] Returning base: 0x%llx\n", base_address);
```

## Ambiente de Desenvolvimento

### Ferramentas Utilizadas

- **Visual Studio 2022** com WDK (Windows Driver Kit)
- **WinDbg** para debugging kernel
- **[kdmapper](https://github.com/TheCruZ/kdmapper)** para injetar o driver
- **VirtualBox** para testes em VM

### Setup do Ambiente

1. **Conectar WinDbg ao kernel da VM**

2. **Compilar o driver:**
```
Build → Build Solution (Ctrl+Shift+B)
```

3. **Injetar com kdmapper:**
```powershell
kdmapper.exe driver.sys
```

**kdmapper:** [https://github.com/TheCruZ/kdmapper](https://github.com/TheCruZ/kdmapper)

## Testando o Hook

### 1. Verificar no WinDbg

Após injetar o driver com kdmapper, você pode verificar o hook no WinDbg:

```
kd> .reload /f dxgkrnl.sys
view -> disassembly
Procure pela sua função: NtOpenCompositionSurfaceSectionInfo
```

Se você ver `mov rax` + `jmp rax`, o hook está ativo!

### 2. Testar Comunicação Usermode ↔ Kernel

Execute a aplicação usermode (`cheat.exe`) na VM. Você deverá ver uma saída similar a esta:

```
[*] Loading user32.dll...
[+] user32.dll loaded!

=== TESTE COM NOTEPAD ===
[+] Found notepad.exe with PID: 12345
[DEBUG] Requesting base for: ntdll.dll (PID: 12345)
[DEBUG] Calling hook at: 0x7FFB...
[DEBUG] Hook returned: 0x0
[DEBUG] Returned base: 0x7ffb95870000
[+] ntdll.dll base address: 0x7ffb95870000
```

✅ **Se aparecer endereços hexadecimais reais: ESTÁ FUNCIONANDO!**

## Resumo do Fluxo Completo

```
┌─────────────────────────────────────────────────────────────────┐
│                      APLICAÇÃO USERMODE                         │
│                      (user_mode.exe)                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. LoadLibraryA("user32.dll");        ← CRÍTICO!               │
│     └─> Inicializa KernelCallbackTable                          │
│                                                                 │
│  2. process_id = get_process_id("cs2.exe");                     │
│     └─> Encontra PID do processo alvo                           │
│                                                                 │
│  3. base = get_module_base_address("client.dll");               │
│     │                                                           │
│     ├─> Cria struct NULL_MEMORY                                 │
│     │   └─> pid = process_id                                    │
│     │   └─> req_base = TRUE                                     │
│     │   └─> module_name = "client.dll"                          │
│     │                                                           │
│     ├─> call_hook(&instructions);                               │
│     │   │                                                       │
│     │   ├─> LoadLibraryA("win32u.dll")                          │
│     │   ├─> GetProcAddress(hWin32u, "NtOpen...")                │
│     │   └─> func(&instructions);  ← Chama função hookada!       │
│     │       │                                                   │
└─────┼───────┼───────────────────────────────────────────────────┘
      │       │
      │       ↓
┌─────┼───────────────────────────────────────────────────────────┐
│     │        WIN32U.DLL (usermode)                              │
│     │                                                           │
│     └─────> NtOpenCompositionSurfaceSectionInfo()               │
│                       │                                         │
│                       │ (syscall para kernel)                   │
└───────────────────────┼─────────────────────────────────────────┘
                        │
                        ↓
┌───────────────────────┼────────────────────────────────────────────┐
│                       │        KERNEL MODE                         │
│                       │                                            │
│       ┌───────────────▼─────────────────┐                          │
│       │  dxgkrnl!NtOpen... (hookado)    │                          │
│       ├─────────────────────────────────┤                          │
│       │  48 B8 [addr]  ; mov rax, addr  │ ← NOSSO SHELLCODE!       │
│       │  FF E0         ; jmp rax        │                          │
│       └───────────────┬─────────────────┘                          │
│                       │                                            │
│                       ↓                                            │
│       ┌───────────────────────────────────────┐                    │
│       │    hook_handle(instructions)          │                    │
│       ├───────────────────────────────────────┤                    │
│       │                                       │                    │
│       │  if (req_base == TRUE)                │                    │
│       │  {                                    │                    │
│       │      1. PsLookupProcessByProcessId()  │                    │
│       │      2. get_module_base_x64()         │                    │
│       │         └─> Itera PEB/LDR do proc     │                    │
│       │         └─> Compara nome das DLLs     │                    │
│       │      3. instructions->base_adress = X │                    │
│       │      4. ObDereferenceObject(process)  │                    │
│       │  }                                    │                    │
│       │                                       │                    │
│       │  return STATUS_SUCCESS;               │                    │
│       └───────────────┬───────────────────────┘                    │
│                       │                                            │
└───────────────────────┼────────────────────────────────────────────┘
                        │
                        ↓ (retorna para usermode)
┌───────────────────────┼────────────────────────────────────────────┐
│                       │        APLICAÇÃO USERMODE                  │
│                       ▼                                            │
│                                                                    │
│  4. base = instructions.base_adress;  ← RECEBE O RESULTADO!        │
│     └─> 0x7FF612340000                                             │
│                                                                    │
│  5. int hp = Read<int>(base + 0x1234);  ← Usar o endereço!         │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

## Conceitos Aprendidos

### 1. Assembly x64

| Opcode | Instrução | Descrição |
|--------|-----------|-----------|
| `48 B8` | `MOV RAX, imm64` | Move valor para RAX |
| `FF E0` | `JMP RAX` | Pula para endereço em RAX |
| `33 C0` | `XOR EAX, EAX` | Zera EAX |
| `C3` | `RET` | Retorna da função |

### 2. MDL (Memory Descriptor List)

Estrutura que descreve páginas de memória física:

```
MDL → Páginas Físicas → Mapeamento Virtual → Escrita
```

### 3. Função Escolhida: NtOpenCompositionSurfaceSectionInfo

Escolhi esta função porque:
- Está no `dxgkrnl.sys` (DirectX Graphics Kernel)
- Raramente é chamada (menos chance de crash)
- É exportada (fácil de encontrar)
- Boa para aprendizado

**Outras opções:**
- `NtQueryCompositionSurfaceHDRMetaData`
- `NtOpenCompositionSurfaceSectionInfo`
- `NtOpenCompositionSurfaceDirtyRegion`

**Evite:**
- Funções com "SecureCookie" (causam BSOD)
- Funções em regiões críticas

## Conclusão

Este projeto demonstra conceitos avançados de programação em kernel mode:
- **Function Hooking** - Modificação de código em tempo de execução
- **Comunicação Kernel ↔ Usermode** - Através de funções hookadas
- **Manipulação de Memória Protegida** - Usando MDL
- **Shellcode em x64** - Assembly de baixo nível
- **Arquitetura de Drivers Windows** - WDM/KMDF
- **Processos e DLLs** - PEB, LDR, module enumeration
- espero voltar daqui uns anos e ver como eu tava no inicio de tudo.

**Principais lições:**
1. **Sempre trabalhe em VM** - bsod é seu pior inimigo!
2. **Valide tudo** - Um ponteiro inválido = BSOD
3. **Use WinDbg** - É sua melhor ferramenta
4. **Estude assembly** - Entender os opcodes é fundamental (nao sei quase nada preciso estudar mt)

---

**Próximo post:** [Desenvolvendo Cliente Usermode para Function Hooking - Parte 3](/desenvolvendo-usermode-cliente/)
