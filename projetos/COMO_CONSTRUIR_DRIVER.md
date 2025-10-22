# Como Construir o Projeto do Zero

> Guia passo a passo para criar este driver de hook em kernel mode desde o início.

## 1. Criando o Projeto no Visual Studio

### Passo 1: Novo Projeto

1. Abra o Visual Studio 2019/2022
2. Clique em **Create a new project**
3. Procure por **"Kernel Mode Driver, Empty (KMDF)"**
4. Dê um nome ao projeto: `KernelCheatYT`
5. Clique em **Create**

---

## 2. Configurações Iniciais

Agora precisamos configurar o projeto corretamente. Siga estes passos:

### Passo 1: Selecionar Configuração

- No topo do Visual Studio, selecione:
  - **Release** (ao invés de Debug)
  - **x64** (plataforma 64 bits)

### Passo 2: Propriedades do Projeto

Clique com botão direito no projeto → **Properties**

#### A. Advanced Settings

```
Configuration Properties → Advanced
├── Character Set → Not Set
```

**Por quê?** Para evitar conflitos com strings do kernel.

#### B. Driver Settings

```
Configuration Properties → Driver Install
└── Run InitialCat → No
```

**Por quê?** Não queremos executar verificações de catálogo ao instalar.

```
Configuration Properties → Driver Signing
└── Sign Mode → Off
```

**Por quê?** Estamos em ambiente de teste, vamos usar kdmapper.

#### C. Linker Settings

```
Configuration Properties → Linker → Advanced
└── Entry Point → DriverEntry
```

**Por quê?** Define o ponto de entrada do driver (função principal).

---

## 3. Criando definitions.h

Este é o primeiro arquivo que vamos criar. Ele contém todas as definições, estruturas e declarações de funções não documentadas do Windows.

### Criar o arquivo

1. Botão direito em **Source Files** → Add → New Item
2. Selecione **Header File (.h)**
3. Nome: `definitions.h`

### Código completo comentado:

```cpp
#pragma once
#ifndef DEFINITIONS_H
#define DEFINITIONS_H

// ========================================
// INCLUDES NECESSÁRIOS DO KERNEL
// ========================================
#include <ntdef.h>      // Definições básicas do NT
#include <ntifs.h>      // File System Driver definitions
#include <ntddk.h>      // Driver Development Kit
#include <windef.h>     // Definições do Windows
#include <ntstrsafe.h>  // Funções seguras de string
#include <wdm.h>        // Windows Driver Model
#pragma comment(lib, "ntoskrnl.lib")  // Link com o kernel

// ========================================
// ENUM: SYSTEM_INFORMATION_CLASS
// ========================================
// Esta enum é usada pela função ZwQuerySystemInformation
// para especificar que tipo de informação queremos
#ifndef _SYSTEM_INFOMATION_CLASS_DEFINED
#define _SYSTEM_INFOMATION_CLASS_DEFINED
typedef enum _SYSTEM_INFOMATION_CLASS 
{
    SystemBasicInformation,                     // Informações básicas do sistema
    SystemProcessorInformation,                 // Info do processador
    SystemPerformanceInformation,               // Performance
    SystemTimeOfDayInformation,                 // Data/hora
    SystemPatchInformation,                     // Patches aplicados
    SystemProcessInformation,                   // Lista de processos
    SystemCallCountInformation,                 // Contagem de syscalls
    SystemDeviceInformation,                    // Dispositivos
    SystemProcessorPerformanceInformation,      // Performance do CPU
    SystemFlagsInformation,                     // Flags do sistema
    SystemCallTimeInformation,                  // Tempo de syscalls
    SystemModuleInformation = 0x0B              // IMPORTANTE: Lista de drivers/módulos carregados
} SYSTEM_INFORMATION_CLASS, 
* PSYSTEM_INFORMATION_CLASS;
#endif

// ========================================
// STRUCT: RTL_PROCESS_MODULE_INFORMATION
// ========================================
// Representa informações sobre um módulo (driver) carregado
#ifndef _RTL_PROCESS_MODULE_INFORMATION_DEFINED
#define _RTL_PROCESS_MODULE_INFORMATION_DEFINED
typedef struct _RTL_PROCESS_MODULE_INFORMATION 
{
    HANDLE Section;                 // Handle da seção de memória
    PVOID MappedBase;               // Base mapeada na memória
    PVOID ImageBase;                // Base da imagem (endereço onde o driver está carregado)
    ULONG ImageSize;                // Tamanho da imagem em bytes
    ULONG Flags;                    // Flags do módulo
    USHORT LoadOrderIndex;          // Ordem de carregamento
    USHORT InitOrderIndex;          // Ordem de inicialização
    USHORT LoadCount;               // Quantas vezes foi carregado
    USHORT OffsetToFileName;        // Offset para o nome do arquivo no FullPathName
    UCHAR FullPathName[256];        // Caminho completo (ex: \SystemRoot\system32\ntoskrnl.exe)
} RTL_PROCESS_MODULE_INFORMATION,
* PRTL_PROCESS_MODULE_INFORMATION;
#endif

// ========================================
// STRUCT: RTL_PROCESS_MODULES
// ========================================
// Estrutura que contém a lista de todos os módulos carregados
#ifndef _RTL_PROCESS_MODULES_DEFINED
#define _RTL_PROCESS_MODULES_DEFINED
typedef struct _RTL_PROCESS_MODULES 
{
    ULONG NumberOfModules;                      // Quantidade de módulos na lista
    RTL_PROCESS_MODULE_INFORMATION Modules[1];  // Array de módulos (tamanho dinâmico)
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;
#endif

// ========================================
// DECLARAÇÕES DE FUNÇÕES NÃO DOCUMENTADAS
// ========================================

// Protege/desprotege memória virtual (não usada neste projeto, mas útil)
extern "C" __declspec(dllimport) 
NTSTATUS NTAPI ZwProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PULONG ProtectSize, 
    ULONG NewProtect,
    PULONG OldProtect
);

// Encontra uma função exportada por nome em um módulo
// Esta função é ESSENCIAL para encontrar funções do kernel
extern "C" NTKERNELAPI
PVOID 
NTAPI
RtlFindExportedRoutineByName(
    _In_ PVOID ImageBase,      // Base do módulo (driver)
    _In_ PCCH RoutineName      // Nome da função a procurar
);

// Consulta informações do sistema (usamos para listar módulos carregados)
extern "C" NTSTATUS ZwQuerySystemInformation(
    ULONG InfoClass,            // Tipo de informação (usamos SystemModuleInformation)
    PVOID Buffer,               // Buffer para receber os dados
    ULONG Length,               // Tamanho do buffer
    PULONG ReturnLength         // Tamanho real dos dados
);

// Obtém o PEB (Process Environment Block) de um processo
extern "C" NTKERNELAPI
PPEB
PsGetProcessPeb(
    _In_ PEPROCESS Process
);

// Copia memória entre processos
extern "C" NTSTATUS NTAPI MmCopyVirtualMemory
(
    PEPROCESS FromProcess,      // Processo de origem
    PVOID FromAddress,          // Endereço de origem
    PEPROCESS ToProcess,        // Processo de destino
    PVOID ToAddress,            // Endereço de destino
    SIZE_T BufferSize,          // Tamanho a copiar
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T ReturnSize          // Bytes copiados
);

#endif // DEFINITIONS_H
```

---

## 4. Criando memory.h e memory.cpp

Agora vamos criar as funções de manipulação de memória.

### 4.1. Criar memory.h

1. Botão direito em **Header Files** → Add → New Item
2. **Header File (.h)**
3. Nome: `memory.h`

```cpp
#pragma once
#include "definitions.h"

// ========================================
// STRUCT: NULL_MEMORY (compartilhada com usermode)
// ========================================
// IMPORTANTE: Esta estrutura DEVE ser IDÊNTICA no driver e no usermode!
// Ela é usada para comunicação entre o driver e a aplicação usermode
typedef struct _NULL_MEMORY
{
    void* buffer_address;      // Endereço do buffer (para write)
    UINT_PTR address;          // Endereço alvo (para read/write)
    ULONGLONG size;            // Tamanho dos dados
    ULONG pid;                 // PID do processo alvo
    BOOLEAN write;             // Flag: operação de escrita?
    BOOLEAN read;              // Flag: operação de leitura?
    BOOLEAN req_base;          // Flag: requisição de base address?
    void* output;              // Ponteiro para output (read)
    const char* module_name;   // Nome do módulo (para req_base)
    ULONG64 base_adress;       // Base address retornado
}NULL_MEMORY;

// ========================================
// DECLARAÇÕES DAS FUNÇÕES DE MEMÓRIA
// ========================================

// Encontra o endereço base de um módulo (driver) carregado pelo nome
PVOID get_system_module_base(const char* module_name);

// Encontra uma função exportada dentro de um módulo
PVOID get_system_module_export(const char* module_name, LPCSTR routine_name);

// Escreve dados em um endereço de memória (modo simples)
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

### 4.2. Criar memory.cpp

1. Botão direito em **Source Files** → Add → New Item
2. **C++ File (.cpp)**
3. Nome: `memory.cpp`

```cpp
#include "memory.h"

// ========================================
// FUNÇÃO: get_system_module_base
// ========================================
// O QUE FAZ: Procura um driver/módulo carregado pelo nome e retorna seu endereço base
// COMO USA: get_system_module_base("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys")
// RETORNA: Endereço base do módulo ou NULL se não encontrar
PVOID get_system_module_base(const char* module_name) 
{
    ULONG bytes = 0;
    
    // PASSO 1: Perguntar ao Windows quanto espaço precisamos para a lista de módulos
    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, NULL, bytes, &bytes);

    // Se não retornou tamanho, algo deu errado
    if (!bytes) 
        return NULL;

    // PASSO 2: Alocar memória para receber a lista
    // 0x636e7474 = "CNTT" em ASCII (tag para identificar nossa alocação)
    PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x636e7474);

    // PASSO 3: Realmente pegar a lista de módulos
    status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);    

    // Verificar se deu certo
    if(!NT_SUCCESS(status))
        return NULL;

    // PASSO 4: Procurar pelo módulo específico na lista
    PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
    PVOID module_base = 0, module_size = 0;

    // Iterar por todos os módulos carregados
    for (ULONG i = 0; i < modules->NumberOfModules; i++) 
    {
        // Comparar o nome (case insensitive)
        if (_stricmp((char*)module[i].FullPathName, module_name) == NULL)
        {
            module_base = module[i].ImageBase;  // Achamos! Pegar o endereço base
            module_size = (PVOID)module[i].ImageSize;
            break;
        }
    }

    // PASSO 5: Liberar a memória que alocamos
    if (modules)
        ExFreePoolWithTag(modules, NULL);
    
    // Validar se encontramos algo
    if(module_base <= NULL)
        return NULL;

    return module_base;
}

// ========================================
// FUNÇÃO: get_system_module_export
// ========================================
// O QUE FAZ: Encontra uma função específica dentro de um módulo
// COMO USA: get_system_module_export("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", "NtQueryCompositionSurfaceHDRMetaData")
// RETORNA: Endereço da função ou NULL se não encontrar
PVOID get_system_module_export(const char* module_name, LPCSTR routine_name) 
{
    // PASSO 1: Primeiro encontrar o módulo
    PVOID lpModule = get_system_module_base(module_name);

    if (lpModule <= NULL)
        return NULL;

    // PASSO 2: Usar função do Windows para encontrar a export
    // Todo driver/DLL tem uma "tabela de exports" com suas funções públicas
    return RtlFindExportedRoutineByName(lpModule, routine_name);
}

// ========================================
// FUNÇÃO: write_memory
// ========================================
// O QUE FAZ: Copia dados para um endereço de memória (modo simples)
// COMO USA: write_memory(endereco_destino, &meus_dados, tamanho)
// RETORNA: true se sucesso, false se falhou
bool write_memory(void* address, void* buffer, size_t size) 
{
    // RtlCopyMemory é como memcpy, mas seguro para o kernel
    if (!RtlCopyMemory(address, buffer, size))
    {
        return false;
    }
    else
    {
        return true;
    }
}

// ========================================
// FUNÇÃO: write_to_readonly_memory
// ========================================
// O QUE FAZ: Escreve em memória protegida (read-only) usando técnica de MDL
// COMO USA: write_to_readonly_memory(endereco_protegido, &meus_dados, tamanho)
// RETORNA: true se sucesso, false se falhou
// 
// POR QUÊ PRECISA DISSO?
// O código do kernel é protegido como READ-ONLY por segurança.
// Para modificá-lo (fazer hook), precisamos temporariamente mudar as permissões.
bool write_to_readonly_memory(void* address, void* buffer, size_t size)
{
    // PASSO 1: Criar um MDL (Memory Descriptor List)
    // MDL é uma estrutura que descreve páginas de memória física
    PMDL Mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);
    
    if(!Mdl)
        return false;

    // PASSO 2: "Travar" as páginas na memória (não deixa Windows mover elas)
    MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
    
    // PASSO 3: Mapear as páginas em um novo endereço virtual
    // Isso cria uma "segunda visão" da mesma memória física
    PVOID Mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    
    // PASSO 4: Mudar as permissões para Read-Write-Execute
    // Agora podemos escrever!
    MmProtectMdlSystemAddress(Mdl, PAGE_EXECUTE_READWRITE);

    // PASSO 5: Escrever os dados
    write_memory(Mapping, buffer, size);

    // PASSO 6: Limpeza - desfazer tudo que fizemos
    MmUnmapLockedPages(Mapping, Mdl);  // Desmapear
    MmUnlockPages(Mdl);                 // Destravar páginas
    IoFreeMdl(Mdl);                     // Liberar o MDL

    return true;
}
```

---

## 5. Criando hook.h e hook.cpp

Agora a parte mais importante: o sistema de hook!

### 5.1. Criar hook.h

1. Botão direito em **Header Files** → Add → New Item
2. **Header File (.h)**
3. Nome: `hook.h`

```cpp
#pragma once
#include "definitions.h"
#include "memory.h"

// Namespace para organizar nossas funções de hook
namespace nullhook
{
    // Instala o hook inline em uma função do kernel
    bool call_kernel_function(void* kernel_function_address);
    
    // Nossa função que será chamada quando a função original for invocada
    NTSTATUS hook_handle(PVOID called_param);
}
```

### 5.2. Criar hook.cpp

1. Botão direito em **Source Files** → Add → New Item
2. **C++ File (.cpp)**
3. Nome: `hook.cpp`

```cpp
#include "hook.h"

// ========================================
// FUNÇÃO: call_kernel_function
// ========================================
// O QUE FAZ: Instala um hook inline em uma função do kernel
// COMO FUNCIONA:
//   1. Encontra a função alvo (NtQueryCompositionSurfaceHDRMetaData)
//   2. Cria um shellcode (código em Assembly)
//   3. Substitui os primeiros 12 bytes da função pelo shellcode
//   4. Shellcode faz jump para nossa função (hook_handle)
//
// RESULTADO: Sempre que alguém chamar a função original, nossa função é executada!
bool nullhook::call_kernel_function(void* kernel_function_address) 
{
    // Validar se recebemos um endereço válido
    if (!kernel_function_address)
        return false;

    // ========================================
    // PASSO 1: ENCONTRAR A FUNÇÃO ALVO
    // ========================================
    // Vamos hookar a função NtOpenCompositionSurfaceSectionInfo do dxgkrnl.sys
    // IMPORTANTE: A função hookada aqui DEVE ser a mesma que o usermode chama!
    // Por quê esta função?
    // - Raramente é usada (menos chance de crash)
    // - É exportada (fácil de encontrar)
    // - Boa para aprendizado e comunicação usermode ↔ kernel
    PVOID* function = reinterpret_cast<PVOID*>(
        get_system_module_export(
            "\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", 
            "NtOpenCompositionSurfaceSectionInfo"  // Mesma função que o usermode chama!
        )
    );
    
    if (!function)
        return false;

    // ========================================
    // PASSO 2: CRIAR O SHELLCODE
    // ========================================
    // Vamos criar 12 bytes de código Assembly que fazem:
    // MOV RAX, <endereço>   ; Carrega nosso endereço em RAX
    // JMP RAX                ; Pula para nosso endereço
    
    BYTE orig[12] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    // Opcodes em Assembly x64:
    // 0x48, 0xB8 = MOV RAX, <valor de 64 bits>
    BYTE shell_code[] = { 0x48, 0xB8 };
    
    // 0xFF, 0xE0 = JMP RAX (pula para o endereço que está em RAX)
    BYTE shell_code_end[] = { 0xFF, 0xE0 };

    // ========================================
    // PASSO 3: MONTAR O SHELLCODE COMPLETO
    // ========================================
    // Estrutura final (12 bytes):
    // [0x48, 0xB8] [8 bytes do endereço] [0xFF, 0xE0]
    //     MOV RAX      nosso endereço        JMP RAX
    
    RtlSecureZeroMemory(orig, sizeof(orig));  // Zerar o buffer
    
    // Copiar: 48 B8
    memcpy((PVOID)((ULONG_PTR)orig), &shell_code, sizeof(shell_code));
    
    // Copiar: endereço da nossa função (8 bytes)
    uintptr_t hook_address = reinterpret_cast<uintptr_t>(kernel_function_address);
    memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code)), &hook_address, sizeof(void*));
    
    // Copiar: FF E0
    memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code) + sizeof(void*)), &shell_code_end, sizeof(shell_code_end));

    // ========================================
    // PASSO 4: ESCREVER NA FUNÇÃO ORIGINAL
    // ========================================
    // Substituir os primeiros 12 bytes da função original pelo nosso shellcode
    // Isso é o "hook" acontecendo!
    write_to_readonly_memory(function, &orig, sizeof(orig));

    return true;
}

// ========================================
// FUNÇÃO: hook_handle
// ========================================
// O QUE FAZ: Esta função será chamada quando alguém chamar a função que hookamos
// COMO FUNCIONA:
//   1. Recebe uma estrutura NULL_MEMORY com instruções
//   2. Verifica qual operação foi solicitada (req_base, read ou write)
//   3. Executa a operação
//   4. Retorna o resultado
//
// OPERAÇÕES SUPORTADAS:
//   - req_base: Retorna o endereço base de uma DLL em um processo
//   - read: Lê memória de um processo
//   - write: Escreve memória em um processo
NTSTATUS nullhook::hook_handle(PVOID called_param) 
{
    // ========================================
    // VALIDAÇÃO DE PONTEIRO
    // ========================================
    if (!called_param)
        return STATUS_INVALID_PARAMETER;

    NULL_MEMORY* instructions = (NULL_MEMORY*)called_param;

    // ========================================
    // OPERAÇÃO: PEGAR ENDEREÇO BASE (req_base)
    // ========================================
    // Quando o usermode quer saber o endereço base de uma DLL
    if (instructions->req_base == TRUE)
    {
        // Debug: Logar no kernel debugger (WinDbg)
        DbgPrint("[HOOK] req_base request for: %s (PID: %d)\n", 
                 instructions->module_name, instructions->pid);
        
        // PASSO 1: Converter string ANSI para UNICODE
        ANSI_STRING AS;
        UNICODE_STRING ModuleName;
        
        RtlInitAnsiString(&AS, instructions->module_name);
        
        NTSTATUS status = RtlAnsiStringToUnicodeString(&ModuleName, &AS, TRUE);
        if (!NT_SUCCESS(status))
        {
            DbgPrint("[HOOK] Failed to convert string: 0x%X\n", status);
            return status;
        }

        // PASSO 2: Pegar o PEPROCESS do processo alvo
        PEPROCESS process = NULL;
        status = PsLookupProcessByProcessId((HANDLE)instructions->pid, &process);
        
        // IMPORTANTE: Sempre validar e liberar objetos!
        if (!NT_SUCCESS(status) || !process)
        {
            DbgPrint("[HOOK] Failed to find process: 0x%X\n", status);
            RtlFreeUnicodeString(&ModuleName);
            return status;
        }

        // PASSO 3: Procurar a DLL dentro do processo
        ULONG64 base_address64 = 0;    
        base_address64 = get_module_base_x64(process, ModuleName);
        
        // PASSO 4: Retornar o resultado para o usermode
        instructions->base_adress = base_address64;
        
        DbgPrint("[HOOK] Returning base: 0x%llx\n", base_address64);
        
        // PASSO 5: Liberar recursos (CRÍTICO para evitar memory leaks!)
        ObDereferenceObject(process);  // Sempre liberar PEPROCESS!
        RtlFreeUnicodeString(&ModuleName);
        
        return STATUS_SUCCESS;
    }    

    // ========================================
    // OPERAÇÃO: ESCREVER MEMÓRIA (write)
    // ========================================
    if (instructions->write == TRUE) 
    {
        // Validar endereço usermode (< 0x7FFFFFFFFFFF)
        if (instructions->address < 0x7FFFFFFFFFFF && instructions->address > 0)
        {
            // Alocar buffer no kernel
            PVOID kernelBuff = ExAllocatePool(NonPagedPool, instructions->size);

            if (!kernelBuff) 
            {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            // Copiar dados do usermode para o kernel
            if (!memcpy(kernelBuff, instructions->buffer_address, instructions->size))
            {
                ExFreePool(kernelBuff);
                return STATUS_UNSUCCESSFUL;
            }

            // Pegar o processo alvo
            PEPROCESS process = NULL;
            NTSTATUS status = PsLookupProcessByProcessId((HANDLE)instructions->pid, &process);
            
            if (NT_SUCCESS(status) && process)
            {
                // Escrever no processo alvo
                write_kernel_memory((HANDLE)instructions->pid, instructions->address, kernelBuff, instructions->size);
                ObDereferenceObject(process);
            }
            
            // Liberar buffer
            ExFreePool(kernelBuff);
        }
    }

    // ========================================
    // OPERAÇÃO: LER MEMÓRIA (read)
    // ========================================
    if(instructions->read == TRUE) 
    {
        // Validar endereço usermode
        if (instructions->address < 0x7FFFFFFFFFFF && instructions->address > 0)
        {
            // Ler memória do processo alvo e retornar em instructions->output
            read_kernel_memory((HANDLE)instructions->pid, instructions->address, instructions->output, instructions->size);
        }
    }
    
    return STATUS_SUCCESS;
}
```

---

## 6. Criando main.cpp

Agora o arquivo principal que inicia tudo!

### Criar main.cpp

1. Botão direito em **Source Files** → Add → New Item
2. **C++ File (.cpp)**
3. Nome: `main.cpp`

```cpp
#include "hook.h"

// ========================================
// FUNÇÃO: DriverEntry
// ========================================
// O QUE É: Ponto de entrada do driver (como a função main() em programas normais)
// QUANDO É CHAMADA: Assim que o driver é carregado pelo Windows (ou kdmapper)
// PARÂMETROS:
//   - DriverObject: Objeto que representa nosso driver
//   - reg_path: Caminho do registro onde o driver está registrado
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING reg_path) 
{
    // Marcar parâmetros como não usados (evita warnings do compilador)
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(reg_path);

    // ========================================
    // INSTALAR O HOOK
    // ========================================
    // Chamar nossa função que vai:
    // 1. Encontrar a função NtQueryCompositionSurfaceHDRMetaData
    // 2. Criar o shellcode
    // 3. Instalar o hook
    //
    // Passamos o endereço da nossa função hook_handle
    // que será executada quando a função original for chamada
    nullhook::call_kernel_function(&nullhook::hook_handle);

    // Retornar sucesso para o Windows
    // O driver permanece carregado na memória
    return STATUS_SUCCESS;
}
```

---

## 7. Compilando o Projeto

### Se der erro de compilação

Se aparecer erros relacionados a "warnings", faça isso:

1. Botão direito no projeto → **Properties**
2. **C/C++** → **General**
3. **Treat Warnings As Errors** → **No (/WX-)**
4. Clique **Apply** e **OK**

### Compilar

1. No menu superior: **Build** → **Build Solution** (ou Ctrl+Shift+B)
2. Aguarde a compilação
3. Se tudo der certo, você verá: `Build: 1 succeeded`
4. O driver estará em: `x64\Release\KernelCheatYT\KernelCheatYT.sys`

---

## 8. Testando com WinDbg

Agora vamos testar e entender o que está acontecendo!

### Pré-requisitos

- Máquina Virtual Windows (com Kernel Debugging habilitado)
- WinDbg instalado no host
- kdmapper para carregar o driver

### Passo a Passo

#### 8.1. Conectar o WinDbg

1. Configure kernel debugging na VM
2. Conecte o WinDbg à VM
3. No WinDbg, você deve ver o prompt: `kd>`

#### 8.2. Encontrar o Processo Explorer

```
kd> !process 0 0 explorer.exe
```

**O que este comando faz?** Lista informações sobre o processo explorer.exe

**Saída esperada:**
```
PROCESS ffff9882edc70080
    SessionId: 1  Cid: 127c    Peb: 00e56000  ParentCid: 1260
    DirBase: 14431d002  ObjectTable: ffff88827c17db00  HandleCount: 2464.
    Image: explorer.exe
```

#### 8.3. Recarregar o Módulo dxgkrnl.sys

```
kd> .reload /f dxgkrnl.sys
```

**O que este comando faz?** Força o reload do driver dxgkrnl.sys para atualizar símbolos

#### 8.4. Abrir o Disassembler

1. No menu do WinDbg: **View** → **Disassembly**
2. Uma janela de código assembly será aberta

#### 8.5. Procurar a Função

Na janela de Disassembly, digite o nome da função:

```
NtOpenCompositionSurfaceSectionInfo
```

**IMPORTANTE:** Esta é a função que estamos hookando! Deve ser a mesma no driver e no usermode!

ou tente outras funções de:
https://j00ru.vexillium.org/syscalls/win32k/64/

**Funções que normalmente funcionam:**
- `NtOpen*` (maioria funciona bem)
- Funções com "Composition" no nome

**Funções para evitar:**
- `NtD*` (podem não funcionar)
- Funções com "SecureCookie" (causam tela azul)
- Funções em regiões críticas

#### 8.6. Ver o Código Original

Você verá algo como:

```assembly
dxgkrnl!NtOpenCompositionSurfaceSectionInfo:
fffff807`12345678  xor    eax, eax     ; Zera EAX
fffff807`1234567a  ret                  ; Retorna
```

Anote o endereço (ex: `fffff807'12345678`)

#### 8.7. Carregar o Driver com kdmapper

Na VM, execute:

```
kdmapper.exe driver.sys
```

#### 8.8. Verificar o Hook

No WinDbg, force reload do módulo novamente:

```
kd> .reload /f dxgkrnl.sys
```

Vá para o mesmo endereço no Disassembly. Agora você deve ver:

```assembly
dxgkrnl!NtOpenCompositionSurfaceSectionInfo:
fffff807`12345678  mov    rax, 0xFFFFF80712340000   ; Nosso shellcode!
fffff807`12345682  jmp    rax                       ; Pula para nossa função!
```

**SUCESSO!** O hook está funcionando! Os primeiros bytes foram substituídos pelo nosso shellcode!

#### 8.9. Testar com a Aplicação Usermode

Agora que o driver está carregado e o hook instalado:

1. Execute o `user_mode.exe` na VM
2. Veja a saída no console (deve mostrar endereços base reais!)
3. No WinDbg, digite `ed` (edit → display) para ver logs do kernel:
   ```
   kd> ed
   ```
4. Você deve ver mensagens de `DbgPrint`:
   ```
   [HOOK] req_base request for: ntdll.dll (PID: 1234)
   [HOOK] Returning base: 0x7ffb95870000
   ```

**Se vir endereços reais hexadecimais: ESTÁ 100% FUNCIONAL!** 🎉

---

## Resumo do Fluxo

```
1. DriverEntry é chamado quando o driver carrega
        ↓
2. Chama call_kernel_function
        ↓
3. Encontra NtQueryCompositionSurfaceHDRMetaData no dxgkrnl.sys
        ↓
4. Cria shellcode: MOV RAX, <endereço> + JMP RAX
        ↓
5. Substitui primeiros 12 bytes da função original
        ↓
6. Agora quando alguém chamar a função original...
        ↓
7. ...nosso shellcode executa e pula para hook_handle!
```

---

## Dicas Finais

1. **Sempre teste em VM** - Um erro no kernel = tela azul
2. **Faça snapshots** - Antes de testar, crie snapshot da VM
3. **Estude Assembly x64** - Entender os opcodes ajuda muito
4. **Use o WinDbg** - É a melhor ferramenta para entender o que está acontecendo
5. **Leia a documentação** - Microsoft Docs tem muita coisa sobre drivers

---

## Próximos Passos

Agora que você construiu o projeto, pode:

1. **Criar a aplicação usermode** - Veja o guia [COMO_CONSTRUIR_USERMODE.md](COMO_CONSTRUIR_USERMODE.md)
2. Hookar outras funções
3. Salvar bytes originais para fazer unhook
4. Criar um trampolim para chamar a função original
5. Estudar como anti-cheats detectam esses hooks

---

## Correções e Melhorias Importantes

Durante o desenvolvimento, fizemos várias correções críticas:

### 1. **Validação e Error Handling**
```cpp
// Sempre validar PEPROCESS e liberar com ObDereferenceObject!
PEPROCESS process = NULL;
status = PsLookupProcessByProcessId((HANDLE)pid, &process);

if (NT_SUCCESS(status) && process)
{
    // Usar o process...
    ObDereferenceObject(process);  // CRÍTICO: Evita memory leak!
}
```

### 2. **Proteção contra Crashes (Exception Handling)**
```cpp
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
```

### 3. **Validação de Memória**
```cpp
// Sempre validar ponteiros antes de usar!
if (!MmIsAddressValid(pPeb))
{
    KeUnstackDetachProcess(&state);
    return 0;
}
```

### 4. **Prevenir Loops Infinitos**
```cpp
// Adicionar contador em loops
ULONG max_iterations = 500;
ULONG current_iteration = 0;

for (...; ...; current_iteration++)
{
    if (current_iteration >= max_iterations)
        break;  // Prevenir loop infinito!
}
```

### 5. **Debug com DbgPrint**
```cpp
// Adicionar logs para debugging no WinDbg
DbgPrint("[HOOK] req_base request for: %s (PID: %d)\n", 
         module_name, pid);
DbgPrint("[HOOK] Returning base: 0x%llx\n", base_address);
```

### 6. **LoadLibrary("user32.dll") no Usermode**
**CRÍTICO:** Sem isso, o programa usermode trava ao chamar o hook!

```cpp
// No início do main() do usermode:
LoadLibraryA("user32.dll");  // Inicializa KernelCallbackTable
```

---

## Problemas Comuns e Soluções

### Problema 1: Tela Azul ao Carregar Driver
**Causa:** Erro no hook_handle (memória inválida, falta de validação)  
**Solução:** Adicionar validações e `__try/__except` blocks

### Problema 2: Usermode Trava ao Chamar Hook
**Causa:** `KernelCallbackTable` não inicializado  
**Solução:** `LoadLibraryA("user32.dll")` no início do main()

### Problema 3: Retorna Endereço 0
**Causa:** Nome da DLL errado, PID errado, ou função hookada diferente  
**Solução:** Verificar nomes e sincronizar driver ↔ usermode

### Problema 4: Memory Leak / Sistema Lento
**Causa:** Esqueceu de chamar `ObDereferenceObject`  
**Solução:** Sempre liberar objetos PEPROCESS!

---

**Parabéns!** Você criou um driver kernel com hook inline totalmente funcional! 

Continue estudando e experimentando (sempre em ambiente seguro)!

## Guias Relacionados

- **[COMO_CONSTRUIR_USERMODE.md](COMO_CONSTRUIR_USERMODE.md)** - Como criar a aplicação cliente
- **[readme_estudo_de_hooks_em_driver_win_dbg_kdmapper.md](readme_estudo_de_hooks_em_driver_win_dbg_kdmapper.md)** - Notas de debugging

