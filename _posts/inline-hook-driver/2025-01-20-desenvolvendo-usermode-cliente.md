---
title: "Desenvolvendo Cliente Usermode para Function Hooking - Parte 3"
date: 2025-01-20 10:00:00 -0300
categories: [Segurança, Kernel Development]
tags: [usermode, driver, comunicação, c++, windows, function-hooking]
---

## Introdução

Este post é a continuação de "[Desenvolvendo Driver de Function Hooking em Kernel Mode](/desenvolvendo-driver-function-hooking/)", onde criamos o driver kernel. Agora vamos desenvolver a aplicação usermode que se comunica com o driver através do hook.

> ⚠️ **Aviso**: Este conteúdo é **exclusivamente educacional**. Use apenas em ambientes controlados (VMs) e para fins de aprendizado.

## Arquitetura do Sistema

```
┌─────────────────────────────────────────────┐
│           USERMODE (cheat.exe)              │
├─────────────────────────────────────────────┤
│ 1. LoadLibraryA("user32.dll")               │ ← CRÍTICO!
│ 2. get_process_id("notepad.exe")            │
│ 3. get_module_base_address("ntdll.dll")     │
│    ↓                                        │
│    call_hook(&instructions)                 │
│    ↓                                        │
│    GetProcAddress("NtOpen...")              │
│    ↓                                        │
│    func(instructions) ──────────────────────┼─→ WIN32U.DLL
└─────────────────────────────────────────────┘         │
                                                        │
                                                        ↓
┌─────────────────────────────────────────────┐
│        KERNEL (dxgkrnl.sys hookado)         │
├─────────────────────────────────────────────┤
│ NtOpenCompositionSurfaceSectionInfo:        │
│   48 B8 [addr]  ; mov rax, hook_handle      │ ← SHELLCODE
│   FF E0         ; jmp rax                   │
│    ↓                                        │
│ hook_handle(instructions)                   │
│    ↓                                        │
│    if (req_base == TRUE)                    │
│      get_module_base_x64()                  │
│      instructions->base_adress = result     │
│    ↓                                        │
│ return STATUS_SUCCESS ──────────────────────┼─→ Volta para usermode
└─────────────────────────────────────────────┘
```

## Desenvolvendo o Cliente Usermode Passo a Passo

### Passo 1: Configuração do Projeto

**1.1. Criar Projeto no Visual Studio**
- Clique com botão direito na **Solution** → **Add** → **New Project**
- Selecione **"Empty Project" (C++)**
- Nome: `client`
- Clique em **Create**

**1.2. Configurações Iniciais**
- **Release** (ao invés de Debug)
- **x64** (plataforma 64 bits)

**Propriedades do Projeto:**
```
Configuration Properties → Advanced
├── Character Set → Not Set

Configuration Properties → C/C++ → General
└── Treat Warnings As Errors → No (/WX-)
```

### Passo 2: Criando main.cpp

```cpp
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <memory>
#include <string_view>
#include <cstdint>

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

uintptr_t base_address = 0;
static std::uint32_t process_id = 0;

// Chama a função hookada no kernel através do win32u.dll
template<typename ... Arg>
uint64_t call_hook(const Arg ... args) 
{
    HMODULE hWin32u = LoadLibraryA("win32u.dll");  // Carrega win32u.dll
    if (!hWin32u)
    {
        std::cout << "[ERROR] Failed to load win32u.dll" << std::endl;
        return 0;
    }

    void* hooked_function = GetProcAddress(hWin32u, "NtOpenCompositionSurfaceSectionInfo");  // Obtém endereço da função
    
    if (!hooked_function)
    {
        std::cout << "[ERROR] Failed to find NtOpenCompositionSurfaceSectionInfo" << std::endl;
        return 0;
    }

    std::cout << "[DEBUG] Calling hook at: 0x" << std::hex << hooked_function << std::endl;

    auto func = static_cast<uint64_t(__stdcall*)(Arg...)>(hooked_function);  // Converte para função

    uint64_t result = func(args ...);  // Chama a função hookada
    
    std::cout << "[DEBUG] Hook returned: 0x" << std::hex << result << std::endl;

    return result;
}

// Procura um processo pelo nome e retorna seu PID
static std::uint32_t get_process_id(const std::string_view process_name) 
{
    PROCESSENTRY32 processentry;  // Estrutura para informações do processo
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);  // Cria snapshot dos processos

    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    processentry.dwSize = sizeof(PROCESSENTRY32);  // Define tamanho da estrutura

    if (!Process32First(snapshot, &processentry))  // Pega primeiro processo
    {
        CloseHandle(snapshot);
        return 0;
    }

    while (Process32Next(snapshot, &processentry) == TRUE)  // Itera pelos processos
    {
        if (process_name.compare(processentry.szExeFile) == 0)  // Compara nome do processo
        {
            CloseHandle(snapshot);
            return processentry.th32ProcessID;  // Retorna PID encontrado
        }
    }
    
    CloseHandle(snapshot);
    return 0;
}

// Pega o endereço base de uma DLL dentro de um processo
static ULONG64 get_module_base_address(const char* module_name) 
{
    NULL_MEMORY instructions = { 0 };  // Inicializa estrutura de comunicação
    instructions.pid = process_id;  // Define PID do processo alvo
    instructions.req_base = TRUE;  // Marca como requisição de base address
    instructions.read = FALSE;  // Não é operação de leitura
    instructions.write = FALSE;  // Não é operação de escrita
    instructions.module_name = module_name;  // Define nome do módulo

    std::cout << "[DEBUG] Requesting base for: " << module_name 
              << " (PID: " << std::dec << process_id << ")" << std::endl;

    call_hook(&instructions);  // Chama função hookada no kernel

    ULONG64 base = 0;
    base = instructions.base_adress;  // Pega resultado retornado pelo kernel

    std::cout << "[DEBUG] Returned base: 0x" << std::hex << base << std::endl;

    return base;
}

// Lê um valor de qualquer tipo da memória de outro processo
template<class T>
T Read(UINT_PTR read_address) 
{
    T response{};  // Variável para armazenar resposta
    
    NULL_MEMORY instructions;  // Estrutura de comunicação
    instructions.pid = process_id;  // PID do processo alvo
    instructions.size = sizeof(T);  // Tamanho do tipo T
    instructions.address = read_address;  // Endereço a ser lido
    instructions.read = TRUE;  // Marca como operação de leitura
    instructions.write = FALSE;  // Não é escrita
    instructions.req_base = FALSE;  // Não é requisição de base
    instructions.output = &response;  // Ponteiro para onde escrever resultado

    call_hook(&instructions);  // Chama função hookada

    return response;  // Retorna valor lido
}

// Escreve dados na memória de outro processo
bool write_memory(UINT_PTR write_address, UINT_PTR source_address, SIZE_T write_size)
{
    NULL_MEMORY instructions;  // Estrutura de comunicação
    instructions.address = write_address;  // Endereço de destino
    instructions.pid = process_id;  // PID do processo alvo
    instructions.write = TRUE;  // Marca como operação de escrita
    instructions.read = FALSE;  // Não é leitura
    instructions.req_base = FALSE;  // Não é requisição de base
    instructions.buffer_address = (void*)source_address;  // Endereço dos dados
    instructions.size = write_size;  // Tamanho dos dados

    call_hook(&instructions);  // Chama função hookada

    return true;  // Retorna sucesso
}

// Helper para escrever valores de qualquer tipo
template<typename S>
bool write(UINT_PTR write_address, const S& value)
{
    return write_memory(write_address, (UINT_PTR)&value, sizeof(S));  // Chama write_memory com tamanho do tipo
}

int main() 
{
    std::cout << "[*] Loading user32.dll..." << std::endl;
    LoadLibraryA("user32.dll");  // CRÍTICO: Inicializa KernelCallbackTable
    std::cout << "[+] user32.dll loaded!" << std::endl;

    std::cout << "\n=== TESTE COM NOTEPAD ===" << std::endl;
    
    process_id = get_process_id("notepad.exe");  // Procura processo notepad

    if (!process_id)
    {
        std::cout << "[!] Notepad not found. Please open notepad.exe!" << std::endl;
        std::cout << "\nPress any key to exit..." << std::endl;
        std::cin.get();
        return 1;
    }

    std::cout << "[+] Found notepad.exe with PID: " << std::dec << process_id << std::endl;

    base_address = get_module_base_address("ntdll.dll");  // Pega base do ntdll.dll

    if(!base_address)
    {
        std::cout << "[!] Failed to get base address of ntdll.dll" << std::endl;
    }
    else
    {
        std::cout << "[+] ntdll.dll base address: 0x" << std::hex << base_address << std::endl;
    }

    std::cout << "\n=== TESTE COM CS2 ===" << std::endl;
    
    process_id = get_process_id("cs2.exe");  // Procura processo CS2

    if (!process_id)
    {
        std::cout << "[!] CS2 not running" << std::endl;
    }
    else
    {
        std::cout << "[+] Found cs2.exe with PID: " << std::dec << process_id << std::endl;
        
        base_address = get_module_base_address("client.dll");  // Pega base do client.dll
        
        if(!base_address)
        {
            std::cout << "[!] Failed to get client.dll" << std::endl;
        }
        else
        {
            std::cout << "[+] client.dll base: 0x" << std::hex << base_address << std::endl;
        }
    }

    std::cout << "\nPress any key to exit..." << std::endl;
    std::cin.get();
    return 0;
}
```

## Explicação Detalhada do Código

### 1. Estrutura NULL_MEMORY

Esta estrutura é **idêntica** à definida no driver kernel. É usada para comunicação entre usermode e kernel:

```cpp
typedef struct _NULL_MEMORY
{
    void* buffer_address;      // Para operações de escrita
    UINT_PTR address;          // Endereço alvo
    ULONGLONG size;            // Tamanho dos dados
    ULONG pid;                 // PID do processo
    BOOLEAN write;             // Flag de escrita
    BOOLEAN read;              // Flag de leitura
    BOOLEAN req_base;          // Flag de requisição de base
    void* output;              // Ponteiro para output
    const char* module_name;   // Nome do módulo
    ULONG64 base_adress;       // Base address retornado
}NULL_MEMORY;
```

### 2. Função call_hook()

Esta é a função **mais importante** do cliente usermode:

```cpp
template<typename ... Arg>
uint64_t call_hook(const Arg ... args) 
{
    // 1. Carrega win32u.dll
    HMODULE hWin32u = LoadLibraryA("win32u.dll");
    
    // 2. Obtém endereço da função hookada
    void* hooked_function = GetProcAddress(hWin32u, "NtOpenCompositionSurfaceSectionInfo");
    
    // 3. Converte para função e chama
    auto func = static_cast<uint64_t(__stdcall*)(Arg...)>(hooked_function);
    uint64_t result = func(args ...);
    
    return result;
}
```

**Como funciona:**
1. Carrega `win32u.dll` (biblioteca usermode que chama funções do kernel)
2. Obtém o endereço da função `NtOpenCompositionSurfaceSectionInfo`
3. Converte o ponteiro para uma função
4. Chama a função (que está hookada no kernel)

### 3. LoadLibraryA("user32.dll") - CRÍTICO!

```cpp
int main() 
{
    // CRÍTICO: Deve ser a PRIMEIRA coisa no main()
    LoadLibraryA("user32.dll");
    // ... resto do código
}
```

**Por que é necessário?**

O `user32.dll` inicializa a `KernelCallbackTable` no PEB (Process Environment Block). Esta tabela é essencial para:
- Comunicação entre usermode e kernel
- Chamadas de callback do sistema
- Transições de modo (usermode → kernel)

**Sem isso:** O programa trava ao tentar chamar a função hookada!

### 4. Operações Suportadas

#### A. Obter Base Address de DLL

```cpp
ULONG64 base = get_module_base_address("ntdll.dll");
```

**Fluxo:**
1. Cria estrutura `NULL_MEMORY` com `req_base = TRUE`
2. Define `module_name = "ntdll.dll"`
3. Chama `call_hook(&instructions)`
4. Kernel executa `get_module_base_x64()` e retorna o endereço
5. Usermode recebe o resultado em `instructions.base_adress`

#### B. Ler Memória

```cpp
int hp = Read<int>(base_address + 0x1234);
```

**Fluxo:**
1. Template `Read<T>()` cria estrutura com `read = TRUE`
2. Define `address` e `size`
3. Kernel executa `read_kernel_memory()`
4. Resultado é escrito em `instructions.output`

#### C. Escrever Memória

```cpp
write<int>(base_address + 0x1234, 100);
```

**Fluxo:**
1. Template `write<T>()` cria estrutura com `write = TRUE`
2. Define `address`, `buffer_address` e `size`
3. Kernel executa `write_kernel_memory()`

## Testando o Sistema Completo

### 1. Preparação

1. **Compile o driver:** `driver.sys`
2. **Compile o cliente:** `cheat.exe`
3. **Abra uma VM** com kernel debugging habilitado
4. **Conecte WinDbg** à VM

### 2. Execução

1. **Execute o cliente na VM:**
   ```powershell
   cheat.exe
   ```

2. **Saída esperada:**
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

   === TESTE COM CS2 ===
   [!] CS2 not running
   ```

### 3. Verificação no WinDbg

No WinDbg, você deve ver logs do kernel:

```
kd> ed
[HOOK] req_base request for: ntdll.dll (PID: 12345)
[HOOK] Returning base: 0x7ffb95870000
```

## Troubleshooting

### Problema 1: Programa Trava

**Sintoma:** Cliente trava ao chamar `call_hook()`

**Solução:** Verifique se `LoadLibraryA("user32.dll")` está **no início do main()**

### Problema 2: Retorna Endereço 0

**Sintoma:** `base_address` sempre retorna 0

**Possíveis causas:**
- Driver não está carregado
- Função hookada diferente entre driver e cliente
- PID do processo incorreto

**Solução:**
1. Verifique se o driver foi injetado com kdmapper
2. Confirme que ambos usam `NtOpenCompositionSurfaceSectionInfo`
3. Verifique se o processo existe

## Conceitos Importantes

### 1. win32u.dll

- **Biblioteca usermode** que fornece interface para chamadas do kernel
- Contém funções como `NtOpenCompositionSurfaceSectionInfo`
- É o "ponte" entre usermode e kernel mode

### 2. KernelCallbackTable

- **Tabela no PEB** que gerencia callbacks do kernel
- Inicializada pelo `user32.dll`
- Essencial para comunicação usermode ↔ kernel

### 3. Process Enumeration

```cpp
CreateToolhelp32Snapshot() → Process32First() → Process32Next()
```

**Usado para:**
- Encontrar processos pelo nome
- Obter PID para comunicação com kernel

### 4. Template Functions

```cpp
template<class T>
T Read(UINT_PTR address) { ... }

template<typename S>
bool write(UINT_PTR address, const S& value) { ... }
```


## Conclusão

Este projeto demonstra uma arquitetura completa de comunicação entre usermode e kernel:

- **Driver Kernel:** Intercepta funções do sistema
- **Cliente Usermode:** Comunica com o driver através de funções hookadas
- **Estrutura Compartilhada:** Permite troca de dados


**Posts relacionados:**
- [Encontrando Funções no Windows com WinDbg](/encontrando-funcoes-windbg/)
- [Desenvolvendo Driver de Function Hooking em Kernel Mode](/desenvolvendo-driver-function-hooking/)
