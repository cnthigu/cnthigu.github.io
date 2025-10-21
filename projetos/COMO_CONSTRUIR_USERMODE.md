# Como Construir o User Mode (Cliente) do Zero

> Guia completo para criar a aplicação usermode que se comunica com o driver kernel.


---

## 1. Criando o Projeto User Mode

### Passo 1: Adicionar Novo Projeto

1. Clique com botão direito na **Solution** → Add → New Project
2. Selecione **"Empty Project"** (C++)
3. Nome: `user_mode`
4. Clique em **Create**

### Passo 2: Criar o arquivo main.cpp

1. Botão direito em **Source Files** (do projeto user_mode) → Add → New Item
2. Selecione **C++ File (.cpp)**
3. Nome: `main.cpp`

---

## 2. Configurações do Projeto

**IMPORTANTE:** O projeto usermode precisa das mesmas configurações do driver para evitar erros!

### Configurações Necessárias:

Botão direito no projeto `user_mode` → **Properties**

#### A. Character Set
```
Configuration Properties → Advanced
└── Character Set → Not Set
```

**Por quê?** Para compatibilidade com as strings do kernel.

#### B. Warning Level (opcional mas recomendado)
```
Configuration Properties → C/C++ → General
└── Treat Warnings As Errors → No (/WX-)
```

---

## 3. Estrutura NULL_MEMORY

Esta é a estrutura que usamos para comunicar com o driver. Ela precisa ser **IDÊNTICA** à do driver!

### No início do main.cpp:

```cpp
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <memory>
#include <string_view>
#include <cstdint>

// ========================================
// STRUCT: NULL_MEMORY
// ========================================
// Esta estrutura é usada para passar instruções para o driver
// IMPORTANTE: Deve ser IDÊNTICA à estrutura no driver!
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

// Variáveis globais
uintptr_t base_address = 0;
static std::uint32_t process_id = 0;
```

### ⚠️ IMPORTANTE: Adicionar no driver também!

No arquivo `memory.h` do **driver**, adicione esta estrutura **NO TOPO**, antes de qualquer função:

```cpp
#pragma once
#include "definitions.h"

// ========================================
// STRUCT: NULL_MEMORY (compartilhada com usermode)
// ========================================
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

// ... resto do código
```

---

## 4. Função call_hook - Comunicação com o Kernel

Esta é a função **MAIS IMPORTANTE**! Ela chama a função hookada para se comunicar com o driver.

```cpp
// ========================================
// FUNÇÃO: call_hook
// ========================================
// O QUE FAZ: Chama a função hookada no kernel através do win32u.dll
// COMO FUNCIONA:
//   1. Carrega win32u.dll (DLL usermode que chama funções do kernel)
//   2. Pega o endereço de NtOpenCompositionSurfaceSectionInfo
//   3. Chama essa função (que está hookada pelo nosso driver)
//   4. O driver intercepta e executa nossas operações
//
// SOLUÇÃO DO FÓRUM: Carregar user32.dll ANTES resolve travamentos!
template<typename ... Arg>
uint64_t call_hook(const Arg ... args) 
{
    // Carregar win32u.dll
    HMODULE hWin32u = LoadLibraryA("win32u.dll");
    if (!hWin32u)
    {
        std::cout << "[ERROR] Failed to load win32u.dll" << std::endl;
        return 0;
    }

    // Pegar a função hookada
    // IMPORTANTE: Este nome DEVE ser o mesmo que o driver está hookando!
    void* hooked_function = GetProcAddress(hWin32u, "NtOpenCompositionSurfaceSectionInfo");
    
    if (!hooked_function)
    {
        std::cout << "[ERROR] Failed to find NtOpenCompositionSurfaceSectionInfo" << std::endl;
        return 0;
    }

    std::cout << "[DEBUG] Calling hook at: 0x" << std::hex << hooked_function << std::endl;

    // Fazer o cast para o tipo de função correto
    // __stdcall é a convenção de chamada usada pelas funções do Windows
    auto func = static_cast<uint64_t(__stdcall*)(Arg...)>(hooked_function);

    // Chamar a função
    // O driver vai interceptar esta chamada e executar nosso código!
    uint64_t result = func(args ...);
    
    std::cout << "[DEBUG] Hook returned: 0x" << std::hex << result << std::endl;

    return result;
}
```

### Como funciona o fluxo:

```
1. USERMODE: call_hook(&instructions)
             ↓
2. USERMODE: Chama NtOpenCompositionSurfaceSectionInfo (win32u.dll)
             ↓
3. WIN32U: Chama a função no kernel (dxgkrnl.sys)
             ↓
4. DRIVER: Hook intercepta! (shellcode: mov rax, addr; jmp rax)
             ↓
5. DRIVER: Executa hook_handle(instructions)
             ↓
6. DRIVER: Processa req_base/read/write
             ↓
7. DRIVER: Retorna para usermode
             ↓
8. USERMODE: Recebe o resultado em instructions
```

---

## 5. Função get_process_id - Encontrar Processos

Esta função procura um processo pelo nome e retorna seu PID.

```cpp
// ========================================
// FUNÇÃO: get_process_id
// ========================================
// O QUE FAZ: Encontra um processo pelo nome e retorna seu PID
// COMO USA: process_id = get_process_id("notepad.exe");
// RETORNA: PID do processo ou 0 se não encontrar
static std::uint32_t get_process_id(const std::string_view process_name) 
{
    PROCESSENTRY32 processentry;
    
    // Criar snapshot de todos os processos
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    // Configurar o tamanho da estrutura
    processentry.dwSize = sizeof(PROCESSENTRY32);

    // Pegar o primeiro processo
    if (!Process32First(snapshot, &processentry))
    {
        CloseHandle(snapshot);
        return 0;
    }

    // Iterar por todos os processos
    while (Process32Next(snapshot, &processentry) == TRUE) 
    {
        // Comparar o nome
        if (process_name.compare(processentry.szExeFile) == 0)
        {
            CloseHandle(snapshot);
            return processentry.th32ProcessID;  // Encontrou!
        }
    }
    
    CloseHandle(snapshot);
    return 0;  // Não encontrou
}
```

### Exemplo de uso:

```cpp
process_id = get_process_id("cs2.exe");
if (process_id == 0) {
    std::cout << "CS2 não está rodando!" << std::endl;
}
```

---

## 6. Função get_module_base_address - Pegar Base de DLLs

Esta função pega o endereço base de uma DLL dentro de um processo.

```cpp
// ========================================
// FUNÇÃO: get_module_base_address
// ========================================
// O QUE FAZ: Pega o endereço base de uma DLL dentro de um processo
// COMO USA: base = get_module_base_address("ntdll.dll");
// RETORNA: Endereço base da DLL ou 0 se não encontrar
//
// IMPORTANTE: process_id deve estar definido antes!
static ULONG64 get_module_base_address(const char* module_name) 
{
    // Criar estrutura de instruções
    NULL_MEMORY instructions = { 0 };
    instructions.pid = process_id;         // PID do processo alvo
    instructions.req_base = TRUE;          // Estamos pedindo base address
    instructions.read = FALSE;
    instructions.write = FALSE;
    instructions.module_name = module_name; // Nome da DLL

    std::cout << "[DEBUG] Requesting base for: " << module_name 
              << " (PID: " << std::dec << process_id << ")" << std::endl;

    // Chamar o driver através do hook
    call_hook(&instructions);

    // O driver preencheu instructions.base_adress
    ULONG64 base = 0;
    base = instructions.base_adress;

    std::cout << "[DEBUG] Returned base: 0x" << std::hex << base << std::endl;

    return base;
}
```

### Como o driver processa:

1. Recebe `instructions` com `req_base == TRUE`
2. Pega o PID e nome do módulo
3. Usa `PsLookupProcessByProcessId` para pegar o `PEPROCESS`
4. Usa `get_module_base_x64` para iterar pelas DLLs do processo
5. Retorna o endereço em `instructions.base_adress`

### Exemplo de uso:

```cpp
// Encontrar cs2.exe
process_id = get_process_id("cs2.exe");

// Pegar endereço base de client.dll dentro do CS2
base_address = get_module_base_address("client.dll");

// Agora você pode ler/escrever usando base_address + offset
int hp = Read<int>(base_address + 0x1234);
```

---

## 7. Função Read - Ler Memória

Esta função lê memória de outro processo.

```cpp
// ========================================
// FUNÇÃO: Read (template)
// ========================================
// O QUE FAZ: Lê um valor de qualquer tipo da memória de outro processo
// COMO USA: int hp = Read<int>(0x7FF612345678);
// RETORNA: O valor lido (tipo T)
//
// TEMPLATE: Pode ler qualquer tipo (int, float, char, struct, etc.)
template<class T>
T Read(UINT_PTR read_address) 
{
    T response{};  // Variável para receber o resultado
    
    // Criar estrutura de instruções
    NULL_MEMORY instructions;
    instructions.pid = process_id;       // PID do processo alvo
    instructions.size = sizeof(T);       // Tamanho do tipo T
    instructions.address = read_address; // Endereço para ler
    instructions.read = TRUE;            // Operação de leitura
    instructions.write = FALSE;
    instructions.req_base = FALSE;
    instructions.output = &response;     // Ponteiro para receber o resultado

    // Chamar o driver
    call_hook(&instructions);

    // O driver preencheu response com o valor lido
    return response;
}
```

### Como o driver processa:

1. Recebe `instructions` com `read == TRUE`
2. Chama `read_kernel_memory(pid, address, output, size)`
3. Usa `MmCopyVirtualMemory` para copiar a memória do processo alvo
4. Os dados são copiados para `instructions.output`

### Exemplos de uso:

```cpp
// Ler um int (4 bytes)
int player_health = Read<int>(base_address + 0x1234);

// Ler um float
float player_speed = Read<float>(base_address + 0x5678);

// Ler uma estrutura
struct Vector3 {
    float x, y, z;
};
Vector3 position = Read<Vector3>(base_address + 0xABCD);

// Ler um byte
uint8_t flags = Read<uint8_t>(base_address + 0x100);
```

---

## 8. Função write_memory - Escrever Memória

Esta função escreve dados na memória de outro processo.

```cpp
// ========================================
// FUNÇÃO: write_memory
// ========================================
// O QUE FAZ: Escreve dados na memória de outro processo
// COMO USA: write_memory(endereco, (UINT_PTR)&dados, tamanho);
// RETORNA: true se sucesso
bool write_memory(UINT_PTR write_address, UINT_PTR source_address, SIZE_T write_size)
{
    // Criar estrutura de instruções
    NULL_MEMORY instructions;
    instructions.address = write_address;           // Onde escrever
    instructions.pid = process_id;                  // PID do processo alvo
    instructions.write = TRUE;                      // Operação de escrita
    instructions.read = FALSE;
    instructions.req_base = FALSE;
    instructions.buffer_address = (void*)source_address;  // Dados para escrever
    instructions.size = write_size;                 // Tamanho

    // Chamar o driver
    call_hook(&instructions);

    return true;
}

// ========================================
// FUNÇÃO: write (template helper)
// ========================================
// O QUE FAZ: Helper para escrever valores de qualquer tipo
// COMO USA: write<int>(endereco, 9999);
template<typename S>
bool write(UINT_PTR write_address, const S& value)
{
    return write_memory(write_address, (UINT_PTR)&value, sizeof(S));
}
```

### Como o driver processa:

1. Recebe `instructions` com `write == TRUE`
2. Copia `buffer_address` para um buffer no kernel
3. Chama `write_kernel_memory(pid, address, buffer, size)`
4. Usa técnicas para escrever na memória do processo alvo
5. Libera o buffer

### Exemplos de uso:

```cpp
// Escrever um int
write<int>(base_address + 0x1234, 9999);

// Escrever um float
write<float>(base_address + 0x5678, 100.0f);

// Escrever um byte
write<uint8_t>(base_address + 0x100, 0xFF);

// Escrever uma estrutura
Vector3 newPos = {10.0f, 20.0f, 30.0f};
write<Vector3>(base_address + 0xABCD, newPos);
```

---

## 9. Função main - Ponto de Entrada

Agora juntamos tudo na função principal!

```cpp
// ========================================
// FUNÇÃO: main
// ========================================
// Ponto de entrada da aplicação
int main() 
{
    // ============================================
    // SOLUÇÃO CRÍTICA DO FÓRUM!
    // ============================================
    // Loading user32 fills out a kernel callback table that is used by 
    // KiUserCallbackDispatcher
    // mov rax, gs:60h  ; process environment block
    // mov r9, [rax+58h] ; peb->KernelCallbackTable
    //
    // SEM ISSO, O PROGRAMA TRAVA AO CHAMAR O HOOK!
    
    std::cout << "[*] Loading user32.dll..." << std::endl;
    LoadLibraryA("user32.dll");
    std::cout << "[+] user32.dll loaded!" << std::endl;

    // ============================================
    // TESTE COM NOTEPAD
    // ============================================
    std::cout << "\n=== TESTE COM NOTEPAD ===" << std::endl;
    
    // 1. Encontrar o processo
    process_id = get_process_id("notepad.exe");

    if (!process_id)
    {
        std::cout << "[!] Notepad not found. Please open notepad.exe!" << std::endl;
        std::cout << "\nPress any key to exit..." << std::endl;
        std::cin.get();
        return 1;
    }

    std::cout << "[+] Found notepad.exe with PID: " << std::dec << process_id << std::endl;

    // 2. Pegar base address de ntdll.dll (sempre existe)
    base_address = get_module_base_address("ntdll.dll");

    if(!base_address)
    {
        std::cout << "[!] Failed to get base address of ntdll.dll" << std::endl;
    }
    else
    {
        std::cout << "[+] ntdll.dll base address: 0x" << std::hex << base_address << std::endl;
        
        // Agora você poderia ler/escrever memória aqui!
        // Exemplo:
        // int value = Read<int>(base_address + 0x1000);
    }

    // ============================================
    // TESTE COM CS2 (exemplo)
    // ============================================
    std::cout << "\n=== TESTE COM CS2 ===" << std::endl;
    
    process_id = get_process_id("cs2.exe");

    if (!process_id)
    {
        std::cout << "[!] CS2 not running" << std::endl;
    }
    else
    {
        std::cout << "[+] Found cs2.exe with PID: " << std::dec << process_id << std::endl;
        
        // Pegar base de client.dll
        base_address = get_module_base_address("client.dll");
        
        if(!base_address)
        {
            std::cout << "[!] Failed to get client.dll" << std::endl;
        }
        else
        {
            std::cout << "[+] client.dll base: 0x" << std::hex << base_address << std::endl;
            
            // Aqui você faria seu cheat:
            // int hp = Read<int>(base_address + OFFSET_HP);
            // write<int>(base_address + OFFSET_HP, 9999);
        }
    }

    std::cout << "\nPress any key to exit..." << std::endl;
    std::cin.get();
    return 0;
}
```

---

## 10. Compilando e Testando

### Passo 1: Compilar o Projeto

```
Build → Build Solution (Ctrl+Shift+B)
```

O executável será gerado em: `x64\Release\user_mode.exe`

### Passo 2: Preparar o Ambiente

1. **Na VM ou PC de teste:**
   - Carregue o driver: `kdmapper.exe KernelCheatYT.sys`
   - Deve mostrar `[+] success`

2. **Abra o processo alvo:**
   - Para teste: Abra o Notepad (`Win + R → notepad`)
   - Para CS2: Execute o jogo

### Passo 3: Executar

```
user_mode.exe
```

### Saída Esperada (com Notepad):

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

Press any key to exit...
```

✅ **Se aparecer o endereço hexadecimal real, FUNCIONOU!**

---

## Resumo do Fluxo Completo

```
┌─────────────────────────────────────────────┐
│           USERMODE (user_mode.exe)          │
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

---

## Troubleshooting

### Problema 1: Programa trava ao chamar hook
**Solução:** Certifique-se de carregar `user32.dll` ANTES de tudo no `main()`!

### Problema 2: Endereço retorna 0
**Possíveis causas:**
- Driver não está carregado
- Nome da DLL está errado
- PID está errado
- Função hookada no driver é diferente do usermode

### Problema 3: Tela azul
**Possíveis causas:**
- Bug no driver (revise `hook_handle`)
- Problema no `get_module_base_x64`
- Memória inválida sendo acessada

---

## Próximos Passos

Agora que você tem tudo funcionando:

1. **Estude pattern scanning** para encontrar offsets dinamicamente
2. **Adicione mais funcionalidades** (ESP, Aimbot, etc.)
3. **Melhore a interface** (adicione menu, hotkeys)
4. **Implemente anti-detecção** (ofuscação, randomização)
5. **Aprenda sobre anti-cheats** e como eles detectam

---

