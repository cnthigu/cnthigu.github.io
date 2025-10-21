# Driver de Hook em Kernel Mode + Aplicação User Mode


Este é um **sistema completo de comunicação kernel ↔ usermode** que demonstra a técnica de **Inline Hooking**.

Especificamente, ele:
- **Driver Kernel:** Intercepta a função `NtOpenCompositionSurfaceSectionInfo` do driver `dxgkrnl.sys`
- **Aplicação Usermode:** Comunica-se com o driver através da função hookada
- Permite ler/escrever memória de outros processos
- Retorna endereços base de DLLs carregadas em processos
- Modifica memória protegida (read-only) usando MDL (Memory Descriptor List)
- Usa shellcode em assembly x64 para criar o redirecionamento

**Aplicações educacionais:**
- Entender como anti-cheats detectam hooks
- Aprender sobre proteção de memória no kernel
- Estudar arquitetura de drivers Windows
- Praticar engenharia reversa e análise de código
- Aprender comunicação kernel ↔ usermode

---

## 📚 Guias Disponíveis

Este projeto contém guias completos e detalhados:

| Guia | Descrição |
|------|-----------|
| **[COMO_CONSTRUIR.md](COMO_CONSTRUIR.md)** | Tutorial completo para criar o driver kernel do zero |
| **[COMO_CONSTRUIR_USERMODE.md](COMO_CONSTRUIR_USERMODE.md)** | Tutorial completo para criar a aplicação usermode |
| **[readme_estudo_de_hooks_em_driver_win_dbg_kdmapper.md](readme_estudo_de_hooks_em_driver_win_dbg_kdmapper.md)** | Notas de debugging com WinDbg e kdmapper |

**Recomendação:** Se você é iniciante, siga os guias nesta ordem:
1. Leia este README para entender o conceito
2. Siga [COMO_CONSTRUIR.md](COMO_CONSTRUIR.md) para criar o driver
3. Siga [COMO_CONSTRUIR_USERMODE.md](COMO_CONSTRUIR_USERMODE.md) para criar a aplicação cliente
4. Use o guia de debugging para troubleshooting

---

## Como funciona um Hook Inline?

Um **hook inline** substitui os primeiros bytes de uma função com um **jump** para sua própria função.

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
    ; (os bytes restantes são sobrescritos)
```

Agora, quando alguém chamar `NtOpenCompositionSurfaceSectionInfo`, ele vai executar **sua função** ao invés da original!

### O Shellcode (12 bytes)

```
48 B8 [endereço de 64 bits] FF E0
│  │   └─────────┬─────────┘  │  │
│  │             │             │  └─> JMP RAX (pula para o endereço)
│  └─────────────┴─────────────┴───> MOV RAX, <endereço>
```

Este código:
1. Carrega o endereço da sua função em `RAX`
2. Pula para esse endereço

---

## Estrutura do Projeto

```
Driver/
│
├── Driver                       # Driver Kernel
│   ├── main.cpp                 # Ponto de entrada do driver (DriverEntry)
│   ├── hook.cpp/h               # Implementação do hook inline
│   ├── memory.cpp/h             # Funções para manipulação de memória
│   ├── definitions.h            # Definições de estruturas não documentadas
│   ├── Driver.inf               # Arquivo de informações do driver
│   └── Driver.vcxproj           # Projeto do Visual Studio
│
├── user_mode/                   # Aplicação Usermode
│   ├── main.cpp                 # Cliente que se comunica com o driver
│   └── user_mode.vcxproj        # Projeto do Visual Studio
│
├── COMO_CONSTRUIR.md            # Guia completo do driver
├── COMO_CONSTRUIR_USERMODE.md   # Guia completo do usermode
├── README.md                    # Este arquivo
├── .gitignore                   # Arquivos ignorados pelo Git
│
└── x64/Release/                 # Binários compilados
    ├── Driver.sys               # Driver final
    └── user_mode.exe            # Aplicação final
```

### Arquivos Principais

| Arquivo | Descrição |
|---------|-----------|
| **Driver Kernel** | |
| `main.cpp` | Ponto de entrada - chama a função de hook |
| `hook.cpp` | Contém a lógica de hook e comunicação com usermode |
| `memory.cpp` | Funções para manipular memória e processos |
| `definitions.h` | Estruturas e declarações de APIs não documentadas |
| **Aplicação Usermode** | |
| `user_mode/main.cpp` | Cliente que se comunica com o driver hookado |

---

## Pré-requisitos

### Software Necessário

1. **Windows 10/11** (de preferência em uma VM)
2. **Visual Studio 2019 ou 2022** com:
   - Desenvolvimento para Desktop com C++
   - Windows Driver Kit (WDK)
3. **SDK do Windows** (Windows 10/11 SDK)
4. **kdmapper** (para carregar o driver sem assinatura digital)
   - Disponível em: https://github.com/TheCruZ/kdmapper

### Conhecimento Recomendado

- Programação em C/C++
- Conceitos básicos de Assembly x64
- Estrutura de drivers Windows (WDM/KMDF)
- Como funciona o kernel do Windows

---

## Como Compilar

### Passo 1: Abrir o Projeto

1. Clone o repositório ou baixe os arquivos
2. Abra o arquivo `KernelCheatYT.sln` no Visual Studio

### Passo 2: Configurar o Build

1. Selecione a configuração: **Release**
2. Selecione a plataforma: **x64**
3. Verifique se o WDK está instalado corretamente

### Passo 3: Compilar

1. No Visual Studio: `Build` → `Build Solution` (Ctrl+Shift+B)
2. O driver será gerado em: `x64\Release\KernelCheatYT\KernelCheatYT.sys`

### Possíveis Erros de Compilação

**Erro: WDK não encontrado**
- Instale o Windows Driver Kit (WDK) compatível com sua versão do Visual Studio

**Erro: Target platform version**
- Clique com botão direito no projeto → Properties → General → Windows SDK Version
- Selecione a versão instalada no seu sistema

---


### 3. Verificar o Hook no WinDbg

O driver será carregado e o hook será aplicado automaticamente. Para verificar:

```powershell
# No WinDbg (modo kernel):
lm m dxgkrnl    # Lista o módulo dxgkrnl
x dxgkrnl!NtOpenCompositionSurfaceSectionInfo    # Mostra o endereço
u dxgkrnl!NtOpenCompositionSurfaceSectionInfo    # Disassembly - você verá o shellcode!
```

Você deverá ver algo como:
```assembly
dxgkrnl!NtOpenCompositionSurfaceSectionInfo:
fffff807`12345678  48b8  mov rax, 0xFFFFF8071234ABCD    ; Nosso shellcode!
fffff807`12345682  ffe0  jmp rax
```

### 4. Testar a Comunicação Usermode ↔ Kernel

Após carregar o driver, execute a aplicação usermode:

```powershell
user_mode.exe
```

**Saída esperada (sucesso):**
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

---

## Entendendo o Código Passo a Passo

### 1. `main.cpp` - Ponto de Entrada

```cpp
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING reg_path) 
{
    // DriverEntry é chamado quando o driver é carregado
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(reg_path);

    // Chama a função que vai instalar o hook
    nullhook::call_kernel_function(&nullhook::hook_handle);

    return STATUS_SUCCESS;  // Retorna sucesso
}
```

**O que acontece:**
- Windows carrega o driver
- `DriverEntry` é executado
- Chamamos nossa função de hook
- Driver retorna sucesso e permanece na memória

---

### 2. `hook.cpp` - O Coração do Hook

#### Função: `call_kernel_function`

```cpp
bool nullhook::call_kernel_function(void* kernel_function_address) 
{
    // Verifica se o endereço é válido
    if (!kernel_function_address)
        return false;

    // PASSO 1: Encontrar a função alvo
    PVOID* function = reinterpret_cast<PVOID*>(
        get_system_module_export(
            "\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", 
            "NtOpenCompositionSurfaceSectionInfo"
        )
    );
    
    if (!function)
        return false;

    // PASSO 2: Criar o shellcode
    BYTE orig[12] = {0};  // Buffer para os 12 bytes
    
    // MOV RAX, <endereço>  (48 B8)
    BYTE shell_code[] = { 0x48, 0xB8 };
    
    // JMP RAX  (FF E0)
    BYTE shell_code_end[] = { 0xFF, 0xE0 };
    
    // PASSO 3: Montar o shellcode completo
    RtlSecureZeroMemory(orig, sizeof(orig));
    
    // Copia: 48 B8
    memcpy((PVOID)((ULONG_PTR)orig), &shell_code, sizeof(shell_code));
    
    // Copia: [8 bytes do endereço]
    uintptr_t hook_address = reinterpret_cast<uintptr_t>(kernel_function_address);
    memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code)), &hook_address, sizeof(void*));
    
    // Copia: FF E0
    memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code) + sizeof(void*)), &shell_code_end, sizeof(shell_code_end));

    // PASSO 4: Escrever na memória protegida
    write_to_readonly_memory(function, &orig, sizeof(orig));

    return true;
}
```

**Detalhamento:**

| Etapa | O que faz | Por quê? |
|-------|-----------|----------|
| 1 | Encontra o endereço da função alvo | Precisamos saber ONDE escrever |
| 2 | Cria os opcodes do shellcode | Instruções assembly que fazem o jump |
| 3 | Monta o shellcode com o endereço | Combina tudo em 12 bytes |
| 4 | Escreve na memória (protegida!) | Substitui o código original |

#### Função: `hook_handle`

```cpp
NTSTATUS nullhook::hook_handle(PVOID called_param) 
{
    // Esta função será chamada quando alguém chamar NtOpenCompositionSurfaceSectionInfo
    
    if (!called_param)
        return STATUS_INVALID_PARAMETER;

    NULL_MEMORY* instructions = (NULL_MEMORY*)called_param;

    // Processar requisições do usermode:
    
    // 1. req_base = TRUE → Retornar endereço base de uma DLL
    if (instructions->req_base == TRUE)
    {
        DbgPrint("[HOOK] req_base for: %s (PID: %d)\n", 
                 instructions->module_name, instructions->pid);
        
        // Converter string, pegar processo, buscar DLL
        // Retornar em instructions->base_adress
        
        return STATUS_SUCCESS;
    }
    
    // 2. write = TRUE → Escrever memória em outro processo
    if (instructions->write == TRUE) 
    {
        // Alocar buffer, copiar dados, escrever no processo alvo
    }

    // 3. read = TRUE → Ler memória de outro processo
    if (instructions->read == TRUE) 
    {
        // Ler memória e retornar em instructions->output
    }
    
    return STATUS_SUCCESS;
}
```

---

### 3. `memory.cpp` - Manipulação de Memória

#### Função: `get_system_module_base`

```cpp
PVOID get_system_module_base(const char* module_name) 
{
    ULONG bytes = 0;
    
    // 1. Pergunta ao sistema quantos bytes são necessários
    ZwQuerySystemInformation(SystemModuleInformation, NULL, bytes, &bytes);
    
    if (!bytes) 
        return NULL;

    // 2. Aloca memória para a lista de módulos
    PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)
        ExAllocatePoolWithTag(NonPagedPool, bytes, 0x636e7474);

    // 3. Obtém a lista de módulos carregados
    ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);    

    // 4. Procura pelo módulo específico
    PVOID module_base = 0;
    for (ULONG i = 0; i < modules->NumberOfModules; i++) 
    {
        if (_stricmp((char*)modules->Modules[i].FullPathName, module_name) == NULL)
        {
            module_base = modules->Modules[i].ImageBase;
            break;
        }
    }

    // 5. Libera a memória e retorna
    ExFreePoolWithTag(modules, NULL);
    return module_base;
}
```

**O que faz:**
1. Consulta o sistema sobre módulos carregados
2. Aloca memória para armazenar a lista
3. Itera pelos módulos procurando pelo nome
4. Retorna o endereço base do módulo

#### Função: `get_system_module_export`

```cpp
PVOID get_system_module_export(const char* module_name, LPCSTR routine_name) 
{
    // 1. Primeiro encontra o módulo
    PVOID lpModule = get_system_module_base(module_name);
    
    if (lpModule <= NULL)
        return NULL;

    // 2. Usa a função do Windows para encontrar a export
    return RtlFindExportedRoutineByName(lpModule, routine_name);
}
```

**Como funciona:**
- Todo módulo PE (Portable Executable) tem uma tabela de exports
- `RtlFindExportedRoutineByName` parseia essa tabela
- Retorna o endereço virtual da função

#### Função: `write_to_readonly_memory`

```cpp
bool write_to_readonly_memory(void* address, void* buffer, size_t size)
{
    // 1. Aloca um MDL (Memory Descriptor List)
    PMDL Mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);
    
    if(!Mdl)
        return false;

    // 2. Faz lock das páginas de memória
    MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
    
    // 3. Mapeia as páginas em um novo endereço virtual
    PVOID Mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    
    // 4. Altera as permissões para RWX (Read-Write-Execute)
    MmProtectMdlSystemAddress(Mdl, PAGE_EXECUTE_READWRITE);

    // 5. Escreve os dados
    write_memory(Mapping, buffer, size);

    // 6. Limpeza: desmapeia, unlock, libera
    MmUnmapLockedPages(Mapping, Mdl);
    MmUnlockPages(Mdl);
    IoFreeMdl(Mdl);

    return true;
}
```

**Por que é necessário?**

As páginas de código do kernel são **read-only** por segurança. Para modificá-las:

1. **MDL (Memory Descriptor List)**: Estrutura que descreve páginas físicas
2. **Lock**: Previne que as páginas sejam paginadas
3. **Mapeamento**: Cria um novo endereço virtual para as mesmas páginas físicas
4. **Permissões**: Altera para RWX temporariamente
5. **Escrita**: Modifica o conteúdo
6. **Limpeza**: Libera todos os recursos

---

## Conceitos Importantes

### 1. O que é um Driver Kernel?

Um driver kernel é um programa que roda em **Ring 0** (modo kernel), com acesso total ao sistema:

```
Ring 3 (User Mode)        Ring 0 (Kernel Mode)
┌───────────────┐         ┌───────────────┐
│  Aplicativos  │         │    Kernel     │
│  (você aqui)  │ ──────> │   Drivers     │
└───────────────┘         └───────────────┘
    Limitado                  Acesso Total
```

### 2. Por que Hookar no Kernel?

**Vantagens:**
- Mais difícil de detectar
- Pode interceptar qualquer chamada do sistema
- Bypassa proteções de user-mode

**Desvantagens:**
- Um erro = BSOD (tela azul)
- Mais complexo de desenvolver
- Difícil de debugar

### 3. Por que `NtOpenCompositionSurfaceSectionInfo`?

Esta função foi escolhida porque:
- Está no `dxgkrnl.sys` (DirectX Graphics Kernel)
- Raramente é chamada (menos chance de crash)
- É exportada (podemos encontrá-la facilmente)
- Funciona bem para comunicação usermode ↔ kernel
- Boa para fins educacionais

**Outras funções que funcionam:**
- `NtOpen*` (maioria das funções NtOpen)
- Funções com "Composition" no nome
- Lista completa: https://j00ru.vexillium.org/syscalls/win32k/64/

**Funções para evitar:**
- Funções com "SecureCookie" (causam BSOD)
- Funções em regiões críticas do sistema

### 4. O que é kdmapper?

`kdmapper` é uma ferramenta que usa uma vulnerabilidade no driver `iqvw64e.sys` da Intel para:
1. Carregar drivers não assinados
2. Executar código no kernel
3. Mapear o driver na memória sem registro

**Aviso:** Só funciona em alguns sistemas e só deve ser usado para aprendizado!

### 5. Assembly x64 - Referência Rápida

| Opcode | Instrução | Descrição |
|--------|-----------|-----------|
| `48 B8` | `MOV RAX, imm64` | Move um valor de 64 bits para RAX |
| `FF E0` | `JMP RAX` | Pula para o endereço em RAX |
| `90` | `NOP` | No Operation (não faz nada) |
| `C3` | `RET` | Retorna da função |

### 6. MDL (Memory Descriptor List)

Um MDL é uma estrutura que descreve páginas de memória física:

```
Virtual Address  ──MDL──>  Physical Pages
┌─────────────┐          ┌──────┐
│ 0x12345000  │ ───────> │ Page │
│ 0x12346000  │          │ Page │
│ 0x12347000  │          │ Page │
└─────────────┘          └──────┘
```

Usado para:
- Transferências DMA
- Modificar memória protegida
- Mapear memória entre processos

---

## Fluxo Completo: Usermode ↔ Kernel

```
┌─────────────────────────────────────────────────────────────────┐
│                      APLICAÇÃO USERMODE                         │
│                      (user_mode.exe)                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. LoadLibraryA("user32.dll");        ← CRÍTICO!              │
│     └─> Inicializa KernelCallbackTable                         │
│                                                                 │
│  2. process_id = get_process_id("cs2.exe");                    │
│     └─> Encontra PID do processo alvo                          │
│                                                                 │
│  3. base = get_module_base_address("client.dll");              │
│     │                                                           │
│     ├─> Cria struct NULL_MEMORY                                │
│     │   └─> pid = process_id                                   │
│     │   └─> req_base = TRUE                                    │
│     │   └─> module_name = "client.dll"                         │
│     │                                                           │
│     ├─> call_hook(&instructions);                              │
│     │   │                                                       │
│     │   ├─> LoadLibraryA("win32u.dll")                         │
│     │   ├─> GetProcAddress(hWin32u, "NtOpen...")               │
│     │   └─> func(&instructions);  ← Chama função hookada!      │
│     │       │                                                   │
└─────┼───────┼───────────────────────────────────────────────────┘
        │       │
        │       ↓
┌───────┼───────────────────────────────────────────────────────────┐
│       │        WIN32U.DLL (usermode)                              │
│       │                                                            │
│       └─────> NtOpenCompositionSurfaceSectionInfo()               │
│                       │                                            │
│                       │ (syscall para kernel)                     │
└───────────────────────┼────────────────────────────────────────────┘
                        │
                        ↓
┌───────────────────────┼────────────────────────────────────────────┐
│                       │        KERNEL MODE                         │
│                       │                                            │
│       ┌───────────────▼─────────────────┐                         │
│       │  dxgkrnl!NtOpen... (hookado)   │                         │
│       ├─────────────────────────────────┤                         │
│       │  48 B8 [addr]  ; mov rax, addr │ ← NOSSO SHELLCODE!      │
│       │  FF E0         ; jmp rax       │                         │
│       └───────────────┬─────────────────┘                         │
│                       │                                            │
│                       ↓                                            │
│       ┌───────────────────────────────────────┐                   │
│       │    hook_handle(instructions)         │                   │
│       ├───────────────────────────────────────┤                   │
│       │                                       │                   │
│       │  if (req_base == TRUE)                │                   │
│       │  {                                    │                   │
│       │      1. PsLookupProcessByProcessId()  │                   │
│       │      2. get_module_base_x64()         │                   │
│       │         └─> Itera PEB/LDR do proc    │                   │
│       │         └─> Compara nome das DLLs     │                   │
│       │      3. instructions->base_adress = X │                   │
│       │      4. ObDereferenceObject(process)  │                   │
│       │  }                                    │                   │
│       │                                       │                   │
│       │  return STATUS_SUCCESS;               │                   │
│       └───────────────┬───────────────────────┘                   │
│                       │                                            │
└───────────────────────┼────────────────────────────────────────────┘
                        │
                        ↓ (retorna para usermode)
┌───────────────────────┼────────────────────────────────────────────┐
│                       │        APLICAÇÃO USERMODE                  │
│                       ▼                                            │
│                                                                    │
│  4. base = instructions.base_adress;  ← RECEBE O RESULTADO!       │
│     └─> 0x7FF612340000                                            │
│                                                                    │
│  5. int hp = Read<int>(base + 0x1234);  ← Usar o endereço!       │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

**Resumo:**
1. **Usermode** chama função hookada através de `win32u.dll`
2. **Win32u** faz syscall para o kernel (`dxgkrnl.sys`)
3. **Kernel** executa nosso shellcode (hook inline)
4. **hook_handle** processa a requisição
5. **Resultado** retorna para usermode através da estrutura `NULL_MEMORY`

---

**⚠️ AVISO IMPORTANTE:**
- Este projeto é apenas para **fins educacionais**
- Um erro no kernel pode causar **tela azul (BSOD)**

---

