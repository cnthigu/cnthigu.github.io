---
title: "Hook Assembly - Modificando Instruções em Memória com DLL Injection"
date: 2026-01-12 14:00:00 -0300
categories: [Segurança, Reverse Engineering]
tags: [assembly, hooking, dll-injection, reverse-engineering, x86, memory-patching, windows]
---

## Introdução

Este projeto demonstra conceitos fundamentais de **engenharia reversa** e **modificação de código em tempo de execução**. Através de uma DLL injetada, conseguimos alterar uma única instrução assembly para transformar completamente o comportamento de um programa.

> ⚠️ **Aviso**: Este conteúdo é **exclusivamente educacional**. Use apenas em ambientes controlados e para fins de aprendizado.

## O que o Projeto Faz?

Temos dois componentes principais:

1. **di06.exe** - Jogo simples que perde 10 de vida ao pressionar F1
2. **hookestudo06.dll** - DLL que modifica o código do jogo em runtime

### Comportamento

- **Sem a DLL**: Pressionar F1 diminui 10 pontos de vida
- **Com a DLL injetada**: Pressionar F1 **aumenta** 10 pontos de vida

Isso é alcançado modificando **apenas um único byte** na instrução assembly, transformando uma subtração (`sub`) em uma adição (`add`).

## Jogo Alvo (di06.exe)

### Código-Fonte

```cpp
#include <iostream>
#include <Windows.h>

using namespace std;

// Jogo simples para demonstração de hooking de instruções assembly
int main()
{
    int vida = 100;
    
    // Loop principal do jogo
    while (true)
    {
        // Detecta pressionamento da tecla F1
        if (GetAsyncKeyState(VK_F1) & 1)
        {
            if (vida > 0) 
            {
                // Esta linha compila para: "sub esi, 0Ah" (0x83 0xEE 0x0A)
                // Com a DLL injetada, a instrução é modificada para: "add esi, 0Ah" (0x83 0xC6 0x0A)
                // Resultado: ao invés de diminuir, a vida aumenta!
                vida -= 10;
                cout << "Vida: " << vida << endl;
            }
            else
            {
                cout << "Game Over" << endl;
            }
        }
    }
}
```

## Análise Assembly

### Instrução Original (Offset 0x102A)

```assembly
83 EE 0A        sub esi, 0Ah    ; Subtrai 10 (0x0A) de ESI
```

### Instrução Modificada

```assembly
83 C6 0A        add esi, 0Ah    ; Adiciona 10 (0x0A) a ESI
```

### Comparação dos Bytes

| Instrução | Byte 1 | Byte 2 | Byte 3 | Operação |
|-----------|--------|--------|--------|----------|
| Original  | `0x83` | `0xEE` | `0x0A` | `sub esi, 0Ah` |
| Modificada| `0x83` | `0xC6` | `0x0A` | `add esi, 0Ah` |

**Observação crucial:** Apenas o **segundo byte** muda: `0xEE` → `0xC6`

## Implementação da DLL

### Código Completo (dllmain.cpp)

```cpp
// dllmain.cpp : Ponto de entrada da DLL para hooking de instruções assembly
#include "pch.h"
#include <Windows.h>

// Função que instala o patch de memória no processo alvo
void InstallPatch()
{
    // Obtém o endereço base do módulo principal (executável que carregou esta DLL)
    DWORD base = (DWORD)GetModuleHandle(nullptr);
    
    // Calcula o endereço absoluto da instrução a ser modificada
    // Offset 0x102A: localização da instrução "sub esi, 0Ah" (vida -= 10)
    DWORD addr = base + 0x102A;

    // Altera a proteção de memória para permitir escrita na região de código
    // Necessário porque páginas de código normalmente são somente-leitura
    DWORD old;
    VirtualProtect((LPVOID)addr, 3, PAGE_EXECUTE_READWRITE, &old);

    // Bytes do patch: 0x83 0xC6 0x0A = "add esi, 0Ah"
    // Substitui "sub esi, 0Ah" (0x83 0xEE 0x0A) por "add esi, 0Ah"
    // Resultado: ao invés de perder 10 de vida, ganha 10 de vida
    BYTE patch[] = { 0x83, 0xC6, 0x0A };
    memcpy((void*)addr, patch, sizeof(patch));

    // Restaura a proteção original da memória (boa prática de segurança)
    VirtualProtect((LPVOID)addr, 3, old, &old);
}

// Ponto de entrada da DLL - chamado automaticamente pelo Windows ao carregar/descarregar
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // DLL foi carregada no processo (injetada)
        
        // Otimização: desabilita notificações de criação/destruição de threads
        DisableThreadLibraryCalls(hModule);
        
        // Cria uma nova thread para aplicar o patch
        // Evita bloquear o carregamento da DLL enquanto o patch é aplicado
        CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)InstallPatch, nullptr, 0, nullptr);
        break;
        
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        // Não precisamos fazer nada nestes casos para este exemplo
        break;
    }
    return TRUE;
}
```

## Técnicas e Conceitos Aplicados

### 1. VirtualProtect - Modificando Proteção de Memória

```cpp
VirtualProtect((LPVOID)addr, 3, PAGE_EXECUTE_READWRITE, &old);
```

**Por que é necessário?**
- Páginas de código executável são **somente-leitura** por padrão
- Isso impede que vírus e malware modifiquem código facilmente
- Precisamos alterar para `PAGE_EXECUTE_READWRITE` temporariamente
- **Boa prática**: Restaurar a proteção original após o patch

### 2. Cálculo de Endereço Base + Offset

```cpp
DWORD base = (DWORD)GetModuleHandle(nullptr);
DWORD addr = base + 0x102A;
```

**Como funciona?**
- `GetModuleHandle(nullptr)` retorna o endereço base do executável principal
- Somamos o **offset estático** encontrado durante análise
- Resultado: endereço absoluto da instrução em memória

**Importante:** O offset pode variar entre compilações diferentes!

### 3. DLL Injection

A DLL é injetada usando ferramentas externas como:
- **Process Hacker** (Plugin DLL Injector)
- **Xenos Injector**
- **Extreme Injector**
- Ou implementações customizadas usando `CreateRemoteThread`

### 4. DLL_PROCESS_ATTACH

```cpp
case DLL_PROCESS_ATTACH:
    DisableThreadLibraryCalls(hModule);
    CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)InstallPatch, nullptr, 0, nullptr);
    break;
```

**Fluxo:**
1. Windows carrega a DLL no processo
2. `DllMain` é chamado com `DLL_PROCESS_ATTACH`
3. `DisableThreadLibraryCalls` otimiza performance (não precisamos de notificações de threads)
4. `CreateThread` cria uma nova thread para aplicar o patch
5. A thread principal retorna imediatamente, evitando travar o carregamento

## Encontrando o Offset com Debugger

### Usando x64dbg / OllyDbg

1. **Abra o executável** no debugger
2. **Procure a string** "Vida: " ou a instrução `sub esi, 0Ah`
3. **Anote o endereço** da instrução (ex: `0x00401BODA`)
4. **Calcule o offset**: `endereço - base_address`
5. **Use o offset** na DLL

### Exemplo Prático

```
Endereço da instrução: 0x0040102A
Endereço base:         0x00400000
Offset:                0x0040102A - 0x00400000 = 0x102A
```

## Capturas de Tela

### Jogo em Execução

![Exemplo do Jogo](/assets/img/gameExemplo.png)

### Assembly Antes do Hook

Instrução original: `sub esi, 0Ah` (0x83 0xEE 0x0A)

![Assembly Antes do Hook](/assets/img/antesHook.png)

### Assembly Depois do Hook

Instrução modificada: `add esi, 0Ah` (0x83 0xC6 0x0A)

![Assembly Depois do Hook](/assets/img/aftherHook.png)

### Exemplo de DLL Hook em Ação

![Exemplo DLL Hook](/assets/img/exemplodllhook.png)

## Como Usar

### Compilação

1. Abra `hookestudo06.sln` no Visual Studio
2. Compile o projeto **di06** (Release ou Debug)
3. Compile o projeto **hookestudo06** como DLL

### Execução

1. **Execute `di06.exe`** normalmente
2. **Pressione F1** - vida diminui
3. **Injete `hookestudo06.dll`** usando um injetor
4. **Pressione F1** novamente - vida aumenta! 🎉

## Conceitos de Engenharia Reversa

### 1. Opcodes x86

| Opcode | Instrução | Descrição |
|--------|-----------|-----------|
| `83 EE imm8` | `sub esi, imm8` | Subtrai valor de 8 bits de ESI |
| `83 C6 imm8` | `add esi, imm8` | Adiciona valor de 8 bits a ESI |

### 2. Registradores

- **ESI** (Extended Source Index): Registrador de 32 bits usado para indexação
- Neste caso, armazena o valor da variável `vida`

### 3. Proteção de Memória no Windows

```
PAGE_NOACCESS             - Nenhum acesso
PAGE_READONLY             - Somente leitura
PAGE_READWRITE            - Leitura e escrita
PAGE_EXECUTE              - Somente execução
PAGE_EXECUTE_READ         - Execução e leitura (padrão para código)
PAGE_EXECUTE_READWRITE    - Execução, leitura e escrita (usamos para patch)
```

## Troubleshooting

### Problema 1: Hook Não Funciona

**Possíveis causas:**
- Offset incorreto (pode variar entre builds)
- ASLR (Address Space Layout Randomization) ativo
- Arquitetura incorreta (x86 vs x64)

**Solução:**
- Use um debugger para encontrar o offset correto
- Desabilite ASLR no Visual Studio (Linker → Advanced → Randomized Base Address → No)
- Certifique-se de que DLL e EXE são da mesma arquitetura

### Problema 2: Crash ao Injetar

**Possíveis causas:**
- Endereço inválido
- Proteção de memória não alterada corretamente
- Thread criada muito cedo

**Solução:**
- Valide o endereço com `IsBadReadPtr` antes de modificar
- Verifique o retorno de `VirtualProtect`
- Adicione `Sleep(100)` antes do patch se necessário

## Avisos Importantes

### ⚠️ Uso Educacional

- Este projeto é **apenas para aprendizado**
- Não use para modificar jogos online (viola ToS e pode resultar em ban)
- Não distribua cheats ou ferramentas de trapaça

### 🛡️ Antivírus

- DLL injectors são frequentemente detectados como malware
- Adicione exceções no antivírus para seu ambiente de desenvolvimento
- Use apenas em **máquinas virtuais** para testes

### 🔒 ASLR e DEP

- **ASLR** (Address Space Layout Randomization) pode alterar offsets
- **DEP** (Data Execution Prevention) pode bloquear modificações
- Para estudo, desabilite essas proteções no projeto

## Código Assembly Gerado pelo Compilador

### Correspondência C++ → Assembly

```cpp
vida -= 10;  // C++
```

**Compila para (x86):**

```assembly
mov    eax, DWORD PTR [vida]    ; Carrega valor de vida em EAX
sub    eax, 0Ah                  ; Subtrai 10
mov    DWORD PTR [vida], eax    ; Armazena de volta
```

**Ou otimizado (registrador):**

```assembly
sub    esi, 0Ah    ; vida está em ESI, subtrai direto
```

## Aprendizados e Conclusão

Este projeto demonstra conceitos fundamentais de:

### Assembly x86
- Entender opcodes e formato de instruções
- Diferença entre `sub` e `add`
- Uso de registradores como ESI

### Windows API
- `GetModuleHandle` - Obter base address
- `VirtualProtect` - Modificar proteção de páginas
- `DllMain` - Entry point de DLLs

### Engenharia Reversa
- Análise estática com debuggers
- Identificação de offsets
- Code patching em runtime

### Memory Management
- Proteção de páginas de memória
- Permissões (R/W/X)
- Importância de restaurar proteções

## Próximos Passos

Para expandir este projeto, você pode:

1. **Adicionar UI**: Interface gráfica para controlar o patch
2. **Hotkeys**: Ativar/desativar patch em runtime
3. **Múltiplos patches**: Modificar várias instruções
4. **Padrões de busca**: Encontrar instruções automaticamente (pattern scanning)
5. **Detour hooks**: Implementar hooks mais complexos com trampolines

## Referências e Recursos

### Documentação
- [Intel x86 Instruction Set Reference](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- [Windows API - VirtualProtect](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [PE Format Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)

### Ferramentas
- [x64dbg](https://x64dbg.com/) - Debugger open-source
- [Cheat Engine](https://www.cheatengine.org/) - Memory scanner e debugger
- [Process Hacker](https://processhacker.sourceforge.io/) - Monitor de processos

### Livros Recomendados
- "Practical Reverse Engineering" - Bruce Dang
- "The Art of Memory Forensics" - Michael Hale Ligh
- "Windows Internals" - Mark Russinovich

---

**Desenvolvido para fins educacionais** | Engenharia Reversa & Assembly x86

**Repositório:** Este projeto faz parte de meus estudos de engenharia reversa e está disponível no meu repositório privado para referência futura.
