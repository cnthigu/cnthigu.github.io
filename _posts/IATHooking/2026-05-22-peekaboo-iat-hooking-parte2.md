---
title: "Implementando IAT Hooking na prática (Parte 2)"
date: 2026-05-22 11:00:00 -0300
categories: [Segurança, Reverse Engineering]
tags: [iat-hooking, pe, windows, reverse-engineering, c++, hook, dll-injection, malware-analysis]
permalink: /iat-hooking-parte2/
---

> **Aviso:** este post tem fins puramente educacionais. IAT Hooking é
> uma técnica usada tanto por malware quanto por ferramentas legítimas
> (EDRs, debuggers, ferramentas de análise, software de compatibilidade).
> O que importa é entender como funciona  usar pra atacar sistemas que
> não são seus é crime. Bom senso sempre.

Na [parte 1](/estrutura-pe-parte1/) a gente mapeou toda a estrutura PE do Windows e entendeu
onde mora a tabela de imports. Agora bora pra prática: construir uma
DLL que, quando carregada num processo, **intercepta chamadas** a uma
função da Win32 API.

A função escolhida pra esse tutorial é a `MessageBoxW` porque o
resultado é visualmente óbvio: quando o hook funciona, o usuário vê uma
caixa de diálogo diferente da que o programa pediu pra mostrar.

## O plano

Vamos construir uma solução com dois projetos:

1. **DLL do hook**  contém toda a lógica de interceptação
2. **EXE vítima**  um programa simples que carrega a DLL e chama
   `MessageBoxW` pra a gente ver o hook em ação

Estrutura final:

```
iatHook.sln
├── dll/                  ← projeto que gera a DLL
│   ├── DllMain.cpp       ← ponto de entrada da DLL
│   ├── hook.cpp/.h       ← orquestra os hooks
│   ├── IATHook.cpp/.h    ← lógica de IAT hooking
│   ├── GetModuleHandle.cpp/.h    ← reimplementação sem usar a Win32
│   ├── GetProcAddress.cpp/.h     ← idem
│   └── util.cpp/.h       ← helpers (comparação de strings, etc)
│
└── iatHook/              ← projeto EXE "vítima"
    └── main.cpp          ← carrega a DLL e chama MessageBoxW
```

## Por que reimplementar GetModuleHandle e GetProcAddress?

Boa pergunta. A resposta curta: porque é educativo, e porque na prática
real (malware, EDR bypass, análise) você não quer depender dessas
funções da Win32 que ficam visíveis na sua própria IAT (e que podem
estar hookeadas por outros caras).

A resposta longa fica pra outro post por enquanto, basta saber que
vamos navegar diretamente no **PEB** (Process Environment Block) pra
achar DLLs carregadas, e parsear a **Export Directory** pra resolver
funções por nome. Tudo manualmente.

## 1. Criando a DLL

No Visual Studio, dentro da mesma solution, adiciona um novo projeto do
tipo **Dynamic-Link Library (DLL)**. O Visual Studio gera um esqueleto
com a função `DllMain` que é o ponto de entrada da DLL, equivalente à
`main` de um EXE.

A `DllMain` é chamada em quatro momentos diferentes pelo Windows. O que
nos interessa é o `DLL_PROCESS_ATTACH`, que dispara assim que a DLL é
carregada no processo:

```cpp
// DllMain.cpp
#include <windows.h>
#include "hook.h"
#include "util.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        EnableDebugConsole();   // abre uma janela de console pra ver os prints
        RunHook();              // dispara nossa lógica de hook
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

O `EnableDebugConsole` aloca uma janela de console nova quando a DLL é
carregada sem isso, os `printf` que o hook faz não apareceriam em
lugar nenhum (DLL não herda console do EXE em todos os casos). A
implementação dele tá no `util.cpp`:

```cpp
// util.cpp
#include "util.h"
#include <stdio.h>

void EnableDebugConsole()
{
    if (AllocConsole())
    {
        FILE* fpstdout;
        FILE* fpstderr;
        FILE* fpstdin;
        freopen_s(&fpstdout, "CONOUT$", "w", stdout);
        freopen_s(&fpstderr, "CONOUT$", "w", stderr);
        freopen_s(&fpstdin,  "CONIN$",  "r", stdin);
    }
}

int IsEqualCStr(const char* a, const char* b)
{
    if (!a || !b)
        return 0;
    return _stricmp(a, b) == 0;
}
```

Aproveitei pra mostrar a `IsEqualCStr` aqui também é a função que o
`HookIAT` usa pra comparar nomes de módulos. Usei `_stricmp`
(case-**insensitive**) de propósito: na IAT o nome geralmente vem como
`"KERNEL32.dll"` (maiúsculas), e a gente quer que `"kernel32.dll"`
também case. Vai poupar uma hora de debug.

## 2. A função HookIAT a estrela do show

Essa é a função que faz o trabalho pesado: navega na estrutura PE do
módulo alvo, acha a tabela de imports, localiza o módulo (`USER32.dll`)
e a função (`MessageBoxW`), e chama uma função auxiliar pra patchear o
ponteiro.

![Diagrama mostrando o estado da IAT antes e depois do hook como o ponteiro é desviado pra função substituta](/assets/img/iat-hooking/iat_hook_before_after.svg)

Os parâmetros são:

- **`pTarget`**  endereço base do módulo cuja IAT queremos patchear
  (geralmente nosso próprio EXE)
- **`lpModuleName`**  nome da DLL de origem da função
  (ex: `"USER32.dll"`)
- **`lpApiName`**  nome da função (ex: `"MessageBoxW"`)
- **`replacement`**  ponteiro pra nossa função substituta

E o retorno é o endereço **original** da função  assim a gente pode
chamar a função real lá dentro do nosso hook.

```cpp
// IATHook.cpp
#include "IAThook.h"
#include "util.h"
#include <string.h>

PVOID HookIAT(PBYTE pTarget, LPCSTR lpModuleName, LPCSTR lpApiName, LPCVOID replacement)
{
    // Passo 1: valida o DOS header
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pTarget;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    // Passo 2: salta pro NT header usando e_lfanew e valida
    PIMAGE_NT_HEADERS pImgNtHdrs =
        (PIMAGE_NT_HEADERS)(pTarget + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    // Passo 3: pega o data directory de imports
    IMAGE_OPTIONAL_HEADER ImgOpHdr = pImgNtHdrs->OptionalHeader;
    IMAGE_DATA_DIRECTORY impDataDir =
        ImgOpHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    // Passo 4: chega na tabela de imports somando o RVA ao base
    PIMAGE_IMPORT_DESCRIPTOR pImportAddressTable =
        (PIMAGE_IMPORT_DESCRIPTOR)(pTarget + impDataDir.VirtualAddress);

    SIZE_T iatSize = impDataDir.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);

    // Passo 5: itera pelos módulos importados
    for (SIZE_T i = 0; i < iatSize; i++)
    {
        // último descriptor é zerado, marca o fim
        if (pImportAddressTable[i].Name == 0)
            break;

        char* pModuleName = (char*)(pTarget + pImportAddressTable[i].Name);

        if (IsEqualCStr(lpModuleName, pModuleName))
        {
            // Achou o módulo. Agora procura a função dentro dele.
            PVOID original = PatchIATEntry(
                pTarget,
                lpApiName,
                &pImportAddressTable[i],
                replacement);

            if (original != NULL)
                return original;
        }
    }

    return NULL;
}
```

A lógica espelha o mapa mental da parte 1:

1. Valida que tá lidando com um PE real (`MZ` + `PE\0\0`)
2. Pula pro NT header via `e_lfanew`
3. Pega o RVA da tabela de imports do `DataDirectory`
4. Soma ao base pra ter o endereço absoluto da tabela
5. Itera pelos módulos até achar o que queremos
6. Chama `PatchIATEntry` pra fazer a troca propriamente dita

## 3. A função PatchIATEntry  onde a mágica acontece

Cada `IMAGE_IMPORT_DESCRIPTOR` tem dois campos importantes:

- **`OriginalFirstThunk`**  RVA pra um array de "hint/name" entries.
  Esses entries têm os **nomes** das funções importadas. Esse array
  geralmente **não é modificado** pelo loader.
- **`FirstThunk`**  RVA pra um array paralelo do mesmo tamanho. Esse é
  o que o loader **preenche com os endereços reais** durante o
  carregamento. **É esse que vamos patchear.**

A ideia: iteramos pelos dois arrays em paralelo. No `OriginalFirstThunk`
conseguimos ler o nome da função; quando o nome bate com o que
procuramos, sobrescrevemos a entrada correspondente no `FirstThunk` com
nosso ponteiro.

```cpp
PVOID PatchIATEntry(PBYTE pTarget, PCSTR lpApiName,
                    PIMAGE_IMPORT_DESCRIPTOR pModuleEntry, LPCVOID replacement)
{
    PULONG_PTR originalThunk = (PULONG_PTR)(pTarget + pModuleEntry->OriginalFirstThunk);
    PULONG_PTR thunk         = (PULONG_PTR)(pTarget + pModuleEntry->FirstThunk);

    while (*originalThunk != NULL)
    {
        // Pula imports por ordinal (sem nome pra comparar)
        if (IMAGE_SNAP_BY_ORDINAL(*originalThunk))
        {
            originalThunk++;
            thunk++;
            continue;
        }

        PIMAGE_IMPORT_BY_NAME importByName =
            (PIMAGE_IMPORT_BY_NAME)(pTarget + *originalThunk);

        if (strcmp(importByName->Name, lpApiName) == 0)
        {
            // Achou. Guarda o original antes de sobrescrever.
            PVOID original = (PVOID)(*thunk);

            // Libera escrita na página, patcheia, restaura proteção
            DWORD protect = 0;
            VirtualProtect(thunk, sizeof(ULONG_PTR), PAGE_READWRITE, &protect);
            *thunk = (ULONG_PTR)replacement;
            VirtualProtect(thunk, sizeof(ULONG_PTR), protect, &protect);

            return original;
        }

        originalThunk++;
        thunk++;
    }

    return NULL;
}
```

Dois pontos importantes:

**Imports por ordinal vs por nome.** Algumas funções são importadas por
número (ordinal) em vez de por nome. Quando isso acontece, o bit mais
alto de `*originalThunk` fica setado. A macro `IMAGE_SNAP_BY_ORDINAL`
testa isso. Tratar uma entrada por ordinal como se fosse `IMAGE_IMPORT_BY_NAME`
leva a um crash garantido por isso o `continue`.

**`VirtualProtect`.** A página onde mora a IAT geralmente é read-only
(é parte da seção `.rdata`). Tentar escrever direto causa exceção de
proteção. A gente libera escrita temporariamente, patcheia, e restaura
a proteção original.

## 4. A função hook propriamente dita

Agora a parte criativa: escrever uma função que tem **exatamente a
mesma assinatura** da `MessageBoxW` original. Como o objetivo desse
tutorial é demonstrar visualmente que o hook funciona, nossa função
substituta vai **trocar o texto** antes de chamar a real o EXE pede
uma mensagem, o usuário vê outra.

```cpp
// hook.cpp
#include "hook.h"
#include "GetModuleHandle.h"
#include "GetProcAddress.h"
#include "IATHook.h"
#include <stdio.h>

// Typedef com a assinatura idêntica à MessageBoxW da Win32
typedef int (WINAPI* MessageBoxW_T)(HWND, LPCWSTR, LPCWSTR, UINT);

// Ponteiro pra função original (guardado depois do patch)
MessageBoxW_T MessageBoxWOriginal = NULL;

// Nossa função substituta mesma assinatura da MessageBoxW
int WINAPI MessageBoxWHook(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
    // Modifica o texto e título antes de chamar a original.
    // Repara que propago uType assim o EXE continua escolhendo
    // o tipo de dialog (MB_OK, MB_YESNO, ícones, etc).
    int result = MessageBoxWOriginal(
        hWnd,
        L"Texto MODIFICADO pelo hook! :)",
        L"Hooked!",
        uType);

    if (result == 0)
        printf("[-] original retornou 0 (GetLastError=%lu)\n", GetLastError());
    else
        printf("[+] original retornou: %d\n", result);

    return result;
}
```

Pontos importantes da assinatura:

- **`WINAPI`** corresponde a `__stdcall`, a calling convention da
  Win32. Se você esquecer disso, o stack vai pro espaço depois da
  chamada e o programa crasha.
- **Tipo de retorno e parâmetros idênticos.** Qualquer divergência aqui
  vira crash ou comportamento errado.
- **Propagar `uType`.** Mesmo modificando o texto, vale a pena passar
  o `uType` que o chamador escolheu assim o tipo de diálogo (OK,
  YES/NO, ícone, etc) continua coerente com o que o EXE pediu.

## 5. Orquestrando tudo: a função RunHook

Essa é chamada lá pela `DllMain`:

```cpp
void RunHook()
{
    printf("[+] Obtendo base address do modulo alvo (proprio .exe)...\n");
    PBYTE pTarget = (PBYTE)GetModuleHandleReplacement(NULL);
    printf("[+] base address = %p\n", pTarget);

    MessageBoxWOriginal = (MessageBoxW_T)HookIAT(
        pTarget,
        "USER32.dll",
        "MessageBoxW",
        MessageBoxWHook);

    if (MessageBoxWOriginal == NULL)
    {
        printf("[-] [FALHA] nao foi possivel hookar MessageBoxW\n");
    }
    else
    {
        printf("[+] [OK] hook aplicado com sucesso\n");
        printf("[+] endereco original guardado: %p\n", MessageBoxWOriginal);
    }
}
```

`GetModuleHandleReplacement(NULL)` retorna o base address do **próprio
processo** (equivalente a `GetModuleHandle(NULL)`). É o EXE que carregou
nossa DLL e é a IAT desse EXE que vamos patchear. Mas como a gente
implementa essa função? E o `GetProcAdressReplacement`? Bora ver.

## 6. GetModuleHandleReplacement achando DLLs via PEB

Em vez de chamar a `GetModuleHandle` da Win32, a gente vai direto na
fonte: o **PEB** (Process Environment Block). É uma estrutura que o
Windows mantém pra cada processo, e dentro dela tem uma lista
duplamente encadeada com **todas as DLLs carregadas** incluindo o
próprio EXE.

O acesso ao PEB é via registrador:

- Em x64: `gs:[0x60]`
- Em x86: `fs:[0x30]`

A gente lê esse registrador, navega pelo campo `Ldr →
InMemoryOrderModuleList`, e itera pelos módulos comparando o nome.
Quando bate, retorna o `DllBase`.

```cpp
// GetModuleHandle.h
#pragma once
#include <windows.h>
#include <winternl.h>
#include "util.h"

HMODULE GetModuleHandleReplacement(IN LPCSTR szModuleName);
```

```cpp
// GetModuleHandle.cpp
#include "GetModuleHandle.h"

// Compara UNICODE_STRING (wide) com LPCSTR (ANSI), case-insensitive
static BOOL IsModuleNameEqual(LPCSTR ansiName, PUNICODE_STRING wideName)
{
    if (!ansiName || !wideName || !wideName->Buffer)
        return FALSE;

    USHORT wideLen = wideName->Length / sizeof(WCHAR);
    USHORT i = 0;

    for (; i < wideLen && ansiName[i] != '\0'; i++)
    {
        WCHAR wc = wideName->Buffer[i];
        CHAR  ac = ansiName[i];

        // lowercase ASCII (suficiente pra nomes de DLL)
        if (wc >= L'A' && wc <= L'Z') wc += 32;
        if (ac >= 'A'  && ac <= 'Z')  ac += 32;

        if ((WCHAR)ac != wc)
            return FALSE;
    }

    return (i == wideLen && ansiName[i] == '\0');
}

HMODULE GetModuleHandleReplacement(IN LPCSTR szModuleName)
{
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    PLIST_ENTRY pHead = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY pCurrent = pHead->Flink;

    while (pCurrent != pHead)
    {
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(
            pCurrent,
            LDR_DATA_TABLE_ENTRY,
            InMemoryOrderLinks);

        // GetModuleHandle(NULL) → retorna handle do próprio .exe
        // (primeiro módulo da lista)
        if (szModuleName == NULL)
            return (HMODULE)pEntry->DllBase;

        // Reserved4 do winternl.h é onde mora o BaseDllName na realidade
        if (IsModuleNameEqual(szModuleName, (PUNICODE_STRING)&pEntry->Reserved4))
        {
            return (HMODULE)pEntry->DllBase;
        }

        pCurrent = pCurrent->Flink;
    }

    return NULL;
}
```

**Detalhe chato sobre o `winternl.h`.** A versão pública do
`LDR_DATA_TABLE_ENTRY` que vem nesse header tem vários campos como
`Reserved1`, `Reserved2`, `Reserved4`, etc. O `BaseDllName` (que é o
que queremos) mora no offset onde a Microsoft declarou `Reserved4`. Por
isso o cast meio feio: `(PUNICODE_STRING)&pEntry->Reserved4`. Funciona
porque o offset é estável há décadas, mas se tiver que escolher entre
elegância e estabilidade do ABI, eu redefiniria a struct toda no meu
header (já vi muito malware fazer assim). Pra esse tutorial, fica como
tá.

**`CONTAINING_RECORD`** é uma macro do Windows que faz aquele truque
de "dado um ponteiro pra um campo dentro de uma struct, me retorna o
ponteiro pro início da struct". Como a `InMemoryOrderModuleList.Flink`
aponta pro **campo** `InMemoryOrderLinks` no meio do
`LDR_DATA_TABLE_ENTRY`, a gente usa essa macro pra "voltar" pro início
da struct.

## 7. GetProcAdressReplacement resolvendo funções via Export Directory

A `GetProcAddress` da Win32 recebe um handle de módulo + nome de
função e devolve o endereço da função. A gente faz o mesmo lendo a
**Export Directory** do PE outro `DataDirectory`, o de índice 0
(`IMAGE_DIRECTORY_ENTRY_EXPORT`).

A Export Directory contém três arrays paralelos:

- `AddressOfFunctions`  RVAs das funções (indexado por ordinal - base)
- `AddressOfNames`  RVAs dos nomes (ordenados alfabeticamente)
- `AddressOfNameOrdinals`  ordinais correspondentes aos nomes

A busca por nome funciona assim: percorre o `AddressOfNames` até achar
o nome desejado; pega o índice; usa esse índice no
`AddressOfNameOrdinals` pra descobrir qual entrada do
`AddressOfFunctions` corresponde àquele nome.

```cpp
// GetProcAddress.h
#pragma once
#include <windows.h>

FARPROC GetProcAdressReplacement(IN HMODULE hModule, IN LPCSTR lpApiName);
```

```cpp
// GetProcAddress.cpp
#include "GetProcAddress.h"

FARPROC GetProcAdressReplacement(IN HMODULE hModule, IN LPCSTR lpApiName)
{
    PBYTE pBase = (PBYTE)hModule;

    // Valida headers (mesma navegação do HookIAT)
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS pImgNtHdrs =
        (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    IMAGE_OPTIONAL_HEADER ImgOpHdr = pImgNtHdrs->OptionalHeader;

    // Dessa vez pegamos EXPORT em vez de IMPORT
    IMAGE_DATA_DIRECTORY exportDataDir =
        ImgOpHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    PIMAGE_EXPORT_DIRECTORY pImgExportDir =
        (PIMAGE_EXPORT_DIRECTORY)(pBase + exportDataDir.VirtualAddress);

    PDWORD FunctionAddressArray =
        (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);

    PVOID pFunctionAddress = NULL;

    // Busca por ordinal (quando lpApiName cabe em 16 bits  é um número)
    if ((ULONG_PTR)lpApiName <= 0xFFFF)
    {
        WORD ordinal = (WORD)((ULONG_PTR)lpApiName & 0xFFFF);
        DWORD base = pImgExportDir->Base;

        if (ordinal < base || ordinal >= base + pImgExportDir->NumberOfFunctions)
            return NULL;

        pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[ordinal - base]);
    }
    // Busca por nome
    else
    {
        PDWORD FunctionNameArray    = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
        PWORD  FunctionOrdinalArray = (PWORD) (pBase + pImgExportDir->AddressOfNameOrdinals);

        for (DWORD i = 0; i < pImgExportDir->NumberOfNames; i++)
        {
            CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
            if (strcmp(lpApiName, pFunctionName) == 0)
            {
                pFunctionAddress =
                    (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);
                break;
            }
        }
    }

    return (FARPROC)pFunctionAddress;
}
```

**Trick do "passa o ordinal como ponteiro".** A `GetProcAddress` real
aceita o nome da função como string, **ou** um ordinal disfarçado de
ponteiro. Se você passar `(LPCSTR)5`, ela entende que você quer a
função de ordinal 5. A gente replica isso checando se
`(ULONG_PTR)lpApiName <= 0xFFFF` se for um número pequeno, é
ordinal; senão, é ponteiro pra string.

**Por que `PWORD` no `FunctionOrdinalArray`?** O array
`AddressOfNameOrdinals` tem entradas de **16 bits** (`WORD`), não 32.
Se você declarar como `PDWORD` (32 bits), a aritmética de ponteiro vai
calcular offsets errados e você pega função errada ou crasha lendo
fora dos limites. Esse foi um bug que pegou bastante gente no curso
que tô estudando.

**E essa função é usada onde?** No nosso código atual, ela está
disponível mas o `HookIAT` não chama. Ela existe pra completar o
conjunto se você quisesse construir uma versão do hook que **resolve
a função por nome em vez de patchear via IAT**, ou pra implementar um
inline hook, essa função seria essencial. Tô deixando ela pronta pros
próximos posts.

## 8. O EXE vítima

Agora o segundo projeto. Cria um projeto do tipo **Console Application
(.exe)** na mesma solution. O `main.cpp` carrega nossa DLL e chama
`MessageBoxW`:

```cpp
// main.cpp do projeto
#include <windows.h>
#include <stdio.h>

int main()
{
    printf("[+] Carregando a DLL de hook...\n");

    HMODULE hDll = LoadLibraryA("dll.dll");
    if (!hDll)
    {
        printf("[-] Falha ao carregar DLL. GetLastError = %lu\n", GetLastError());
        return 1;
    }

    printf("[+] DLL carregada. Chamando MessageBoxW...\n");

    int result = MessageBoxW(
        NULL,
        L"Texto original da mensagem",
        L"Titulo original",
        MB_OK | MB_ICONINFORMATION);

    printf("[+] MessageBoxW retornou: %d\n", result);

    FreeLibrary(hDll);
    return 0;
}
```

**A ordem importa:** primeiro carregamos a DLL (que patcheia a IAT),
**depois** chamamos `MessageBoxW`. Se chamássemos antes, a chamada
passaria direto pra função real sem ser interceptada.

## 9. Configurações importantes do Visual Studio

Antes de rodar, tem algumas coisas pra ajustar:

**Tipo de configuração de cada projeto:**

- Projeto `dll` → **Configuration Properties → General → Configuration
  Type → Dynamic Library (.dll)**
- Projeto `iatHook` → **Configuration Type → Application (.exe)**

**Output compartilhado.** Os dois projetos precisam gerar o `.dll` e o
`.exe` na mesma pasta (senão o `LoadLibraryA` não acha a DLL). Em ambos
os projetos, em **General → Output Directory**, coloca:

```
$(SolutionDir)$(Platform)\$(Configuration)\
```

**Dependência de build.** No projeto `iatHook`, **botão direito →
Build Dependencies → Project Dependencies** e marca `dll`. Isso garante
que a DLL é compilada antes do EXE.

## 10. Hora da verdade rodando

Build da solution, abre um cmd na pasta do EXE, roda. Saída esperada
no console (aquele que o `EnableDebugConsole` criou):

```
[+] Carregando a DLL de hook...
[+] Obtendo base address do modulo alvo (proprio .exe)...
[+] base address = 00007FF72B1A0000
[+] [OK] hook aplicado com sucesso
[+] endereco original guardado: 00007FFFEB9E91F0
[+] DLL carregada. Chamando MessageBoxW...
```

Aqui o Windows vai mostrar a caixa de diálogo. Mas repara: o EXE pediu
pra mostrar "Texto original da mensagem" / "Titulo original", e o que
aparece na tela é **"Texto MODIFICADO pelo hook! :)"** com título
**"Hooked!"**. Essa é a demonstração mais visual possível de que o hook
tá no controle da chamada.

Você clica OK e o fluxo continua:

```
[+] original retornou: 1
[+] MessageBoxW retornou: 1
```

O `1` é o `IDOK` retorno padrão da `MessageBoxW` quando o usuário
clica OK. Repara que esse valor passou direto pelo nosso hook e voltou
pro `main` como se nada tivesse acontecido. Do ponto de vista do EXE,
ele chamou `MessageBoxW` e recebeu uma resposta normal. Mas a gente teve
acesso completo aos parâmetros no meio do caminho e os modificou.

![Diagrama do fluxo completo da chamada hookeada sequência EXE → IAT → Hook → função real → retorno](/assets/img/iat-hooking/hooked_call_flow_sequence.svg)

## 11. Outras coisas que dá pra fazer com o hook

Modificar o texto é o exemplo mais didático, mas o hook pode fazer
muito mais:

**Bloquear a chamada inteiramente:**

```cpp
int WINAPI MessageBoxWHook(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
    printf("[HOOK] Chamada bloqueada!\n");
    return IDCANCEL;  // finge que o usuário cancelou
}
```

**Filtrar baseado nos parâmetros:**

```cpp
if (wcsstr(lpText, L"senha") != NULL)
{
    printf("[HOOK] Palavra sensivel detectada, bloqueando\n");
    return IDCANCEL;
}
return MessageBoxWOriginal(hWnd, lpText, lpCaption, uType);
```

**Telemetria silenciosa.** Só logar os parâmetros e chamar a original
sem alterar nada. Útil pra análise de comportamento de programas
fechados você descobre tudo que o programa tá fazendo sem interferir.

## Limitações do IAT hooking

Vale registrar pra ficar honesto:

1. **Só pega chamadas via tabela de imports.** Se o programa resolve a
   função em runtime via `GetProcAddress`, ele pega o endereço direto da
   `USER32.dll` e nossa IAT patcheada não é consultada.
2. **Funciona só no módulo cuja IAT você patcheou.** Se quiser cobrir
   o processo inteiro, precisa patchear a IAT de cada DLL carregada.
3. **Detectável.** Verificar se um ponteiro da IAT aponta pra fora do
   módulo esperado é trivial. EDRs fazem isso.

Pra contornar (1) e (2), a técnica mais usada é **inline hooking**
sobrescrever os primeiros bytes da função em si com um `jmp` pro hook.
É o que bibliotecas tipo Microsoft Detours, MinHook e EasyHook fazem.
Fica pra outro post.

## Conclusão

Em duas partes a gente saiu do "não sei o que é um PE" e chegou num
hook funcional que intercepta chamadas da Win32 API. Tudo isso sem
bibliotecas externas só Windows SDK e entendimento da estrutura PE.

O que mais me marcou nesse estudo: **não tem mágica**. É só código,
ponteiros, e leitura de structs. Quando você entende o formato, o que
parecia ficção de filme de hacker vira engenharia normal.

Espero que ajude alguém. Se achou erro ou tem sugestão, comenta aí.

---

*Esse post faz parte da série IATHook, minhas anotações de estudo
sobre IAT Hooking. Código completo no meu repositório (link em
breve).*
