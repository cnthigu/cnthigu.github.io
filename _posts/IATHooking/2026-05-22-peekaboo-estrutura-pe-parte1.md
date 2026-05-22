---
title: "Entendendo a estrutura PE do Windows (Parte 1)"
date: 2026-05-22 10:00:00 -0300
categories: [Segurança, Reverse Engineering]
tags: [iat-hooking, pe, windows, reverse-engineering, c++, hook, malware-analysis]
permalink: /estrutura-pe-parte1/
---

> **Aviso:** este post faz parte de uma série sobre **IAT Hooking** com fins
> puramente educacionais. As técnicas aqui descritas são as mesmas usadas
> por malware, mas também por ferramentas de segurança defensiva, EDRs,
> debuggers, ferramentas de análise e cheats de jogos antigos. Conhecimento
> técnico não é crime uso pra atacar sistemas que não são seus, é. Não
> faça isso.

Tô estudando IAT Hooking acompanhando um curso no YouTube, e decidi
transformar minhas anotações em posts pra fixar o conteúdo e ajudar quem
tiver começando agora. Essa é a **parte 1**, onde vou mapear toda a
estrutura de um executável PE do Windows base teórica obrigatória pra
qualquer coisa de hook, injeção, reverse engineering ou análise de
binários.

Na [**parte 2**](/iat-hooking-parte2/) a gente vai pra prática: construir uma DLL que faz hook
de uma função da Win32 API usando essa estrutura toda que vamos ver
agora.

## O que é PE?

PE (**Portable Executable**) é o formato dos arquivos `.exe`, `.dll`,
`.sys` e similares no Windows. É o equivalente ao ELF no Linux ou Mach-O
no macOS. Esse formato define como o binário tá organizado em disco e
como ele é mapeado pra memória quando o Windows carrega o programa.

Pra fazer hook de função importada (IAT hooking), a gente precisa
**navegar nessa estrutura na memória**, achar a tabela de imports, e
patchear o ponteiro da função que queremos interceptar. Pra navegar,
precisamos conhecer as structs que descrevem o layout.

## Onde estão definidas

Tudo que vou mostrar abaixo vive em `winnt.h`, que vem com o Windows SDK.
Se você incluir `<windows.h>` no seu código, todas essas structs já estão
disponíveis automaticamente.

Pra fins de estudo, vou copiar as definições aqui (igual fiz nas minhas
anotações originais) num arquivo `struct.h` separado mas no projeto
real basta o `#include <windows.h>`.

## 1. IMAGE_DOS_HEADER  o cabeçalho mais antigo

```cpp
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;        // Magic number
    WORD   e_cblp;         // Bytes on last page of file
    WORD   e_cp;           // Pages in file
    WORD   e_crlc;         // Relocations
    WORD   e_cparhdr;      // Size of header in paragraphs
    WORD   e_minalloc;     // Minimum extra paragraphs needed
    WORD   e_maxalloc;     // Maximum extra paragraphs needed
    WORD   e_ss;           // Initial (relative) SS value
    WORD   e_sp;           // Initial SP value
    WORD   e_csum;         // Checksum
    WORD   e_ip;           // Initial IP value
    WORD   e_cs;           // Initial (relative) CS value
    WORD   e_lfarlc;       // File address of relocation table
    WORD   e_ovno;         // Overlay number
    WORD   e_res[4];       // Reserved words
    WORD   e_oemid;        // OEM identifier
    WORD   e_oeminfo;      // OEM information
    WORD   e_res2[10];     // Reserved words
    LONG   e_lfanew;       // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```

Esse cabeçalho é uma herança do MS-DOS. Quando você executa um `.exe`
moderno num MS-DOS antigo, ele simplesmente imprime "This program cannot
be run in DOS mode" esse stub DOS vive aqui.

Pra nós, dois campos importam:

- **`e_magic`**  vale `0x5A4D` (em ASCII, `"MZ"`, iniciais de **Mark
  Zbikowski**, engenheiro da Microsoft que projetou o formato). Tem que
  ser igual a `IMAGE_DOS_SIGNATURE` pra você ter certeza que tá lidando
  com um PE válido.
- **`e_lfanew`**  o **offset** (a partir do início do arquivo) onde
  começa o cabeçalho NT, o que realmente importa pra gente. É a "ponte"
  entre o mundo DOS antigo e o PE moderno.

## 2. IMAGE_NT_HEADERS o cabeçalho NT (PE de verdade)

Existem duas versões dessa struct, uma pra 32 bits e outra pra 64 bits:

```cpp
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD                   Signature;
    IMAGE_FILE_HEADER       FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS {
    DWORD                   Signature;
    IMAGE_FILE_HEADER       FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
```

O `windows.h` automaticamente define `IMAGE_NT_HEADERS` como uma das
duas dependendo da arquitetura que você tá compilando.

Campos importantes:

- **`Signature`**  vale `0x00004550` (em ASCII, `"PE\0\0"`). Tem que
  bater com `IMAGE_NT_SIGNATURE`. Segunda verificação que fazemos pra
  garantir que é um PE válido.
- **`FileHeader`**  metadados gerais (arquitetura, número de seções,
  timestamp, etc).
- **`OptionalHeader`**  apesar do nome, **não é opcional** em
  executáveis. É onde mora a informação crítica.

## 3. IMAGE_FILE_HEADER  metadados do arquivo

```cpp
typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;               // Arquitetura (x86, x64, ARM...)
    WORD    NumberOfSections;      // Quantas seções tem (.text, .data, etc)
    DWORD   TimeDateStamp;         // Timestamp de compilação
    DWORD   PointerToSymbolTable;  // Tabela de símbolos (debug)
    DWORD   NumberOfSymbols;       // Quantidade de símbolos
    WORD    SizeOfOptionalHeader;  // Tamanho do OptionalHeader
    WORD    Characteristics;       // Flags (é DLL? Executável? etc)
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```

Aqui tem coisa útil pra análise forense  o `TimeDateStamp`, por
exemplo, fala quando o binário foi compilado (alguns malwares mexem
nesse campo pra esconder origens). `Characteristics` tem flags tipo
`IMAGE_FILE_DLL` que indicam se o binário é uma DLL ou um EXE.

Pro IAT hooking, esse cabeçalho não é o foco  a gente só atravessa ele
pra chegar no próximo.

## 4. IMAGE_OPTIONAL_HEADER  o coração da estrutura PE

```cpp
typedef struct _IMAGE_OPTIONAL_HEADER {
    // Standard fields
    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;

    // NT additional fields
    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
```

Struct gigante, eu sei. Vou destacar só o que importa pra nossa missão:

- **`AddressOfEntryPoint`**  RVA do primeiro código a ser executado
  quando o binário roda (no caso de DLL, é a `DllMain`).
- **`ImageBase`**  endereço base "preferido" onde o binário quer ser
  carregado em memória (com ASLR ativo, o Windows pode escolher outro).
- **`SizeOfImage`**  quantos bytes o binário ocupa em memória depois
  de carregado.
- **`DataDirectory[]`**  a parte mais importante pra nós. Array de 16
  ponteiros pra "diretórios" dentro do PE.

### O que é RVA?

**RVA** = **Relative Virtual Address** = endereço virtual relativo.

A ideia é: o PE não pode hardcodar endereços absolutos, porque o
Windows pode carregar ele em endereços diferentes a cada execução
(graças ao ASLR). Então o formato armazena **offsets relativos ao
endereço base** (`ImageBase`).

Pra converter RVA em endereço absoluto na memória:

```
endereço_absoluto = endereço_base_do_módulo + RVA
```

Exemplo: se o módulo foi carregado em `0x00007FF600000000` e a IAT está
no RVA `0x00026910`, então o endereço real da IAT na memória é
`0x00007FF600026910`.

![Diagrama mostrando como o RVA funciona cálculo do endereço absoluto a partir do ImageBase e do RVA](/assets/img/iat-hooking/rva_calculation_explanation.svg)

Esse cálculo é a operação mais comum quando você navega num PE em
memória. Você vai ver `pTarget + algumaCoisa.VirtualAddress` várias
vezes no código da parte 2 é exatamente isso.

### O que é o DataDirectory?

```cpp
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

Cada entrada do `DataDirectory[]` tem dois campos: o RVA onde aquele
diretório começa, e o tamanho dele em bytes. Os 16 diretórios são
indexados por constantes tipo:

- `IMAGE_DIRECTORY_ENTRY_EXPORT`  tabela de funções que o módulo
  **exporta** (usada pelo `GetProcAddress`).
- `IMAGE_DIRECTORY_ENTRY_IMPORT`  tabela de funções que o módulo
  **importa** de outros módulos. **É essa que vamos hookear.**
- `IMAGE_DIRECTORY_ENTRY_RESOURCE`  recursos embutidos (ícones,
  strings, etc).
- `IMAGE_DIRECTORY_ENTRY_BASERELOC` informação pra ASLR conseguir
  remapear o módulo em outro endereço.
- ... e mais alguns.

Pro IAT hooking, o que nos interessa é o índice `IMAGE_DIRECTORY_ENTRY_IMPORT`.

## 5. Visualizando tudo isso na prática  PE-bear

Antes de cair no código, recomendo muito instalar o
[**PE-bear**](https://github.com/hasherezade/pe-bear) e abrir um `.exe`
qualquer (no curso usei o `C:\Windows\System32\notepad.exe`).

Você consegue ver visualmente tudo que descrevi acima os cabeçalhos,
as seções, e principalmente a **tabela de imports**.

Na aba **Imports**, você vê todas as DLLs das quais o programa depende
(`KERNEL32.dll`, `USER32.dll`, etc), e dentro de cada uma, todas as
funções que ele importa daquela DLL. Pra cada função, tem:

- O **nome** (`CreateFileW`, `MessageBoxW`...)
- O **RVA da entrada na IAT**  esse é exatamente o ponteiro que vamos
  sobrescrever no hook.

![PE-bear aberto no notepad.exe, mostrando a aba Imports com todas as DLLs importadas (KERNEL32.dll, GDI32.dll, USER32.dll, etc)](/assets/img/iat-hooking/1-img-pe-imports-exempl.png)

Logo abaixo da lista de DLLs tem uma outra parte bem interessante: as
funções que cada DLL exporta pro programa, com seus respectivos
offsets. Selecionando `KERNEL32.dll`, dá pra ver todas as funções que o
notepad importa de lá `GetProcAddress`, `CreateFileW`, `ReadFile`,
etc com a coluna **Call via** mostrando o offset de cada uma.

![Zoom na tabela inferior do PE-bear destacando a coluna Call via com os offsets das funções de KERNEL32.dll](/assets/img/iat-hooking/2-offsets-import-pe-img.png)

Como pode ver na imagem acima, o `KERNEL32.dll` tem o endereço virtual
**call via 26910** pra chamar a função `CreateFileW`. Isso é o que nos
ajuda a acessar essa função enquanto ela está mapeada na memória.

Tem também o conceito de **thunk** que aparece no PE-bear: é o slot na
memória que o Windows preenche com o endereço real da função durante o
carregamento. Quando o programa chama `CreateFileW`, ele basicamente faz
algo como `call [endereço_do_thunk]`, e o thunk aponta pra função real
na `KERNEL32.dll`.

**A ideia do IAT hooking é simples:** sobrescrever o thunk com o
endereço da **nossa** função. Quando o programa pensa que tá chamando
`CreateFileW`, na real ele chama a nossa.

## 6. IMAGE_SECTION_HEADER  as seções do binário

```cpp
typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        DWORD   PhysicalAddress;
        DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

Logo depois do `IMAGE_NT_HEADERS` vem um array de `IMAGE_SECTION_HEADER`
 um pra cada seção do binário. Seções típicas:

- **`.text`**  código executável
- **`.data`**  dados inicializados (variáveis globais com valor)
- **`.rdata`** dados read-only (constantes, tabela de imports/exports)
- **`.bss`**  dados não inicializados
- **`.rsrc`** recursos

Cada seção tem suas próprias permissões (leitura/escrita/execução)
definidas em `Characteristics`. É por isso que a gente precisa do
`VirtualProtect` no hook: a página onde mora a IAT geralmente é
read-only, e precisamos liberar escrita temporariamente pra patchear.

Pra o nosso hook, não vamos manipular seções diretamente mas é
importante entender que elas existem e que cada uma tem suas regras de
proteção.

## Resumindo o mapa mental

Quando o Windows carrega um PE na memória, o layout fica mais ou menos
assim:

![Diagrama da estrutura PE na memória hierarquia completa do DOS header até as seções](/assets/img/iat-hooking/pe_structure_layout.svg)

A navegação pra chegar na tabela de imports é sempre essa:

1. Lê o `IMAGE_DOS_HEADER` no início do módulo
2. Soma `e_lfanew` ao base pra chegar no `IMAGE_NT_HEADERS`
3. Pega `OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]`
4. Soma o `VirtualAddress` desse diretório ao base pra chegar na IAT

Esse é exatamente o passo a passo que vamos implementar em código na
parte 2.

## Próximo passo

Na [**parte 2**](/iat-hooking-parte2/) vamos colocar tudo isso em prática:

1. Criar uma DLL
2. Implementar a função `HookIAT` que navega na estrutura PE
3. Patchear o ponteiro de uma função (`MessageBoxW`) com a nossa
4. Carregar essa DLL num executável e ver o hook acontecendo ao vivo

Até lá, recomendo brincar com o PE-bear, abrir alguns `.exe` e
identificar visualmente cada um dos cabeçalhos que vimos aqui. Ajuda
muito a fixar.

---

*Esse post faz parte da série, minhas anotações de estudo
sobre IAT Hooking. Se achou algum erro ou tem sugestão, manda aí.*
