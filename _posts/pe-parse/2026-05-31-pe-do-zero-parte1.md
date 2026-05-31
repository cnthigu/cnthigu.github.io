---
title: "PE do zero: navegando pelos headers (Parte 1)"
date: 2026-05-31 10:00:00 -0300
categories: [Segurança, Reverse Engineering]
tags: [pe, windows, reverse-engineering, c++, pe-parsing, cff-explorer]
permalink: /pe-do-zero-parte1/
---

> **Aviso:** este post tem fins puramente educacionais. Entender a estrutura
> PE é conhecimento base pra qualquer coisa de reverse engineering, análise
> de malware, hooking e desenvolvimento de ferramentas de segurança. O mesmo
> conhecimento aplicado aqui é o que malware usa. A diferença é a intenção.
> Não ataque sistemas que não são seus.

Tava estudando IAT Hooking e em algum momento percebi que não entendia
direito o que estava fazendo. Sabia que tinha que navegar pelo PE pra
chegar na Import Table, mas não entendia o caminho de verdade. Resolvi
parar e estudar a estrutura do PE do zero, com calma, campo por campo.

Esse post é meu caderno de anotações desse estudo. Diferente da
[série IAT Hooking](/estrutura-pe-parte1/) que é mais referência, aqui a
ideia é ir abrindo o CFF Explorer, apontar pra cada campo, e escrever o
código que acessa aquele valor em tempo real. Aprender fazendo.

Essa é a **Parte 1**, onde a gente percorre toda a cadeia de headers: DOS
Header, NT Headers, FileHeader, Sections e DataDirectory. Na
[**Parte 2**](/pe-do-zero-parte2/) a gente usa esse mapa pra converter RVA
em offset real e finalmente chegar na Import Table de verdade, lendo os
nomes de cada DLL e função importada.

## Ferramenta que vou usar

Recomendo baixar o **CFF Explorer** da NTCore pra acompanhar. É gratuito
e tem uma view visual de tudo que vamos ver no código.

[Download: https://ntcore.com/explorer-suite/](https://ntcore.com/explorer-suite/)

Como cobaia eu vou usar o notepad.exe mesmo:

```
C:\Windows\System32\notepad.exe
```

Simples, acessível em qualquer Windows, e tem tudo que a gente precisa
pra estudar.

## 1. DOS Header: o começo de tudo

Primeira coisa: abre o `notepad.exe` no CFF Explorer e clica em
**Dos Header**.

![CFF Explorer mostrando todos os campos do DOS Header do notepad.exe, com e_magic=5A4D e e_lfanew=100](/assets/img/pe-do-zero/01-cff-dos-header.png)

Tem uma lista enorme de campos ali, mas de início só dois importam:

**`e_magic`**: vale `0x5A4D`, que em ASCII é `"MZ"`. São as iniciais de
**Mark Zbikowski**, o engenheiro da Microsoft que projetou o formato
executável do MS-DOS nos anos 80. Todo arquivo PE válido começa com esse
valor. É a primeira coisa que qualquer parser verifica pra confirmar que
está lidando com um executável Windows de verdade.

**`e_lfanew`**: esse campo guarda o **offset** de onde começa o cabeçalho
NT, em bytes a partir do início do arquivo. No notepad vale `0x100`. Pensa
nele como uma ponte: o DOS Header está ali só por compatibilidade histórica,
mas ele aponta pra onde o PE de verdade começa. Sem ele não teria como
saber onde pular.

Vamos acessar esses dois valores no código:

```cpp
HMODULE proc = GetModuleHandle(NULL); // base address do processo atual

PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)proc;

cout << "Magic: 0x"    << hex << dos->e_magic  << endl;
cout << "e_lfanew: 0x" << hex << dos->e_lfanew << endl;
```

`GetModuleHandle(NULL)` retorna o endereço base do módulo atual, que é
o `.exe` que está rodando. A gente faz um cast pra `PIMAGE_DOS_HEADER`
porque o executável começa exatamente com essa struct, então o ponteiro
já aponta pro lugar certo desde o início.

![Console mostrando Magic: 0x5a4d e e_lfanew: 0x100](/assets/img/pe-do-zero/02-console-magic-lfanew.png)

Bate exatamente com o que o CFF Explorer mostrou.

Uma observação importante aqui: o `GetModuleHandle(NULL)` retorna o base
address do **meu próprio exe**, o que compilei e estou rodando. Nao do
notepad. O CFF Explorer com o notepad aberto é só pra ter uma referência
visual dos campos, entender o que cada um representa. Por isso os valores
no console podem ser diferentes dos que aparecem no CFF, sao binários
diferentes rodando.

![Diagrama da estrutura PE mostrando o DOS Header com os campos e_magic e e_lfanew](/assets/img/pe-do-zero/svg-01-dos-header.svg)

## 2. NT Headers: a assinatura PE

Agora que tenho o `e_lfanew`, posso pular pra próxima camada. Clica em
**Nt Headers** no CFF Explorer:

![CFF Explorer mostrando o NT Headers com o campo Signature igual a 00004550](/assets/img/pe-do-zero/03-cff-nt-signature.png)

Só um campo visível aqui: **`Signature`** com valor `0x00004550`. Em
ASCII isso é `"PE\0\0"`. É a segunda verificação que qualquer parser faz.
DOS Header começa com `MZ`, NT Headers começa com `PE`. Dois checks
simples que confirmam que você está lidando com um executável Windows
válido.

Pra chegar aqui no código, a gente pega o base address, soma o `e_lfanew`
e faz o cast:

```cpp
PIMAGE_NT_HEADERS32 nt = (PIMAGE_NT_HEADERS32)((BYTE*)proc + dos->e_lfanew);

cout << "Signature: 0x" << hex << nt->Signature << endl;
```

Por que `(BYTE*)proc + dos->e_lfanew`? Porque aritmética de ponteiro em
C++ depende do tipo. Se você somar direto em `HMODULE`, o compilador não
sabe o tamanho do passo. Fazendo o cast pra `BYTE*` primeiro, cada
unidade de soma é exatamente 1 byte, aí somar `e_lfanew` te leva ao
offset exato dentro do binário.

Vale notar uma coisa sobre a struct que usei: `PIMAGE_NT_HEADERS32`. Se
o seu projeto estiver compilado como **x64**, basta trocar por
`PIMAGE_NT_HEADERS64`. Ou você pode usar `PIMAGE_NT_HEADERS` direto, que
o próprio compilador resolve pra versao certa dependendo da arquitetura
alvo. Pra esse estudo estou compilando em x86 pra manter mais simples.

![Console mostrando Magic, e_lfanew e Signature com os valores corretos](/assets/img/pe-do-zero/04-console-signature.png)

![Diagrama mostrando o DOS Header com seta saindo de e_lfanew apontando para o NT Headers](/assets/img/pe-do-zero/svg-02-dos-to-nt.svg)

## 3. FileHeader: metadados do executável

O NT Headers tem três partes dentro dele:

```
IMAGE_NT_HEADERS
│
├── Signature
├── FileHeader    ← estamos aqui
└── OptionalHeader
```

O **FileHeader** guarda informações gerais sobre o executável. Clica em
**File Header** no CFF Explorer:

![CFF Explorer mostrando o File Header com NumberOfSections igual a 0007 em destaque](/assets/img/pe-do-zero/05-cff-file-header.png)

Os campos que mais me interessaram aqui:

- **`Machine`**: arquitetura do binário. `0x8664` é AMD64 (x86-64). `0x14C`
  seria x86 32 bits.
- **`NumberOfSections`**: quantas seções o executável tem (`.text`, `.data`,
  `.rdata`, etc.). Vou precisar disso pra iterar pelas seções logo mais.
- **`TimeDateStamp`**: timestamp de quando o binário foi compilado.
  Malwares costumam falsificar esse campo pra esconder a origem.
- **`Characteristics`**: flags que indicam se é DLL, EXE, se tem debug
  symbols, etc.

Código pra pegar o número de seções:

```cpp
cout << "NumberOfSections: " << dec << nt->FileHeader.NumberOfSections << endl;
```

![Console mostrando NumberOfSections e o nome da primeira seção](/assets/img/pe-do-zero/06-console-num-sections.png)

### Como o C++ sabe onde o FileHeader começa?

Aqui eu tive uma dúvida: como `nt->FileHeader` sabe o endereço exato na
memória?

O Windows definiu a struct `IMAGE_NT_HEADERS` com os campos numa **ordem
exata e fixa**. O layout real fica assim:

```
offset +0    Signature       (4 bytes)
offset +4    FileHeader      (20 bytes)
offset +24   OptionalHeader  (variável)
```

Quando você escreve `nt->FileHeader`, o compilador calcula automaticamente
"4 bytes depois do início da struct". Sem mágica nenhuma, é só aritmética
de struct. E como essa ordem nunca muda (é parte do formato PE há décadas),
você pode contar com ela sempre.

## 4. Section Headers: as partes do executável

Um executável PE é dividido em **seções**, cada uma com uma função
específica:

| Seção | Conteúdo |
|-------|----------|
| `.text` | código executável |
| `.data` | variáveis globais com valor inicial |
| `.rdata` | dados somente leitura (strings, tabela de imports) |
| `.bss` | variáveis não inicializadas |
| `.rsrc` | recursos (ícones, imagens, strings de UI) |

Cada seção tem um cabeçalho (`IMAGE_SECTION_HEADER`) que descreve onde
ela está e quanto espaço ocupa. A tabela de seções fica logo depois do
`IMAGE_NT_HEADERS` na memória. Não existe outro ponteiro pra encontrá-la,
ela simplesmente começa imediatamente após.

Pra acessar a primeira seção existe uma macro do Windows SDK feita
exatamente pra isso:

```cpp
PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

cout << "Name : "               << section->Name             << endl;
cout << "VirtualAddress : 0x"   << hex << section->VirtualAddress   << endl;
cout << "PointerToRawData : 0x" << hex << section->PointerToRawData << endl;
```

`IMAGE_FIRST_SECTION(nt)` calcula o endereço certo somando o tamanho do
NT Headers ao ponteiro `nt`. O resultado é um ponteiro pra primeira
entrada da tabela de seções.

![Console mostrando o nome da seção, VirtualAddress e PointerToRawData](/assets/img/pe-do-zero/07-console-section-details.png)

### Iterando por todas as seções

Mostrar só a primeira seção é útil pra entender a struct, mas na prática
a gente precisa percorrer todas. É simples: `NumberOfSections` já tem a
quantidade exata, e as seções ficam em sequência na memória logo depois
do NT Headers, entao dá pra acessar como array mesmo:

```cpp
WORD numSections = nt->FileHeader.NumberOfSections;
PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);

for (WORD i = 0; i < numSections; i++) {
    cout << "Name : "               << sections[i].Name                    << endl;
    cout << "VirtualAddress : 0x"   << hex << sections[i].VirtualAddress   << endl;
    cout << "PointerToRawData : 0x" << hex << sections[i].PointerToRawData << endl;
    cout << "---" << endl;
}
```

`sections[i]` funciona exatamente como um array normal porque os
`IMAGE_SECTION_HEADER` ficam um do lado do outro na memória. Na Parte 2
esse loop vai ser o coração da conversao RVA → offset: a gente itera pelas
seções, verifica qual delas contém o RVA que estamos procurando, e usa o
`PointerToRawData` pra calcular o offset real.

## O que é RVA?

Antes de avançar pro Optional Header e DataDirectory, precisei parar pra
entender um conceito que aparece em todo lugar: **RVA** (*Relative Virtual
Address*, endereço virtual relativo).

RVA é um **endereço relativo à ImageBase** do módulo. A ImageBase é o
endereço onde o Windows carregou o executável na memória. O RVA sozinho
não diz onde algo está, você precisa somá-lo à ImageBase pra ter o
endereço absoluto:

```
ImageBase = 0x140000000
RVA       =      0x1000
VA        = 0x140001000
```

Por que isso existe? Por causa do **ASLR** (Address Space Layout
Randomization): o Windows carrega executáveis em endereços diferentes a
cada execução. Hardcodar endereços absolutos dentro do PE não funciona.
Então o formato armazena tudo como offsets relativos, e quem carrega o
binário resolve os endereços reais na hora.

### RVA nao e offset no arquivo

Esse foi o ponto que mais me confundiu: um RVA diz onde algo está na
**memória**, mas nao diz onde está no **arquivo em disco**. O Windows
reorganiza o executável quando carrega, então o que está no offset `0x400`
no arquivo pode estar no endereço virtual `0x1000` quando carregado.

Pra ler algo pelo RVA diretamente no arquivo (sem ter o binário mapeado
na memória), você precisa converter RVA em offset real. Isso é feito
usando as seções como tabela de conversão. Cada seção sabe:

```
VirtualAddress   = RVA onde a seção começa na memória
PointerToRawData = offset onde a seção começa no arquivo
```

Então a conversão fica:

```
rawOffset = PointerToRawData + (RVA - VirtualAddress)
```

Exemplo: você quer algo no RVA `0x1200`. A seção `.text` vai de RVA
`0x1000` até `0x2000`, com `PointerToRawData = 0x400`:

```
rawOffset = 0x400 + (0x1200 - 0x1000) = 0x600
```

Esse cálculo é o coração do PE parsing quando você trabalha com o arquivo
em disco. Na Parte 2 a gente implementa exatamente isso pra chegar na
Import Table.

![Diagrama completo da estrutura PE: DOS Header apontando para NT Headers, FileHeader, OptionalHeader com DataDirectory apontando para Import Table, e a tabela de Section Headers](/assets/img/pe-do-zero/svg-03-estrutura-completa.svg)

## 5. Optional Header e DataDirectory

Apesar do nome, o Optional Header **nao e opcional** em executáveis. É
onde ficam as informações mais importantes pra nós: `ImageBase`,
`AddressOfEntryPoint`, e principalmente o **DataDirectory**.

O DataDirectory é um array de 16 entradas. Cada uma aponta pra uma
tabela diferente dentro do PE:

```
DataDirectory[0]  → Export Table
DataDirectory[1]  → Import Table   ← essa nos interessa
DataDirectory[2]  → Resource Table
DataDirectory[5]  → BaseReloc Table
...
```

Cada entrada tem dois campos: o RVA onde aquela tabela começa e o
tamanho em bytes.

```cpp
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;  // RVA onde a tabela começa
    DWORD Size;            // tamanho em bytes
} IMAGE_DATA_DIRECTORY;
```

No CFF Explorer, clico em **Optional Header → Data Directories**:

![CFF Explorer mostrando o Data Directories com Import Directory RVA e Size em destaque](/assets/img/pe-do-zero/08-cff-data-directories.png)

O Import Directory tem um RVA nao-zero, é lá que fica a tabela de
imports. Em código:

```cpp
IMAGE_DATA_DIRECTORY importDir =
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

cout << "Import RVA:  0x" << hex << importDir.VirtualAddress << endl;
cout << "Import Size: "   << dec << importDir.Size           << endl;
```

Esse RVA ainda nao é o endereço final. Pra chegar na
`IMAGE_IMPORT_DESCRIPTOR` de verdade você precisa converter esse RVA
usando as seções, exatamente o cálculo que vimos acima. Isso fica pra
Parte 2.

## 6. Section Headers no CFF Explorer

Por último, clica em **Section Headers** no CFF Explorer pra ver a tabela
completa:

![CFF Explorer mostrando a tabela de Section Headers com todas as seções do notepad: .text, .rdata, .data, .pdata, .didat, .rsrc, .reloc](/assets/img/pe-do-zero/09-cff-section-headers.png)

O que cada coluna significa:

| Coluna | Significado |
|--------|-------------|
| **Name** | nome da seção (até 8 bytes) |
| **Virtual Size** | tamanho real do conteúdo na memória |
| **Virtual Address** | RVA onde a seção começa na memória |
| **Raw Size** | tamanho no arquivo (arredondado pro `FileAlignment`) |
| **Raw Address** | offset da seção no arquivo em disco (`PointerToRawData`) |
| **Reloc Address / Linenumbers** | raramente usados em binários modernos |
| **Characteristics** | flags de permissão da página |

Repara nas Characteristics: `60000020` no `.text` significa executável +
legível + contém código. `40000040` no `.rdata` significa somente leitura
+ contém dados inicializados. É por isso que pra fazer IAT hooking você
precisa do `VirtualProtect`, a IAT fica na `.rdata` que é read-only por
padrão.

As colunas **Virtual Address** e **Raw Address** sao exatamente os valores
que a gente usa pra converter RVA em offset. Agora entendo o que cada
linha dessa tabela representa e por que vou precisar delas.

## Onde chegamos

Cobri toda a cadeia de headers do PE:

```
IMAGE_DOS_HEADER
└── e_lfanew → IMAGE_NT_HEADERS
                ├── Signature
                ├── IMAGE_FILE_HEADER
                │     └── NumberOfSections
                ├── IMAGE_OPTIONAL_HEADER
                │     └── DataDirectory[1] → Import Table RVA
                └── IMAGE_SECTION_HEADER[]
                      ├── .text
                      ├── .rdata
                      ├── .data
                      └── ...
```

Na [**Parte 2**](/pe-do-zero-parte2/) a gente usa esse mapa pra:

1. Converter o RVA da Import Table em offset real usando as seções
2. Ler os `IMAGE_IMPORT_DESCRIPTOR`, um pra cada DLL importada
3. Acessar os nomes das DLLs e das funções dentro de cada descriptor
4. Imprimir tudo: `kernel32.dll → CreateFileW, ReadFile...`

---

*Post da série pe-do-zero, minhas anotações de estudo sobre PE parsing.
Se achou algum erro ou tem sugestão, manda aí.*
