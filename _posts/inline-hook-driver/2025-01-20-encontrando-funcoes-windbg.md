---
title: "Encontrando Funções no Windows com WinDbg"
date: 2025-01-20 08:00:00 -0300
categories: [Segurança, Reverse Engineering]
tags: [windbg, kernel, debugging, windows, reverse-engineering, syscalls]
---

## Introdução

Antes de desenvolver qualquer driver ou técnica de hooking, precisamos entender como encontrar e analisar funções do sistema Windows. Neste post, vou compartilhar minha experiência usando o **WinDbg** para localizar e estudar funções do kernel.

> ⚠️ **Aviso**: Este conteúdo é **exclusivamente educacional**. Use apenas em ambientes controlados (VMs) e para fins de aprendizado.

## Primeiro Passo: Entendendo a Função que Vamos Analisar

Antes de desenvolver qualquer driver, precisamos entender algumas coisas sobre as funções que vamos interceptar. Para isso, precisamos ter o **WinDbg** instalado e configurado para kernel debugging.

### Configurando o WinDbg

1. **Abra o WinDbg**
2. **Vá em File → Kernel Debug**
3. **Configure a conexão** (Serial, USB, ou Network)

### Encontrando o Processo Explorer

Agora vamos localizar o processo `explorer.exe` para entender como o sistema funciona:

```
!process 0 0 explorer.exe
```

![Primeira imagem do WinDbg mostrando o comando !process](/assets/img/1_primeira.png)

Este comando lista informações sobre o processo explorer.exe. Como você pode ver na imagem acima, ele retorna detalhes importantes como:
- **SessionId**: ID da sessão
- **Cid**: Process ID (PID)
- **Peb**: Endereço do Process Environment Block
- **DirBase**: Diretório base
- **Image**: Nome da imagem (explorer.exe)

### Recarregando o Módulo dxgkrnl.sys

Agora vamos recarregar o módulo `dxgkrnl.sys` para garantir que temos os símbolos atualizados:

```
.reload /f dxgkrnl.sys
```

Este comando força o reload do driver `dxgkrnl.sys` (DirectX Graphics Kernel), atualizando os símbolos e endereços na memória.

### Abrindo o Disassembler

Agora vem a parte interessante! Vamos abrir o **Disassembler** no WinDbg:

1. **Vá em View → Disassembly**
2. **Digite o nome da função:** `NtOpenCompositionSurfaceSectionInfo`

Aqui começa a brincadeira! Esta é a função que estamos analisando.

![Segunda imagem mostrando o disassembler com a função NtOpenCompositionSurfaceSectionInfo](/assets/img/2_segunda.png)

### Como a Função Está Antes do Hook

Como você pode ver na imagem acima, esta é exatamente como a função `NtOpenCompositionSurfaceSectionInfo` está **antes** de aplicarmos qualquer modificação. 

Observando o código assembly, vemos que a função original é bem simples:
- `mov rax, rsp` - Move o valor do ponteiro da stack (RSP) para o registrador RAX
- `ret` - Retorna da função

**Importante:** Na imagem você pode ver que `48 8b c4` está destacado - esses são **3 bytes** do código original. Isso é perfeito para nosso hook, pois precisamos de pelo menos 5 bytes para fazer o jump, e essa função tem espaço suficiente para nossa técnica funcionar.

Esta é a função "limpa" que vamos analisar. Mais tarde, quando aplicarmos modificações, esses primeiros bytes serão substituídos pelo nosso código.

![Terceira imagem mostrando detalhes da função antes do hook](/assets/img/3_terceira.png)

### Após Fazer o Hook

Agora que entendemos como a função está antes do hook, vamos ver exatamente o que vamos colocar no lugar dos bytes originais:

```
48 B8 [endereço de 64 bits] FF  E0
│  │   └─────────┬─────────┘   │ │
│  │             │             │ └─> JMP RAX
└─ └─────────────┴─────────────┴───> MOV RAX, <endereço>
```

**Detalhamento:**

- **48 B8**: Opcode para `MOV RAX, imm64`
- **[8 bytes]**: Endereço da nossa função
- **FF E0**: Opcode para `JMP RAX`

Este shellcode de **12 bytes** substituirá os primeiros bytes da função original, fazendo com que qualquer chamada para `NtOpenCompositionSurfaceSectionInfo` seja redirecionada para nossa função personalizada.

## Outras Funções Disponíveis

Podemos procurar mais funções e encontrei esse site excelente:
**[https://j00ru.vexillium.org/syscalls/win32k/64/](https://j00ru.vexillium.org/syscalls/win32k/64/)**

Este site contém uma tabela completa de todas as system calls do Windows, incluindo as funções do `win32k.sys`. A gente só precisa analisar uma função e trocar no driver/usermode.

**Algumas anotações pessoais:**
- Funções com nome de **"composition"** nelas são boas para hook
- Funções `NtOpen*` geralmente funcionam bem
- Evite funções `NtD*` (podem não funcionar)

**⚠️ Dica importante:** Algumas funções têm proteções ou usam **secure cookie** / regiões críticas. Evite modificar/alterar código em regiões marcadas como críticas até entender o comportamento.

> **Experiência pessoal:** Muitas telas azuis nos meus testes! 😅 Sempre teste em VM com snapshots!

## Conceitos Importantes

### 1. Assembly x64

| Instrução | Opcode | Descrição |
|-----------|--------|-----------|
| `MOV RAX, imm64` | `48 B8` | Move valor para RAX |
| `JMP RAX` | `FF E0` | Pula para endereço em RAX |
| `XOR EAX, EAX` | `33 C0` | Zera EAX |
| `RET` | `C3` | Retorna da função |

## Próximos Passos

Agora que sabemos como encontrar e analisar funções, podemos:

1. **Desenvolver o driver** que vai interceptar essas funções
2. **Implementar o inline hook** para redirecionar chamadas
3. **Criar comunicação** entre kernel e usermode
4. **Testar e debugar** nossa implementação

---

**Próximo post:** [Desenvolvendo um Driver de Inline Hook em Kernel Mode](/desenvolvendo-driver-inline-hook/)
