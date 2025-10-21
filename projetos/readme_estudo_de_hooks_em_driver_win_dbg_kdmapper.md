# Estudo de Hooks em Driver — README

> Notas de estudo para configurar **WinDbg** numa VM e usar **kdmapper** para inspecionar e testar hooks em funções do kernel/Win32k. Uso exclusivo para fins educacionais e de aprendizagem.

---

## Objetivo
Organizar um passo-a-passo mínimo para: configurar o ambiente (VM + WinDbg), identificar processos/funções a hookar, recarregar módulos/endereços, inspecionar código (disassembly) e testar injeção usando um kdmapper de estudo.

## Pré-requisitos
- Máquina virtual (VM) com Windows configurada para debugging de kernel (ex.: VirtualBox / VMware / Hyper-V).
- WinDbg (modo kernel) instalado no host de depuração.
- kdmapper (ferramenta de mapeamento de drivers para testes educativos).
- Driver de estudo compilado (arquivo `.sys`).
- Familiaridade básica com assembly x64 e com conceitos de driver/Win32k.

> Aviso: **não** use este material para atividades maliciosas. Teste apenas em ambientes controlados e máquinas que você possui ou tem permissão para modificar.

---

## Passos gerais (resumo)
1. Habilitar debugging de kernel na VM e conectar o WinDbg do host.
2. Iniciar a VM em modo que aceite a conexão de depuração.
3. No WinDbg, localizar o processo alvo (ex.: `explorer.exe`) e pegar informações relevantes.
4. Recarregar o módulo alvo (ex.: `dxgkrnl.sys`) para garantir símbolos/bytes atualizados.
5. Abrir o *Disassembly* (View → Disassembly) e pesquisar o nome da função a ser hookada.
6. Anotar o endereço da função e inspecionar o código em volta.
7. Usar kdmapper para injetar o driver de teste e validar o hook.

---

## Comandos úteis no WinDbg (exemplos)

- Localizar processo `explorer.exe` e ver meta-informações:

```text
!process 0 0 explorer.exe
```

**Exemplo de saída esperada** (formatada):

```
PROCESS ffff9882edc70080
    SessionId: 1  Cid: 127c    Peb: 00e56000  ParentCid: 1260
    DirBase: 14431d002  ObjectTable: ffff88827c17db00  HandleCount: 2464.
    Image: explorer.exe
```

- Recarregar um módulo para atualizar bytes/símbolos (force):

```text
.reload /f dxgkrnl.sys
```

- Abrir o Disassembler
  - No WinDbg: `View` → `Disassembly`.
  - Na janela de disassembly, pesquise pelo nome de função (ex.: `NtOpenCompositionSurfaceSectionInfo`).
  - você pode tbm procurar por outras funcoes do windwos:
  (ex `NtQueryCompositionSurfaceHDRMetaData`)
- Procure funções `NtOpen*` — essas normalmente aparecem e são bons alvos de estudo.
- Funções `NtD*` ou funções muito internas podem não funcionar ou não aparecer.
- Funções relacionadas a *composition* (composição gráfica) costumam estar presentes — são úteis para aprender.
**Dica:** algumas funções têm proteções ou usam `secure cookie` / regiões críticas. Evite modificar/alterar código em regiões marcadas como críticas até entender o comportamento.

---

## Exemplo prático (fluxo que você descreveu)
1. Rode `!process 0 0 explorer.exe` — pegue o `PROCESS` e confirme o `Image: explorer.exe`.
2. Recarregue o módulo alvo: `.reload /f dxgkrnl.sys`.
3. Abra Disassembly e pesquise a função que quer analisar, por exemplo:
   - `NtOpenCompositionSurfaceSectionInfo`
4. Anote o endereço mostrado pelo disassembler — por exemplo: `0FFFF9882E7FB7090`.
5. Vá para esse endereço no disassembly e inspecione as instruções (procure por padrões como `xor eax, eax`, `ret`, prologs/epilogs etc.).

> Observação do seu experimento: muitas vezes, o código começa com `xor eax, eax` seguido de instruções que retornam ou preparam o contexto — anote isso ao estudar como o hook deve se comportar.

---

## Boas práticas e cuidados
- Trabalhe sempre em VM snapshot — crie um snapshot antes de testar injeções/alterações.
- Evite hooks em funções que lidam com dados sensíveis do kernel sem entender proteção (CSRSS, secure cookie, regiões críticas).
- Anote o endereço virtual **exato** encontrado no disassembly — ao recarregar o driver/módulo o endereço pode mudar.
- Use símbolos (pdb) quando possível para facilitar entendimento das estruturas e nomes.
- Se o endereço parecer invalidado após recarregar o driver, recalcule/pegue novamente — a imagem do módulo pode ter mudado.

---

## Troubleshooting (problemas comuns)
- **Função não aparece no disassembly**: tente recarregar o módulo (`.reload /f <module>`) e pesquise novamente; confirme que você está olhando o módulo certo.
- **Endereço muda após recarga**: sempre re-anote o novo endereço depois do `.reload`.
- **Hook falha com crashes ou proteção**: verifique se a função usa *stack cookie* / safe exceptions / region critical; revise se a manipulação segura de parâmetros é necessária.
- **kdmapper não mapeia**: verifique compatibilidade do driver (assinatura digital, versões do SO, DEP/CFG) e execute em VM isolada.

---

## Checklist rápido antes de testar
- [ ] Snapshot da VM criado
- [ ] WinDbg conectado ao kernel da VM
- [ ] Módulo recarregado com `.reload /f`
- [ ] Endereço da função anotado
- [ ] Driver de teste (.sys) pronto e compatível
- [ ] kdmapper configurado e com permissões


