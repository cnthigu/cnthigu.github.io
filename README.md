# cnthigu.github.io

Blog pessoal criado com Jekyll e tema Klisé, hospedado no GitHub Pages.

## 🚀 Tecnologias

- **Jekyll 4.3** - Gerador de sites estáticos
- **Klisé Theme** - Tema minimalista com suporte dark/light mode
- **GitHub Pages** - Hospedagem gratuita
- **Markdown** - Formato dos posts

## 📝 Começando

### Instalação Local (Windows)

1. **Instale o Ruby 3.4+**
   - Baixe em: https://rubyinstaller.org/downloads/
   - Use a versão **Ruby+Devkit 3.2.X (x64)**

2. **Clone o repositório:**
   ```bash
   git clone https://github.com/cnthigu/cnthigu.github.io.git
   cd cnthigu.github.io
   ```

3. **Instale as dependências:**
   ```bash
   bundle install
   ```

4. **Execute localmente:**
   ```bash
   bundle exec jekyll serve --livereload --future
   ```

5. **Acesse:** `http://localhost:4000`

### Flags úteis

- `--livereload` - Auto-refresh no navegador
- `--future` - Mostra posts com data futura
- `--drafts` - Mostra rascunhos

## ✍️ Criar um Novo Post

### Método 1: Manual

Crie um arquivo em `_posts/nome-do-post/YYYY-MM-DD-nome-do-post.md`:

```markdown
---
title: Título do Post
date: 2025-10-20 10:00:00 -0300
modified: 2025-10-20 10:00:00 -0300
tags: [tag1, tag2]
description: Descrição breve do post
---

Seu conteúdo aqui em Markdown...
```

### Método 2: Com Jekyll Compose

```bash
bundle exec jekyll post "Título do Post"
```

## 🎨 Personalização

### Configurações (_config.yml)

Edite `_config.yml` para personalizar:

```yaml
title: Seu Nome                    # Título do site
author:
  name: Seu Nome                   # Seu nome
  bio: Sua biografia               # Descrição
  github: seu-usuario              # GitHub username
  email: seu@email.com             # Email
  avatar: /assets/img/avatar.jpg   # Sua foto
mode: dark                         # Tema padrão (dark/light)
```

### Trocar sua foto

Substitua o arquivo `assets/img/avatar.jpg` pela sua foto.

### Estilos e Cores

Edite os arquivos em `_sass/klise/` para customizar cores e estilos:

- `_sass/klise/_dark.scss` - Tema escuro
- `_sass/klise/_base.scss` - Estilos base
- `_sass/klise/_layout.scss` - Layout

## 📁 Estrutura do Projeto

```
cnthigu.github.io/
├── _config.yml          # Configurações
├── _includes/           # Componentes reutilizáveis
├── _layouts/            # Templates
│   ├── default.html     # Layout base
│   ├── home.html        # Página inicial
│   └── post.html        # Layout de post
├── _posts/              # Posts (Markdown)
├── _sass/               # Estilos SCSS
├── assets/
│   ├── css/            # CSS compilado
│   ├── img/            # Imagens
│   └── js/             # JavaScript
├── about.md            # Página sobre
└── index.md            # Página inicial
```

## 🚀 Deploy no GitHub Pages

1. **Commit suas mudanças:**
   ```bash
   git add .
   git commit -m "Atualização do blog"
   git push origin main
   ```

2. **Configure no GitHub:**
   - Vá em: Repositório → **Settings** → **Pages**
   - **Source:** Branch `main`, pasta `/ (root)`
   - Clique em **Save**

3. **Acesse:** `https://cnthigu.github.io`

## 🔧 Comandos Úteis

```bash
# Instalar/atualizar dependências
bundle install
bundle update

# Rodar servidor local
bundle exec jekyll serve

# Limpar cache
bundle exec jekyll clean

# Build para produção
bundle exec jekyll build
```

## 📄 Licença

Este projeto está sob a licença MIT.

## 🙏 Créditos

- Tema base: [Klisé Theme](https://github.com/piharpi/jekyll-klise) por [@piharpi](https://github.com/piharpi)
- Powered by [Jekyll](https://jekyllrb.com/)

---

**Feito com ❤️ por cnthigu**
