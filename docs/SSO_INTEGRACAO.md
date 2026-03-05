# SGE Central — Guia de Integração SSO + RBAC

> Documento técnico para integrar qualquer sistema satélite ao ecossistema SGE.

---

## Arquitetura

```
┌─────────────────┐     1. Redirect      ┌──────────────────┐
│  Sistema        │ ──────────────────►   │  SGE Central     │
│  Satélite       │                       │  (SSO Login)     │
│                 │   4. ?sso_token=...   │                  │
│  sso_client.js  │ ◄────────────────── │  sso.js          │
└────────┬────────┘                       └────────┬─────────┘
         │                                         │
         │  5. Revalidação                         │ 2. Auth + 3. RBAC
         │     a cada página                       │
         ▼                                         ▼
┌──────────────────────────────────────────────────────────┐
│                    Supabase (PostgREST)                   │
│                                                          │
│  public.v_sso_usuarios   → gps_compartilhado.sge_central_usuarios          │
│  public.v_sso_sistemas   → gps_compartilhado.sge_central_sistemas          │
│  public.v_sso_acesso     → gps_compartilhado.sge_central_usuario_sistema_  │
│                             acesso + sge_central_perfis (JOIN)              │
└──────────────────────────────────────────────────────────┘
```

---

## Checklist de Integração (Novo Sistema)

### 1. Registrar o sistema no banco

```sql
INSERT INTO gps_compartilhado.sge_central_sistemas (nome, slug, is_active)
VALUES ('Nome do Sistema', 'slug_do_sistema', true);
```

> O `slug` deve ser único, sem espaços, minúsculo com underscores.

### 2. Conceder acesso aos usuários

```sql
INSERT INTO gps_compartilhado.sge_central_usuario_sistema_acesso 
  (usuario_id, sistema_id, perfil_id, is_active)
VALUES 
  ('UUID_DO_USUARIO', 'UUID_DO_SISTEMA', 'UUID_DO_PERFIL', true);
```

**Perfis disponíveis:**

| Nome | Nível | UUID |
|------|-------|------|
| VISAO | 10 | `9bfecbe1-1885-49d8-97dd-a222e21e48b3` |
| GESTAO | 50 | `4a2bb7df-1270-487b-8768-9c1a35d9551e` |
| ADM | 80 | `b0ee8f01-68ae-4b9d-9586-9f7a1b5785cc` |
| SUPER | 100 | `e95887fe-beea-45c2-9d04-4eba964b6887` |

### 3. Adicionar o script no HTML do sistema

```html
<!-- Supabase JS (obrigatório antes do sso_client.js) -->
<script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2"></script>

<!-- SGE SSO SDK (carregado do GitHub Pages) -->
<script src="https://grupogps-mecanizada.github.io/SGE_GRUPOGPS/js/auth/sso_client.js?v=5"></script>
```

> **IMPORTANTE:** Sempre use `?v=X` com o número da versão atual do SDK (`SGE_SDK_VERSION`).

### 4. Criar o `auth.js` do sistema

```javascript
// Substitua 'slug_do_sistema' pelo slug registrado no passo 1
const ssoClient = new window.SgeAuthSDK('slug_do_sistema');

const AUTH = {
    currentUser: null,

    async init() {
        const userData = await ssoClient.checkAuth(); // DEVE ser await (async)

        if (userData) {
            console.log('Autenticado:', userData.nome, '| Perfil:', userData.perfil);
            this.currentUser = userData;
            this.applyProfile(userData.perfil);
            return true;
        }

        // Se bypass ativo, tentar login local
        if (ssoClient.isBypass()) {
            // ... fallback de autenticação local
        }

        return false;
    },

    applyProfile(perfil) {
        // Aplicar regras de visibilidade por perfil
        // perfil = 'VISAO' | 'GESTAO' | 'ADM' | 'SUPER'
        document.body.setAttribute('data-perfil', perfil);
    },

    logout() {
        ssoClient.logout();
    }
};
```

### 5. Inicializar no carregamento

```javascript
document.addEventListener('DOMContentLoaded', async () => {
    const ok = await AUTH.init();
    if (ok) {
        // Carregar dados do sistema...
    }
});
```

---

## Como Funciona (Fluxo Automático)

### Login (primeira vez)
1. `checkAuth()` → sem token → redireciona pra Central SGE
2. Central SGE → form de email/senha → Supabase Auth
3. RBAC triple-check: usuário ativo? sistema ativo? acesso concedido?
4. Gera JWT com `{ user: { id, email, nome, perfil }, ver: 5 }`
5. Redireciona de volta com `?sso_token=...`
6. `sso_client.js` salva no `localStorage`

### Visitas subsequentes
1. `checkAuth()` → token no `localStorage`
2. Valida expiração (8h)
3. **Revalida com servidor** → verifica 3 camadas RBAC
4. **Sincroniza perfil** → se admin mudou de GESTAO pra VISAO, aplica imediatamente

### Auto-cleanup (a cada página)
- Token corrompido → removido
- URL com `sso_token` acumulados → limpa
- SDK atualizado (versão diferente) → token antigo removido, força re-login

---

## Gerenciamento na Central SGE

### Bloquear um usuário (todos os sistemas)
- Botão **"Bloquear"** no painel Gestão de Identidade
- Efeito: `sge_central_usuarios.is_active = false`
- Resultado: próximo carregamento de qualquer sistema → "Acesso Negado"

### Revogar acesso a um sistema específico
- Drawer de configuração do usuário → desativar sistema
- Efeito: `sge_central_usuario_sistema_acesso.is_active = false`

### Mudar perfil de acesso
- Drawer de configuração → alterar perfil (VISAO/GESTAO/ADM/SUPER)
- Efeito: próximo carregamento sincroniza automaticamente

### Desativar um sistema inteiro
- `sge_central_sistemas.is_active = false`
- Efeito: nenhum usuário consegue acessar

---

## Forçar Atualização Global

Quando fizer mudanças no `sso_client.js`:

1. Altere `SGE_SDK_VERSION` no arquivo:
```javascript
const SGE_SDK_VERSION = 6; // era 5, agora 6
```

2. Atualize o `?v=` no HTML de cada sistema satélite:
```html
<script src=".../sso_client.js?v=6"></script>
```

3. Faça push. **Todos** os navegadores vão:
   - Baixar a nova versão (cache-bust pelo `?v=`)
   - Detectar mismatch de versão
   - Limpar tokens antigos
   - Forçar novo login pelo SSO

---

## Tabelas e Views

### Banco de dados (`gps_compartilhado`)

| Tabela | Finalidade |
|--------|-----------|
| `sge_central_usuarios` | Cadastro de usuários (id = auth.users.id) |
| `sge_central_sistemas` | Sistemas do ecossistema (slug único) |
| `sge_central_perfis` | Níveis de acesso (VISAO/GESTAO/ADM/SUPER) |
| `sge_central_usuario_sistema_acesso` | Quem acessa o quê, com qual perfil |

### Views públicas (para SSO)

| View | Campos | Uso |
|------|--------|-----|
| `v_sso_usuarios` | id, nome, email, is_active | Verificar se usuário está ativo |
| `v_sso_sistemas` | id, nome, slug, is_active | Verificar se sistema está ativo |
| `v_sso_acesso` | id, usuario_id, sistema_id, is_active, perfil_nome | Verificar acesso + perfil |

### Permissões (RLS/Grants)

```sql
-- Necessário para SSO funcionar via REST API
GRANT SELECT ON public.v_sso_usuarios TO anon, authenticated;
GRANT SELECT ON public.v_sso_sistemas TO anon, authenticated;
GRANT SELECT ON public.v_sso_acesso TO anon, authenticated;
GRANT USAGE ON SCHEMA gps_compartilhado TO anon, authenticated;
GRANT SELECT ON gps_compartilhado.sge_central_usuarios TO anon, authenticated;
GRANT SELECT ON gps_compartilhado.sge_central_sistemas TO anon, authenticated;
GRANT SELECT ON gps_compartilhado.sge_central_usuario_sistema_acesso TO anon, authenticated;
GRANT SELECT ON gps_compartilhado.sge_central_perfis TO anon, authenticated;
```

---

## Constantes Importantes

| Constante | Valor |
|-----------|-------|
| Supabase URL | `https://mgcjidryrjqiceielmzp.supabase.co` |
| Anon Key | `eyJhbGci...UAKkzy5f...` |
| Central URL | `https://grupogps-mecanizada.github.io/SGE-CENTRAL` |
| SDK Atual | `SGE_SDK_VERSION = 5` |
| Token TTL | 8 horas |

---

## Troubleshooting

| Problema | Causa | Solução |
|----------|-------|---------|
| 406 Not Acceptable | Tabela não acessível via REST | Usar views públicas (`v_sso_*`) |
| Token com perfil errado | Token antigo no localStorage | Incrementar `SGE_SDK_VERSION` |
| Loop infinito de redirects | Token na hash fragment (#) | SDK v5 já trata automaticamente |
| "Não encontrado" após login | Falta GRANT no banco | Executar os GRANTs acima |
| Perfil não atualiza | Token antigo sem revalidação | SDK v5 revalida a cada página |
