/**
 * SGE IDENTITY PROVIDER (SSO) SDK v5
 * Ponte entre qualquer sistema satélite e a Central SGE.
 * 
 * FEATURES:
 *   1. SSO redirect → Central SGE para autenticação
 *   2. TOKEN REVALIDATION via public views (v_sso_*)
 *   3. PROFILE SYNC — atualiza perfil do servidor em cada revalidação
 *   4. AUTO-CLEANUP — limpa tokens antigos/corruptos automaticamente
 *   5. VERSION GUARD — força re-login quando SDK é atualizado
 *   6. BYPASS mode — login local via Supabase Auth (fallback)
 */

const SGE_CENTRAL_URL = window.SGE_CENTRAL_URL_OVERRIDE
    || "https://grupogps-mecanizada.github.io/SGE-CENTRAL";

const SGE_SSO_API = "https://mgcjidryrjqiceielmzp.supabase.co";
const SGE_SSO_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im1nY2ppZHJ5cmpxaWNlaWVsbXpwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzIxMjEwNzEsImV4cCI6MjA4NzY5NzA3MX0.UAKkzy5fMIkrlmnqz9E9KknUw9xhoYpa3f1ptRpOuAA";

// ═══ VERSION GUARD ═══
// Increment this number on EVERY deployment that changes token format or auth logic.
// Old tokens with mismatched versions are automatically purged.
const SGE_SDK_VERSION = 5;

// Direct REST helper — queries public schema views
async function _ssoFetch(table, params) {
    const url = new URL(`${SGE_SSO_API}/rest/v1/${table}`);
    Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));
    const resp = await fetch(url.toString(), {
        headers: {
            'apikey': SGE_SSO_KEY,
            'Authorization': `Bearer ${SGE_SSO_KEY}`,
            'Accept': 'application/vnd.pgrst.object+json'
        }
    });
    if (!resp.ok) return null;
    return await resp.json();
}

class SgeAuthSDK {
    constructor(appSlug) {
        this.appSlug = appSlug;
        this.storageKey = `sge_token_${this.appSlug}`;
        this.versionKey = `sge_ver_${this.appSlug}`;
        this._log('SDK v5 inicializado', { appSlug, version: SGE_SDK_VERSION, bypass: this.isBypass() });

        // AUTO-CLEANUP on construction
        this._autoCleanup();
    }

    _log(msg, data) {
        const p = `[SGE SSO][${this.appSlug}]`;
        data ? console.log(`${p} ${msg}`, data) : console.log(`${p} ${msg}`);
    }
    _warn(msg, data) {
        const p = `[SGE SSO][${this.appSlug}]`;
        data ? console.warn(`${p} ⚠ ${msg}`, data) : console.warn(`${p} ⚠ ${msg}`);
    }

    isBypass() { return window.SGE_SSO_BYPASS === true; }

    // ═══ AUTO-CLEANUP ═══
    // Runs on EVERY page load. Clears stale tokens, old versions, and corrupted data.
    _autoCleanup() {
        try {
            const storedVersion = parseInt(localStorage.getItem(this.versionKey) || '0', 10);

            // Version mismatch → purge old token and force fresh login
            if (storedVersion !== SGE_SDK_VERSION) {
                const hadToken = !!localStorage.getItem(this.storageKey);
                localStorage.removeItem(this.storageKey);
                localStorage.setItem(this.versionKey, String(SGE_SDK_VERSION));
                if (hadToken) {
                    this._log(`Auto-cleanup: Token antigo removido (v${storedVersion} → v${SGE_SDK_VERSION})`);
                }
            }

            // Validate stored token isn't corrupted
            const token = localStorage.getItem(this.storageKey);
            if (token) {
                const userData = this.decodeToken(token);
                if (!userData) {
                    this._warn('Auto-cleanup: Token corrompido removido');
                    localStorage.removeItem(this.storageKey);
                }
            }

            // NOTE: Do NOT call _cleanUrl() here — checkAuth() needs to read sso_token from URL first

        } catch (e) {
            // localStorage might be blocked (incognito, security settings)
            this._warn('Auto-cleanup falhou — localStorage pode estar bloqueado', e.message);
        }
    }

    // Remove any sso_token params from URL without page reload
    _cleanUrl() {
        const url = new URL(window.location.href);
        const search = url.searchParams;
        const hashStr = url.hash;

        let needsClean = false;

        // Clean search params
        if (search.has('sso_token')) {
            search.delete('sso_token');
            needsClean = true;
        }

        // Clean hash params (SPA routing: #page?sso_token=...)
        if (hashStr.includes('sso_token=')) {
            const hashBase = hashStr.split('?')[0];
            url.hash = hashBase;
            needsClean = true;
        }

        if (needsClean) {
            window.history.replaceState({}, document.title, url.toString());
            this._log('Auto-cleanup: URL limpa');
        }
    }

    // ═══ REDIRECT TO LOGIN ═══
    redirectToLogin() {
        if (this.isBypass()) {
            this._log('BYPASS ativado');
            return 'BYPASS';
        }
        // Always send clean URL (no hash, no query params, no old tokens)
        const cleanUrl = window.location.origin + window.location.pathname;
        const returnUrl = encodeURIComponent(cleanUrl);
        const targetUrl = `${SGE_CENTRAL_URL}/?app_slug=${this.appSlug}&redirect=${returnUrl}`;
        this._log('Redirecionando para Central SGE', { targetUrl });
        window.location.href = targetUrl;
        return 'REDIRECT';
    }

    // ═══ CHECK AUTH (async, com revalidação e auto-correction) ═══
    async checkAuth() {
        this._log('Verificando autenticação...');

        // 1. Token from URL (returning from SSO — check both search and hash)
        const tokenFromUrl = this._extractTokenFromUrl();

        if (tokenFromUrl) {
            this._log('Token SSO recebido via URL');
            const userData = this.decodeToken(tokenFromUrl);
            if (!userData) {
                this._warn('Token da URL inválido — descartando');
                this._cleanUrl();
                this.redirectToLogin();
                return null;
            }

            // Store token + version
            localStorage.setItem(this.storageKey, tokenFromUrl);
            localStorage.setItem(this.versionKey, String(SGE_SDK_VERSION));
            this._cleanUrl();

            this._log('✓ Autenticado via SSO', { nome: userData.nome, perfil: userData.perfil });
            return userData;
        }

        // 2. Token from storage — needs revalidation
        const token = localStorage.getItem(this.storageKey);
        if (!token) {
            this._log('Nenhum token encontrado');
            if (this.isBypass()) return null;
            this.redirectToLogin();
            return null;
        }

        const userData = this.decodeToken(token);
        if (!userData) {
            this._warn('Token inválido/expirado — removendo');
            localStorage.removeItem(this.storageKey);
            if (this.isBypass()) return null;
            this.redirectToLogin();
            return null;
        }

        // 3. REVALIDATE with server (also syncs profile)
        const result = await this._revalidate(userData);
        if (!result) {
            localStorage.removeItem(this.storageKey);
            return null;
        }

        // 4. Update profile from server if it changed
        if (result.perfil && result.perfil !== userData.perfil) {
            this._log(`Perfil sincronizado: ${userData.perfil} → ${result.perfil}`);
            userData.perfil = result.perfil;
        }

        this._log('✓ Autenticado e revalidado', { nome: userData.nome, perfil: userData.perfil });
        return userData;
    }

    // ═══ EXTRACT TOKEN FROM URL ═══
    _extractTokenFromUrl() {
        // Check search params (?sso_token=...)
        const searchParams = new URLSearchParams(window.location.search);
        const fromSearch = searchParams.get('sso_token');
        if (fromSearch) return fromSearch;

        // Check hash fragment (#page?sso_token=...)
        const hash = window.location.hash;
        if (hash.includes('sso_token=')) {
            const hashQuery = hash.split('?')[1];
            if (hashQuery) {
                const hashParams = new URLSearchParams(hashQuery);
                return hashParams.get('sso_token');
            }
        }

        return null;
    }

    // ═══ REVALIDATION via public views ═══
    // Returns { perfil } on success, false on failure
    async _revalidate(userData) {
        try {
            this._log('Revalidando com servidor...');

            // Check 1: User active?
            const user = await _ssoFetch('v_sso_usuarios', {
                'select': 'id,is_active',
                'id': `eq.${userData.id}`
            });

            if (!user) {
                this._warn('Usuário não encontrado');
                this._showBlocked('Seu cadastro não foi encontrado no sistema.');
                return false;
            }
            if (!user.is_active) {
                this._warn('Conta bloqueada');
                this._showBlocked('Sua conta foi <strong>bloqueada</strong> pelo administrador.');
                return false;
            }

            // Check 2: System active?
            const sys = await _ssoFetch('v_sso_sistemas', {
                'select': 'id,nome,is_active',
                'slug': `eq.${this.appSlug}`
            });

            if (!sys) {
                this._log('Sistema não registrado — permitido');
                return { perfil: userData.perfil };
            }
            if (!sys.is_active) {
                this._showBlocked(`O sistema <strong>${sys.nome}</strong> foi desativado.`);
                return false;
            }

            // Check 3: Access active + get current profile
            const access = await _ssoFetch('v_sso_acesso', {
                'select': 'id,is_active,perfil_nome',
                'usuario_id': `eq.${userData.id}`,
                'sistema_id': `eq.${sys.id}`
            });

            if (!access) {
                this._showBlocked(`Você <strong>não tem acesso</strong> a <strong>${sys.nome}</strong>.`);
                return false;
            }
            if (!access.is_active) {
                this._showBlocked(`Seu acesso a <strong>${sys.nome}</strong> foi <strong>revogado</strong>.`);
                return false;
            }

            this._log('✓ Revalidação OK', { perfil: access.perfil_nome });
            return { perfil: access.perfil_nome || userData.perfil };

        } catch (err) {
            this._warn('Erro de rede — permitido por fallback', err.message);
            return { perfil: userData.perfil };
        }
    }

    // ═══ ACCESS DENIED SCREEN ═══
    _showBlocked(reason) {
        localStorage.removeItem(this.storageKey);
        const o = document.createElement('div');
        o.id = 'sge-access-denied';
        o.style.cssText = 'position:fixed;inset:0;z-index:99999;background:radial-gradient(ellipse at 50% 30%,#fef2f2,#fee2e2 60%,#fecaca);display:flex;flex-direction:column;align-items:center;justify-content:center;font-family:Inter,sans-serif';
        o.innerHTML = `<div style="background:#fff;border:1px solid rgba(214,69,69,.15);border-radius:16px;padding:40px;max-width:420px;width:90%;text-align:center;box-shadow:0 4px 18px rgba(214,69,69,.07)">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#d64545" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-bottom:16px"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            <h2 style="font-size:20px;font-weight:800;color:#d64545;margin-bottom:8px">Acesso Negado</h2>
            <p style="font-size:14px;color:#5a6676;line-height:1.6;margin-bottom:24px">${reason}<br><br>Contate o administrador do SGE Central.</p>
            <div style="display:flex;gap:10px;justify-content:center">
                <button onclick="window.history.back()" style="padding:10px 20px;background:#f3f4f6;border:1px solid #d1d5db;border-radius:8px;cursor:pointer;font-size:14px;color:#4b5563">← Voltar</button>
                <button onclick="localStorage.removeItem('${this.storageKey}');localStorage.removeItem('${this.versionKey}');window.location.reload()" style="padding:10px 20px;background:#d64545;color:#fff;border:none;border-radius:8px;cursor:pointer;font-size:14px;font-weight:600">Trocar Conta</button>
            </div></div>
            <div style="position:absolute;bottom:24px;font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:.05em">SGE Central — RBAC v5</div>`;
        document.body.appendChild(o);
    }

    // ═══ JWT DECODER ═══
    decodeToken(token) {
        try {
            if (!token || typeof token !== 'string') return null;
            const parts = token.split('.');
            if (parts.length < 2) return null;
            const b = parts[1];
            const json = decodeURIComponent(atob(b.replace(/-/g, '+').replace(/_/g, '/')).split('').map(c =>
                '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
            ).join(''));
            const payload = JSON.parse(json);
            if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
                this._warn('Token expirado');
                return null;
            }
            if (!payload.user || !payload.user.id) {
                this._warn('Token sem dados de usuário');
                return null;
            }
            return payload.user;
        } catch (e) {
            this._warn('Token corrompido', e.message);
            return null;
        }
    }

    // ═══ LOGOUT ═══
    logout() {
        this._log('Logout SSO');
        localStorage.removeItem(this.storageKey);
        localStorage.removeItem(this.versionKey);
        this.redirectToLogin();
    }

    // ═══ GET USER ═══
    getUser() {
        const t = localStorage.getItem(this.storageKey);
        return t ? this.decodeToken(t) : null;
    }
}

window.SgeAuthSDK = SgeAuthSDK;
