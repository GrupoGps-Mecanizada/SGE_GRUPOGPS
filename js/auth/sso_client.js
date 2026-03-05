/**
 * SGE IDENTITY PROVIDER (SSO) SDK v3
 * Ponte entre qualquer sistema satélite e a Central SGE.
 * 
 * FEATURES:
 *   1. SSO redirect → Central SGE para autenticação
 *   2. TOKEN REVALIDATION — verifica com servidor se usuário ainda está ativo
 *   3. BYPASS mode — login local via Supabase Auth (fallback)
 *   4. Heartbeat (desabilitado até edge function existir)
 * 
 * Para ativar o bypass, defina window.SGE_SSO_BYPASS = true ANTES de carregar este script.
 */

const SGE_CENTRAL_URL = window.SGE_CENTRAL_URL_OVERRIDE
    || "https://grupogps-mecanizada.github.io/SGE-CENTRAL";

const SGE_SSO_SUPABASE_URL = "https://mgcjidryrjqiceielmzp.supabase.co";
const SGE_SSO_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im1nY2ppZHJ5cmpxaWNlaWVsbXpwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzIxMjEwNzEsImV4cCI6MjA4NzY5NzA3MX0.UAKkzy5fMIkrlmnqz9E9KknUw9xhoYpa3f1ptRpOuAA";

class SgeAuthSDK {
    constructor(appSlug) {
        this.appSlug = appSlug;
        this.storageKey = `sge_token_${this.appSlug}`;
        this.pulseInterval = null;
        this._log('SDK v3 inicializado', { appSlug, bypass: this.isBypass() });
    }

    // ========== LOGGING ==========
    _log(msg, data) {
        const prefix = `[SGE SSO][${this.appSlug}]`;
        if (data) console.log(`${prefix} ${msg}`, data);
        else console.log(`${prefix} ${msg}`);
    }

    _warn(msg, data) {
        const prefix = `[SGE SSO][${this.appSlug}]`;
        if (data) console.warn(`${prefix} ⚠ ${msg}`, data);
        else console.warn(`${prefix} ⚠ ${msg}`);
    }

    // ========== BYPASS MODE ==========
    isBypass() {
        return window.SGE_SSO_BYPASS === true;
    }

    // ========== 1. REDIRECT TO LOGIN ==========
    redirectToLogin() {
        if (this.isBypass()) {
            this._log('BYPASS ativado — login local via Supabase Auth');
            return 'BYPASS';
        }

        const returnUrl = encodeURIComponent(window.location.href);
        const targetUrl = `${SGE_CENTRAL_URL}/?app_slug=${this.appSlug}&redirect=${returnUrl}`;
        this._log('Redirecionando para Central SGE', { targetUrl });
        window.location.href = targetUrl;
        return 'REDIRECT';
    }

    // ========== 2. CHECK AUTH (com revalidação server-side) ==========
    async checkAuth() {
        this._log('Verificando autenticação...');

        // 2.1 Token recebido via URL (retornando do SSO)
        const urlParams = new URLSearchParams(window.location.search);
        const tokenFromUrl = urlParams.get('sso_token');

        if (tokenFromUrl) {
            this._log('Token SSO recebido via URL — validando com servidor...');
            localStorage.setItem(this.storageKey, tokenFromUrl);
            window.history.replaceState({}, document.title, window.location.pathname);

            const userData = this.decodeToken(tokenFromUrl);
            if (!userData) {
                this._warn('Token da URL inválido');
                localStorage.removeItem(this.storageKey);
                this.redirectToLogin();
                return null;
            }

            // Validate with server immediately
            const valid = await this._revalidateWithServer(userData);
            if (!valid) {
                localStorage.removeItem(this.storageKey);
                return null; // _revalidateWithServer handles the UI
            }

            return userData;
        }

        // 2.2 Token from LocalStorage
        const tokenFromStorage = localStorage.getItem(this.storageKey);
        if (!tokenFromStorage) {
            this._log('Nenhum token encontrado');
            if (this.isBypass()) return null;
            this.redirectToLogin();
            return null;
        }

        // 2.3 Decode token
        const userData = this.decodeToken(tokenFromStorage);
        if (!userData) {
            this._warn('Token inválido ou expirado. Limpando...');
            localStorage.removeItem(this.storageKey);
            if (this.isBypass()) return null;
            this.redirectToLogin();
            return null;
        }

        // 2.4 REVALIDATE WITH SERVER — check if user is still active
        const valid = await this._revalidateWithServer(userData);
        if (!valid) {
            localStorage.removeItem(this.storageKey);
            return null;
        }

        this._log('✓ Autenticado e validado', { nome: userData.nome, perfil: userData.perfil });
        return userData;
    }

    // ========== 2.5 SERVER-SIDE REVALIDATION ==========
    async _revalidateWithServer(userData) {
        try {
            this._log('Revalidando com servidor...');

            // Create a Supabase client to query RBAC tables
            const rbacClient = window.supabase.createClient(SGE_SSO_SUPABASE_URL, SGE_SSO_ANON_KEY, {
                db: { schema: 'gps_compartilhado' }
            });

            // Check 1: Is the USER globally active?
            const { data: userRecord, error: userErr } = await rbacClient
                .from('sge_central_usuarios')
                .select('id, is_active')
                .eq('id', userData.id)
                .single();

            if (userErr || !userRecord) {
                this._warn('Usuário não encontrado no SGE Central');
                this._showAccessRevoked('Seu cadastro não foi encontrado no sistema de governança.');
                return false;
            }

            if (!userRecord.is_active) {
                this._warn('BLOQUEADO: Conta desativada pelo administrador');
                this._showAccessRevoked('Sua conta foi <strong>bloqueada</strong> pelo administrador do SGE Central.');
                return false;
            }

            // Check 2: Find the system
            const { data: sysRecord, error: sysErr } = await rbacClient
                .from('sge_central_sistemas')
                .select('id, nome, is_active')
                .eq('slug', this.appSlug)
                .single();

            if (sysErr || !sysRecord) {
                // System not registered — allow access (backward compatibility)
                this._log('Sistema não registrado no RBAC — acesso permitido por padrão');
                return true;
            }

            if (!sysRecord.is_active) {
                this._warn('Sistema desativado');
                this._showAccessRevoked(`O sistema <strong>${sysRecord.nome}</strong> foi desativado pelo administrador.`);
                return false;
            }

            // Check 3: Does the user have ACCESS to this system?
            const { data: accessRecord, error: accessErr } = await rbacClient
                .from('sge_central_usuario_sistema_acesso')
                .select('id, is_active')
                .eq('usuario_id', userData.id)
                .eq('sistema_id', sysRecord.id)
                .single();

            if (accessErr || !accessRecord) {
                this._warn('Sem registro de acesso para este sistema');
                this._showAccessRevoked(`Você <strong>não possui acesso</strong> ao sistema <strong>${sysRecord.nome}</strong>.`);
                return false;
            }

            if (!accessRecord.is_active) {
                this._warn('Acesso revogado pelo administrador');
                this._showAccessRevoked(`Seu acesso ao sistema <strong>${sysRecord.nome}</strong> foi <strong>revogado</strong>.`);
                return false;
            }

            this._log('✓ Revalidação OK — usuário ativo, acesso concedido');
            return true;

        } catch (err) {
            // Network error — allow access to avoid blocking on connectivity issues
            this._warn('Erro de rede na revalidação — acesso permitido por fallback', err.message);
            return true;
        }
    }

    // ========== ACCESS REVOKED SCREEN ==========
    _showAccessRevoked(reason) {
        this._warn('Exibindo tela de acesso revogado');
        localStorage.removeItem(this.storageKey);

        // Hide all app content and show access denied
        const appContent = document.getElementById('app') || document.body;
        const overlay = document.createElement('div');
        overlay.id = 'sge-access-denied';
        overlay.style.cssText = `
            position:fixed; inset:0; z-index:99999;
            background: radial-gradient(ellipse at 50% 30%, #fef2f2 0%, #fee2e2 60%, #fecaca 100%);
            display:flex; flex-direction:column; align-items:center; justify-content:center;
            font-family: 'Inter', sans-serif;
        `;
        overlay.innerHTML = `
            <div style="background:#fff; border:1px solid rgba(214,69,69,0.15); border-radius:16px; 
                        padding:40px; max-width:420px; width:90%; text-align:center;
                        box-shadow:0 4px 18px rgba(214,69,69,0.07);">
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#d64545" 
                     stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-bottom:16px;">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <line x1="12" y1="8" x2="12" y2="12"/>
                    <line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
                <h2 style="font-size:20px; font-weight:800; color:#d64545; margin-bottom:8px;">
                    Acesso Negado
                </h2>
                <p style="font-size:14px; color:#5a6676; line-height:1.6; margin-bottom:24px;">
                    ${reason}<br><br>
                    Entre em contato com o administrador do SGE Central.
                </p>
                <div style="display:flex; gap:10px; justify-content:center;">
                    <button onclick="window.history.back()" 
                            style="padding:10px 20px; background:#f3f4f6; border:1px solid #d1d5db; 
                                   border-radius:8px; cursor:pointer; font-size:14px; color:#4b5563;">
                        ← Voltar
                    </button>
                    <button onclick="localStorage.removeItem('${this.storageKey}'); window.location.reload();"
                            style="padding:10px 20px; background:#d64545; color:#fff; border:none; 
                                   border-radius:8px; cursor:pointer; font-size:14px; font-weight:600;">
                        Trocar Conta
                    </button>
                </div>
            </div>
            <div style="position:absolute; bottom:24px; font-size:11px; color:#94a3b8; 
                        text-transform:uppercase; letter-spacing:0.05em;">
                SGE Central — Controle de Acesso RBAC · Grupo GPS
            </div>
        `;
        document.body.appendChild(overlay);
    }

    // ========== 3. JWT DECODER ==========
    decodeToken(token) {
        try {
            const base64Url = token.split('.')[1];
            if (!base64Url) return null;
            const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
            const jsonPayload = decodeURIComponent(atob(base64).split('').map(c => {
                return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
            }).join(''));

            const payload = JSON.parse(jsonPayload);

            // Validate expiry
            if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
                this._warn('Token JWT expirado');
                return null;
            }

            return payload.user;
        } catch (e) {
            this._warn('Falha ao decodificar token', e);
            return null;
        }
    }

    // ========== 4. LOGOUT ==========
    logout() {
        this._log('Logout SSO');
        localStorage.removeItem(this.storageKey);
        if (this.pulseInterval) clearInterval(this.pulseInterval);
        this.redirectToLogin();
    }

    // ========== 5. GET USER ==========
    getUser() {
        const token = localStorage.getItem(this.storageKey);
        if (!token) return null;
        return this.decodeToken(token);
    }
}

// Expose globally
window.SgeAuthSDK = SgeAuthSDK;
