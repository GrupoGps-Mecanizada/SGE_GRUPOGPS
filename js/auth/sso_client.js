/**
 * SGE IDENTITY PROVIDER (SSO) SDK v2
 * Ponte entre qualquer sistema satélite e a Central SGE.
 * 
 * MODOS DE OPERAÇÃO:
 *   1. SSO ATIVO: Redireciona para Central SGE para autenticação centralizada
 *   2. SSO BYPASS: Permite login local via Supabase Auth (quando Central não está pronta)
 * 
 * Para ativar o bypass, defina window.SGE_SSO_BYPASS = true ANTES de carregar este script.
 */

const SGE_CENTRAL_URL = window.SGE_CENTRAL_URL_OVERRIDE
    || "https://grupogps-mecanizada.github.io/SGE-CENTRAL";

const SGE_HEARTBEAT_URL = "https://mgcjidryrjqiceielmzp.supabase.co/functions/v1/sso-heartbeat";

class SgeAuthSDK {
    constructor(appSlug) {
        this.appSlug = appSlug;
        this.storageKey = `sge_token_${this.appSlug}`;
        this.pulseInterval = null;
        this.heartbeatEnabled = false; // Desabilitado até verificar disponibilidade
        this._log('SDK inicializado', { appSlug, bypass: this.isBypass() });
    }

    // ========== LOGGING ==========
    _log(msg, data) {
        const prefix = `[SGE SSO][${this.appSlug}]`;
        if (data) {
            console.log(`${prefix} ${msg}`, data);
        } else {
            console.log(`${prefix} ${msg}`);
        }
    }

    _warn(msg, data) {
        const prefix = `[SGE SSO][${this.appSlug}]`;
        if (data) {
            console.warn(`${prefix} ⚠ ${msg}`, data);
        } else {
            console.warn(`${prefix} ⚠ ${msg}`);
        }
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

    // ========== 2. CHECK AUTH ==========
    checkAuth() {
        this._log('Verificando autenticação...');

        // 2.1 Token recebido via URL (retornando do SSO)
        const urlParams = new URLSearchParams(window.location.search);
        const tokenFromUrl = urlParams.get('sso_token');

        if (tokenFromUrl) {
            this._log('Token SSO recebido via URL');
            localStorage.setItem(this.storageKey, tokenFromUrl);
            window.history.replaceState({}, document.title, window.location.pathname);
            this.startHeartbeat(tokenFromUrl);
            return this.decodeToken(tokenFromUrl);
        }

        // 2.2 Token do LocalStorage
        const tokenFromStorage = localStorage.getItem(this.storageKey);
        if (!tokenFromStorage) {
            this._log('Nenhum token encontrado');

            if (this.isBypass()) {
                this._log('BYPASS: permitindo login local');
                return null; // Não redireciona — permite login local
            }

            // SSO Ativo — mas verificar se Central está acessível primeiro
            this._warn('Sem token. Será redirecionado para Central SGE.');
            this.redirectToLogin();
            return null;
        }

        // 2.3 Decodificar e validar
        const userData = this.decodeToken(tokenFromStorage);
        if (!userData) {
            this._warn('Token inválido ou expirado. Limpando...');
            localStorage.removeItem(this.storageKey);

            if (this.isBypass()) {
                return null;
            }

            this.redirectToLogin();
            return null;
        }

        this._log('Autenticado via token SSO', { nome: userData.nome, perfil: userData.perfil });
        this.startHeartbeat(tokenFromStorage);
        return userData;
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

            // Valida expiração
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

    // ========== 4. HEARTBEAT ==========
    startHeartbeat(token) {
        if (this.pulseInterval) clearInterval(this.pulseInterval);

        // Teste de disponibilidade antes de iniciar heartbeat
        const ping = async () => {
            try {
                const response = await fetch(SGE_HEARTBEAT_URL, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                });

                if (response.ok) {
                    this.heartbeatEnabled = true;
                } else if (response.status === 401 || response.status === 403) {
                    this._warn(`Heartbeat recusado (${response.status}). Token pode ser inválido.`);
                } else {
                    this._warn(`Heartbeat falhou (${response.status})`);
                }
            } catch (err) {
                // Edge function não disponível — desabilitar heartbeat silenciosamente
                if (this.heartbeatEnabled) {
                    this._warn('Heartbeat indisponível. Edge Function não deployada. Desabilitando.');
                }
                this.heartbeatEnabled = false;
                clearInterval(this.pulseInterval);
                this.pulseInterval = null;
                return; // Não tenta mais
            }
        };

        ping(); // Primeiro teste
        this.pulseInterval = setInterval(() => {
            if (this.heartbeatEnabled) {
                ping();
            }
        }, 120000);
    }

    // ========== 5. LOGOUT ==========
    logout() {
        this._log('Logout executado');
        localStorage.removeItem(this.storageKey);
        if (this.pulseInterval) {
            clearInterval(this.pulseInterval);
            this.pulseInterval = null;
        }

        if (this.isBypass()) {
            window.location.reload();
            return;
        }

        this.redirectToLogin();
    }

    // ========== 6. ACCESS DENIED SCREEN ==========
    static showAccessDenied(systemName) {
        document.body.innerHTML = `
            <div style="
                position:fixed; inset:0;
                background: radial-gradient(ellipse at 50% 30%, #f1f5f9 0%, #e8edf5 60%, #dde4ef 100%);
                display:flex; flex-direction:column; align-items:center; justify-content:center;
                font-family: 'Inter', sans-serif; text-align:center; padding:40px;
            ">
                <div style="
                    background:#fff; border:1px solid rgba(214,69,69,0.15); border-radius:16px;
                    padding:40px; max-width:440px; width:100%;
                    box-shadow: 0 4px 18px rgba(214,69,69,0.08);
                ">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#d64545" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-bottom:16px;">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        <line x1="12" y1="8" x2="12" y2="12"/>
                        <line x1="12" y1="16" x2="12.01" y2="16"/>
                    </svg>
                    <h1 style="font-size:22px; font-weight:800; color:#d64545; margin-bottom:8px;">
                        Acesso Negado
                    </h1>
                    <p style="font-size:14px; color:#5a6676; line-height:1.6; margin-bottom:24px;">
                        Você <strong>não tem permissão</strong> para acessar o sistema
                        <strong style="color:#2d3748;">${systemName || 'solicitado'}</strong>.
                        <br><br>
                        Seu setor ou perfil não está autorizado. Entre em contato com o administrador
                        do SGE Central para solicitar acesso.
                    </p>
                    <div style="display:flex; gap:10px; justify-content:center;">
                        <button onclick="window.history.back()" style="
                            padding:10px 20px; background:#f0f2f5; border:1px solid #d8dce5;
                            border-radius:8px; color:#5a6676; font-size:13px; font-weight:600;
                            cursor:pointer; font-family:'Inter',sans-serif;
                        ">← Voltar</button>
                        <button onclick="localStorage.clear(); window.location.reload()" style="
                            padding:10px 20px; background:#4a7fd7; border:none;
                            border-radius:8px; color:#fff; font-size:13px; font-weight:600;
                            cursor:pointer; font-family:'Inter',sans-serif;
                        ">Trocar Conta</button>
                    </div>
                </div>
                <div style="
                    position:absolute; bottom:24px; font-size:11px; color:#94a3b8;
                    font-weight:500; letter-spacing:0.05em; text-transform:uppercase;
                ">
                    SGE Central — Controle de Acesso RBAC · Grupo GPS
                </div>
            </div>
        `;
    }
}

window.SgeAuthSDK = SgeAuthSDK;
