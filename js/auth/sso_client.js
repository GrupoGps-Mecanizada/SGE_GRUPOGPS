/**
 * SGE IDENTITY PROVIDER (SSO) SDK
 * Funciona como a ponte entre o aplicativo satélite e a Central SGE.
 * Pode ser injetado em qualquer projeto (Urbana, Mecanizada, Gesta De Força, etc.)
 */

// Usando o path de arquivo local para simular o roteamento na máquina
const SGE_CENTRAL_URL = "file:///c:/Users/Warlison Abreu/Desktop/CODIGOS/SGE_Central";

class SgeAuthSDK {
    constructor(appSlug) {
        this.appSlug = appSlug;
        this.storageKey = `sge_token_${this.appSlug}`;
        this.pulseInterval = null;
    }

    // 1. Redireciona o usuário para o hub caso ele não tenha token
    redirectToLogin() {
        // Redireciona o usuário para passar pela "catraca" do Painel Master
        const returnUrl = encodeURIComponent(window.location.href);
        window.location.href = `${SGE_CENTRAL_URL}/sso_login.html?app_slug=${this.appSlug}&redirect=${returnUrl}`;
    }

    // 2. Checa se já existe um token válido (retornado por query param ou localstorage)
    checkAuth() {
        // 2.1 Verifica se acabou de voltar do sso_login.html (Vem via GET "?token=xxxxx")
        const urlParams = new URLSearchParams(window.location.search);
        const tokenFromUrl = urlParams.get('sso_token');

        if (tokenFromUrl) {
            // Salva e limpa a URL para ficar elegante
            localStorage.setItem(this.storageKey, tokenFromUrl);
            window.history.replaceState({}, document.title, window.location.pathname);
            this.startHeartbeat(tokenFromUrl);
            return this.decodeToken(tokenFromUrl);
        }

        // 2.2 Tenta recuperar do LocalStorage
        const tokenFromStorage = localStorage.getItem(this.storageKey);
        if (!tokenFromStorage) {
            this.redirectToLogin();
            return null;
        }

        // 2.3 Em ambiente de produção, deveríamos consultar o Supabase Edge Functions para ver se o token inspirou, mas decodificamos localmente para economizar tráfego
        const userData = this.decodeToken(tokenFromStorage);
        if (!userData) {
            this.redirectToLogin();
            return null;
        }

        this.startHeartbeat(tokenFromStorage);
        return userData;
    }

    // 3. Simulação de um Decoder de JWT muito simples (Sem bibliotecas no client-side)
    decodeToken(token) {
        try {
            const base64Url = token.split('.')[1];
            const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
            const jsonPayload = decodeURIComponent(atob(base64).split('').map(function (c) {
                return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
            }).join(''));

            const payload = JSON.parse(jsonPayload);

            // Valida Expiração
            if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
                console.warn("SGE AUTH: Token JWT expirou.");
                return null;
            }
            return payload.user;

        } catch (e) {
            return null;
        }
    }

    // 4. HEARTBEAT (O Pulso que avisa o SGE CENTRAL que estamos ONLINE)
    startHeartbeat(token) {
        if (this.pulseInterval) clearInterval(this.pulseInterval);

        // Bater na Edge Function do Supabase a cada 2 MINUTOS
        // Avisando: "O usuário X continua ativo na guia aberta do aplicativo Y"
        const ping = async () => {
            try {
                const response = await fetch("https://mgcjidryrjqiceielmzp.supabase.co/functions/v1/sso-heartbeat", {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                });

                if (!response.ok) {
                    console.warn(`[SGE SSO] Heartbeat falhou. Status: ${response.status}`);
                    // Se der 401 ou 403, pode logar o usuário para fora por segurança em atualizações futuras
                }
            } catch (err) {
                console.warn(`[SGE SSO] Erro de rede no Heartbeat.`);
            }
        };

        ping(); // Envia o 1º de cara
        this.pulseInterval = setInterval(ping, 120000); // 2 Minutos = 120.000 ms
    }

    // 5. Logout
    logout() {
        localStorage.removeItem(this.storageKey);
        if (this.pulseInterval) clearInterval(this.pulseInterval);
        this.redirectToLogin();
    }
}

// Expõe para janela global (Apropriado caso se use direto nos index.html do GPS)
window.SgeAuthSDK = SgeAuthSDK;
