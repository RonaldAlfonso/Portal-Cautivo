const CONFIG = {
    apiBase: '',
    sessionTimeout: 3600,
    autoRefreshInterval: 30000
};

class Utils {
    static showLoading(button) {
        if (button) {
            const text = button.querySelector('.btn-text');
            const loader = button.querySelector('.btn-loader');
            if (text) text.style.display = 'none';
            if (loader) loader.style.display = 'inline-block';
            button.disabled = true;
        }
    }

    static hideLoading(button) {
        if (button) {
            const text = button.querySelector('.btn-text');
            const loader = button.querySelector('.btn-loader');
            if (text) text.style.display = 'inline-block';
            if (loader) loader.style.display = 'none';
            button.disabled = false;
        }
    }

    static showError(element, message) {
        if (element) {
            element.textContent = message;
            element.style.display = 'block';
            setTimeout(() => {
                element.style.display = 'none';
            }, 5000);
        }
    }

    static formatTime(seconds) {
        if (seconds < 60) return `${seconds} segundos`;
        if (seconds < 3600) return `${Math.floor(seconds / 60)} minutos`;
        return `${Math.floor(seconds / 3600)} horas`;
    }

    static formatDate(dateString) {
        if (!dateString || dateString === 'Never' || dateString === 'Nunca') return 'Nunca';
        try {
            const date = new Date(dateString);
            if (isNaN(date.getTime())) return 'Nunca';
            return date.toLocaleString('es-ES', {
                day: '2-digit',
                month: '2-digit',
                year: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
        } catch {
            return 'Nunca';
        }
    }
}

class SessionManager {
    static getSession() {
        const sessionData = localStorage.getItem('portal_session');
        return sessionData;
    }

    static setSession(data) {
        localStorage.setItem('portal_session', JSON.stringify(data));
    }

    static clearSession() {
        localStorage.removeItem('portal_session');
    }

    static isAdmin() {
        const session = this.getSession();
        if (!session) return false;
        try {
            const data = JSON.parse(session);
            return data.isAdmin === true;
        } catch {
            return false;
        }
    }
}

class LoginManager {
    static init() {
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', this.handleLogin.bind(this));
        }
    }

    static async handleLogin(e) {
        e.preventDefault();
        
        const form = e.target;
        const submitBtn = form.querySelector('button[type="submit"]');
        const errorElement = document.getElementById('errorMessage');
        
        const username = form.querySelector('#username').value;
        const password = form.querySelector('#password').value;
        
        Utils.showLoading(submitBtn);
        
        const formData = new URLSearchParams();
        formData.append('user', username);
        formData.append('pass', password);
        
        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: formData,
                credentials: 'include'
            });
            
            const data = await response.json();
            
            if (data.success) {
                SessionManager.setSession({
                    username: username,
                    isAdmin: data.is_admin,
                    timestamp: Date.now()
                });
                window.location.href = 'success.html';
            } else {
                Utils.showError(errorElement, data.error || 'Error de autenticación');
            }
        } catch (error) {
            console.error('Error en login:', error);
            Utils.showError(errorElement, 'Error de conexión. Intente nuevamente.');
        } finally {
            Utils.hideLoading(submitBtn);
        }
    }
}

class SuccessPage {
    static init() {
        console.log('Iniciando SuccessPage...');
        
        const session = SessionManager.getSession();
        
        if (!session) {
            console.log('No hay sesión en localStorage, verificando con servidor...');
            this.verifySession();
        } else {
            try {
                const data = JSON.parse(session);
                const elapsed = Math.floor((Date.now() - data.timestamp) / 1000);
                if (elapsed > CONFIG.sessionTimeout) {
                    console.log('Sesión expirada en localStorage');
                    SessionManager.clearSession();
                    this.verifySession();
                } else {
                    console.log('Sesión válida en localStorage');
                    this.setupPage();
                }
            } catch (e) {
                console.error('Error al parsear sesión:', e);
                this.verifySession();
            }
        }
    }

    static async verifySession() {
        console.log('Verificando sesión con servidor...');
        
        try {
            const response = await fetch('/api/verify-session', {
                method: 'POST',
                credentials: 'include'
            });
            
            const data = await response.json();
            console.log('Respuesta de verificación:', data);
            
            if (data.valid) {
                console.log('Sesión válida en servidor');
                SessionManager.setSession({
                    username: data.username,
                    isAdmin: data.is_admin,
                    timestamp: Date.now()
                });
                this.setupPage();
            } else {
                console.log('Sesión inválida, redirigiendo a login...');
                SessionManager.clearSession();
                window.location.href = 'index.html';
            }
        } catch (error) {
            console.error('Error al verificar sesión:', error);
            SessionManager.clearSession();
            window.location.href = 'index.html';
        }
    }

    static setupPage() {
        console.log('Configurando página de éxito...');
        
        const adminBtn = document.getElementById('adminBtn');
        const logoutBtn = document.getElementById('logoutBtn');
        const sessionTimer = null;

        if (adminBtn) {
            console.log('Admin button encontrado, verificando si es admin...');
            
            adminBtn.style.display = 'none';
            
            const session = SessionManager.getSession();
            if (session) {
                try {
                    const data = JSON.parse(session);
                    if (data.isAdmin) {
                        console.log('Es admin según localStorage');
                        adminBtn.style.display = 'flex';
                    }
                } catch (e) {
                    console.error('Error al parsear localStorage:', e);
                }
            }
            
            adminBtn.addEventListener('click', () => {
                window.location.href = 'admin.html';
            });
        }

        if (logoutBtn) {
            logoutBtn.addEventListener('click', async () => {
                try {
                    const response = await fetch('/api/logout', {
                        method: 'POST',
                        credentials: 'include'
                    });
                    
                    if (response.ok) {
                        SessionManager.clearSession();
                        window.location.href = 'index.html';
                    } else {
                        console.error('Error al cerrar sesión en servidor');
                        SessionManager.clearSession();
                        window.location.href = 'index.html';
                    }
                } catch (error) {
                    console.error('Error al cerrar sesión:', error);
                    SessionManager.clearSession();
                    window.location.href = 'index.html';
                }
            });
        }

        if (sessionTimer) {
            this.updateSessionTimer(sessionTimer);
            setInterval(() => {
                this.updateSessionTimer(sessionTimer);
            }, 60000);
        }
        
        console.log('Página de éxito configurada correctamente');
    }

    static updateSessionTimer(element) {
        const session = SessionManager.getSession();
        if (!session) return;

        try {
            const data = JSON.parse(session);
            const elapsed = Math.floor((Date.now() - data.timestamp) / 1000);
            const remaining = CONFIG.sessionTimeout - elapsed;
            
            if (remaining <= 0) {
                console.log('Sesión expiró, redirigiendo...');
                SessionManager.clearSession();
                window.location.href = 'index.html';
                return;
            }

            element.textContent = Utils.formatTime(remaining);
        } catch {
            element.textContent = 'Sesión activa';
        }
    }
}

class AdminPage {
    static init() {
        if (!SessionManager.isAdmin()) {
            window.location.href = 'success.html';
            return;
        }

        this.initNavigation();
        this.initUsersSection();
        this.initSessionsSection();
        this.initModals();
        this.initLogout();
        
        this.loadUsers();
        this.loadSessions();
    }

    static initNavigation() {
        const navItems = document.querySelectorAll('.nav-item[data-section]');
        navItems.forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                
                navItems.forEach(nav => nav.classList.remove('active'));
                item.classList.add('active');
                
                const sectionId = item.dataset.section;
                const sections = document.querySelectorAll('.content-section');
                sections.forEach(section => {
                    section.classList.remove('active');
                    if (section.id === `${sectionId}Section`) {
                        section.classList.add('active');
                    }
                });

                // Recargar datos al cambiar de sección
                if (sectionId === 'users') {
                    this.loadUsers();
                } else if (sectionId === 'sessions') {
                    this.loadSessions();
                }
            });
        });
    }

    static initUsersSection() {
        const newUserBtn = document.getElementById('newUserBtn');
        if (newUserBtn) {
            newUserBtn.addEventListener('click', () => {
                this.showNewUserModal();
            });
        }
    }

    static initSessionsSection() {
        setInterval(() => {
            const sessionsSection = document.getElementById('sessionsSection');
            if (sessionsSection && sessionsSection.classList.contains('active')) {
                this.loadSessions();
            }
        }, CONFIG.autoRefreshInterval);
    }

    static initModals() {
        const newUserModal = document.getElementById('newUserModal');
        const confirmModal = document.getElementById('confirmModal');
        const closeButtons = document.querySelectorAll('.modal-close, .modal-cancel');

        closeButtons.forEach(button => {
            button.addEventListener('click', () => {
                if (newUserModal) newUserModal.style.display = 'none';
                if (confirmModal) confirmModal.style.display = 'none';
            });
        });

        const createUserBtn = document.getElementById('createUserBtn');
        if (createUserBtn) {
            createUserBtn.addEventListener('click', () => {
                this.createNewUser();
            });
        }

        window.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal')) {
                e.target.style.display = 'none';
            }
        });
    }

    static initLogout() {
        const logoutBtn = document.getElementById('logoutBtn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', async () => {
                try {
                    const response = await fetch('/api/logout', {
                        method: 'POST',
                        credentials: 'include'
                    });
                    
                    if (response.ok) {
                        SessionManager.clearSession();
                        window.location.href = 'index.html';
                    } else {
                        console.error('Error al cerrar sesión en servidor');
                        SessionManager.clearSession();
                        window.location.href = 'index.html';
                    }
                } catch (error) {
                    console.error('Error al cerrar sesión:', error);
                    SessionManager.clearSession();
                    window.location.href = 'index.html';
                }
            });
        }
    }

    static showNewUserModal() {
        const modal = document.getElementById('newUserModal');
        const form = document.getElementById('newUserForm');
        
        if (form) form.reset();
        if (modal) modal.style.display = 'flex';
    }

    static async createNewUser() {
        const username = document.getElementById('newUsername').value.trim();
        const password = document.getElementById('newPassword').value;
        const confirmPassword = document.getElementById('confirmPassword').value;

        if (!username || !password) {
            alert('Por favor complete todos los campos');
            return;
        }

        if (password.length < 8) {
            alert('La contraseña debe tener al menos 8 caracteres');
            return;
        }

        if (password !== confirmPassword) {
            alert('Las contraseñas no coinciden');
            return;
        }

        const createBtn = document.getElementById('createUserBtn');
        Utils.showLoading(createBtn);

        try {
            const formData = new URLSearchParams();
            formData.append('username', username);
            formData.append('password', password);

            const response = await fetch('/api/users/create', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: formData,
                credentials: 'include'
            });

            const data = await response.json();

            if (data.success) {
                alert('Usuario creado exitosamente');
                document.getElementById('newUserModal').style.display = 'none';
                this.loadUsers();
            } else {
                alert(data.error || 'Error al crear usuario');
            }
        } catch (error) {
            console.error('Error creando usuario:', error);
            alert('Error de conexión al crear usuario');
        } finally {
            Utils.hideLoading(createBtn);
        }
    }

    static async loadUsers() {
        const tbody = document.getElementById('usersTableBody');
        if (!tbody) return;

        tbody.innerHTML = '<tr class="loading-row"><td colspan="4"><div class="loading-spinner">Cargando usuarios...</div></td></tr>';

        try {
            const response = await fetch('/api/users', {
                method: 'POST',
                credentials: 'include'
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const contentType = response.headers.get('content-type');
            if (!contentType || !contentType.includes('application/json')) {
                const text = await response.text();
                console.error('Respuesta no JSON:', text);
                throw new Error('El servidor no devolvió JSON válido');
            }

            const data = await response.json();
            
            if (data.error) {
                throw new Error(data.error);
            }

            this.renderUsersTable(data.users || []);
        } catch (error) {
            console.error('Error al cargar usuarios:', error);
            tbody.innerHTML = `
                <tr>
                    <td colspan="4" style="color: var(--danger); text-align: center; padding: 2rem;">
                        Error al cargar usuarios: ${error.message}
                    </td>
                </tr>
            `;
        }
    }

    static renderUsersTable(users) {
        const tbody = document.getElementById('usersTableBody');
        if (!tbody) return;

        if (!users || users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 2rem; color: var(--neutral-500);">No hay usuarios registrados</td></tr>';
            return;
        }

        tbody.innerHTML = '';

        users.forEach(user => {
            const row = document.createElement('tr');
            
            row.innerHTML = `
                <td>
                    <strong>${user.username}</strong>
                    ${user.username === 'admin' ? '<span style="color: var(--primary-blue); margin-left: 0.5rem;">(Admin)</span>' : ''}
                </td>
                <td>
                    <span class="status-badge ${user.is_active ? 'active' : 'inactive'}">
                        ${user.is_active ? 'Activo' : 'Inactivo'}
                    </span>
                </td>
                <td>${Utils.formatDate(user.last_login)}</td>
                <td>
                    <div class="table-actions">
                        <button class="action-btn toggle" title="${user.is_active ? 'Desactivar' : 'Activar'}" data-user="${user.username}" data-active="${user.is_active}">
                            <i class="fas fa-power-off"></i>
                        </button>
                        ${user.username !== 'admin' ? `
                            <button class="action-btn delete" title="Eliminar" data-user="${user.username}">
                                <i class="fas fa-trash"></i>
                            </button>
                        ` : ''}
                    </div>
                </td>
            `;

            tbody.appendChild(row);
        });

        this.bindUserActions();
    }

    static bindUserActions() {
        document.querySelectorAll('.action-btn.toggle').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const username = e.currentTarget.dataset.user;
                const isActive = e.currentTarget.dataset.active === 'true';
                await this.toggleUserStatus(username, isActive);
            });
        });

        document.querySelectorAll('.action-btn.delete').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const username = e.currentTarget.dataset.user;
                this.confirmDeleteUser(username);
            });
        });
    }

    static async toggleUserStatus(username, isCurrentlyActive) {
        try {
            const action = isCurrentlyActive ? 'deactivate' : 'activate';
            const formData = new URLSearchParams();
            formData.append('username', username);

            const response = await fetch(`/api/users/${action}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: formData,
                credentials: 'include'
            });

            const data = await response.json();

            if (data.success) {
                alert(data.message || `Usuario ${isCurrentlyActive ? 'desactivado' : 'activado'} exitosamente`);
                this.loadUsers();
            } else {
                alert(data.error || 'Error al cambiar estado del usuario');
            }
        } catch (error) {
            console.error('Error al cambiar estado:', error);
            alert('Error de conexión al cambiar estado del usuario');
        }
    }

    static confirmDeleteUser(username) {
        const modal = document.getElementById('confirmModal');
        const message = document.getElementById('confirmMessage');
        const confirmBtn = document.getElementById('confirmActionBtn');
        
        message.textContent = `¿Está seguro de eliminar al usuario "${username}"?`;
        
        confirmBtn.onclick = () => {
            this.deleteUser(username);
            modal.style.display = 'none';
        };
        
        modal.style.display = 'flex';
    }

    static async deleteUser(username) {
        try {
            const formData = new URLSearchParams();
            formData.append('username', username);

            const response = await fetch('/api/users/delete', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: formData,
                credentials: 'include'
            });

            const data = await response.json();

            if (data.success) {
                alert('Usuario eliminado exitosamente');
                this.loadUsers();
            } else {
                alert(data.error || 'Error al eliminar usuario');
            }
        } catch (error) {
            console.error('Error al eliminar usuario:', error);
            alert('Error de conexión al eliminar usuario');
        }
    }

    static async loadSessions() {
        const tbody = document.getElementById('sessionsTableBody');
        if (!tbody) return;

        tbody.innerHTML = '<tr class="loading-row"><td colspan="5"><div class="loading-spinner">Cargando sesiones...</div></td></tr>';

        try {
            const response = await fetch('/api/sessions', {
                method: 'POST',
                credentials: 'include'
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const contentType = response.headers.get('content-type');
            if (!contentType || !contentType.includes('application/json')) {
                const text = await response.text();
                console.error('Respuesta no JSON:', text);
                throw new Error('El servidor no devolvió JSON válido');
            }

            const data = await response.json();
            
            if (data.error) {
                throw new Error(data.error);
            }

            this.renderSessionsTable(data.sessions || []);
        } catch (error) {
            console.error('Error al cargar sesiones:', error);
            tbody.innerHTML = `
                <tr>
                    <td colspan="5" style="color: var(--danger); text-align: center; padding: 2rem;">
                        Error al cargar sesiones: ${error.message}
                    </td>
                </tr>
            `;
        }
    }

    static renderSessionsTable(sessions) {
        const tbody = document.getElementById('sessionsTableBody');
        if (!tbody) return;

        if (!sessions || sessions.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 2rem; color: var(--neutral-500);">No hay sesiones activas</td></tr>';
            return;
        }

        tbody.innerHTML = '';

        sessions.forEach(session => {
            const row = document.createElement('tr');
            const created = new Date(session.created_at);
            const expires = new Date(session.expires_at);
            const expiresIn = Math.max(0, Math.floor((expires.getTime() - Date.now()) / 1000));
            
            row.innerHTML = `
                <td><strong>${session.username}</strong></td>
                <td><code>${session.client_ip}</code></td>
                <td>${created.toLocaleString('es-ES', { 
                    day: '2-digit', 
                    month: '2-digit', 
                    year: 'numeric',
                    hour: '2-digit', 
                    minute: '2-digit' 
                })}</td>
                <td>${Utils.formatTime(expiresIn)}</td>
                <td>
                    <div class="table-actions">
                        <button class="action-btn delete" title="Terminar sesión" data-session="${session.session_id}">
                            <i class="fas fa-times-circle"></i>
                        </button>
                    </div>
                </td>
            `;

            tbody.appendChild(row);
        });

        document.querySelectorAll('.action-btn.delete[data-session]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const sessionId = e.currentTarget.dataset.session;
                this.terminateSession(sessionId);
            });
        });
    }

    static async terminateSession(sessionId) {
        if (!confirm('¿Está seguro de terminar esta sesión?')) {
            return;
        }

        try {
            const formData = new URLSearchParams();
            formData.append('session_id', sessionId);

            const response = await fetch('/api/sessions/terminate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: formData,
                credentials: 'include'
            });

            const data = await response.json();

            if (data.success) {
                alert('Sesión terminada exitosamente');
                this.loadSessions();
            } else {
                alert(data.error || 'Error al terminar sesión');
            }
        } catch (error) {
            console.error('Error al terminar sesión:', error);
            alert('Error de conexión al terminar sesión');
        }
    }
}

// Inicialización al cargar el DOM
document.addEventListener('DOMContentLoaded', () => {
    const path = window.location.pathname;
    const page = path.split('/').pop() || 'index.html';

    CONFIG.apiBase = window.location.origin;

    console.log('Página detectada:', page);

    switch(page) {
        case 'index.html':
        case '':
            LoginManager.init();
            break;
        case 'success.html':
            SuccessPage.init();
            break;
        case 'admin.html':
            AdminPage.init();
            break;
    }

    document.body.classList.add(page.replace('.html', '-page'));
});