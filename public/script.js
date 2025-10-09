document.addEventListener('DOMContentLoaded', () => {

    // --- LÓGICA PARA A PÁGINA DE ADMIN ---
    const userScoresBody = document.getElementById('user-scores-body');
    const createUserForm = document.getElementById('create-user-form');
    
    // Função para carregar os usuários no painel de admin
    const loadUsers = async () => {
        if (!userScoresBody) return;
        
        try {
            const response = await fetch('/api/all-scores');
            if (!response.ok) throw new Error('Falha ao carregar usuários.');
            
            const users = await response.json();
            userScoresBody.innerHTML = ''; // Limpa a tabela antes de preencher

            users.forEach(user => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${user.username}</td>
                    <td>
                        <select class="nine-box-select" data-user-id="${user.id}">
                            <option value="0" ${user.nineBoxScore == 0 ? 'selected' : ''}>N/A</option>
                            <option value="1" ${user.nineBoxScore == 1 ? 'selected' : ''}>1 - Insuficiente</option>
                            <option value="2" ${user.nineBoxScore == 2 ? 'selected' : ''}>2 - Eficaz</option>
                            <option value="3" ${user.nineBoxScore == 3 ? 'selected' : ''}>3 - Comprometido</option>
                            <option value="4" ${user.nineBoxScore == 4 ? 'selected' : ''}>4 - Questionável</option>
                            <option value="5" ${user.nineBoxScore == 5 ? 'selected' : ''}>5 - Mantenedor</option>
                            <option value="6" ${user.nineBoxScore == 6 ? 'selected' : ''}>6 - Forte Desempenho</option>
                            <option value="7" ${user.nineBoxScore == 7 ? 'selected' : ''}>7 - Enigma</option>
                            <option value="8" ${user.nineBoxScore == 8 ? 'selected' : ''}>8 - Em Crescimento</option>
                            <option value="9" ${user.nineBoxScore == 9 ? 'selected' : ''}>9 - Destaque</option>
                        </select>
                    </td>
                    <td>
                        <textarea class="notes-textarea" data-user-id="${user.id}" rows="3">${user.notes || ''}</textarea>
                    </td>
                    <td>
                        <button class="update-button" data-user-id="${user.id}">Salvar</button>
                        <button class="delete-button" data-user-id="${user.id}">Excluir</button>
                    </td>
                `;
                userScoresBody.appendChild(row);
            });
        } catch (error) {
            console.error(error);
            userScoresBody.innerHTML = '<tr><td colspan="4">Erro ao carregar usuários.</td></tr>';
        }
    };

    // Event listener para os botões de Salvar e Excluir
    if (userScoresBody) {
        userScoresBody.addEventListener('click', async (e) => {
            const userId = e.target.dataset.userId;
            if (!userId) return;

            // Ação de SALVAR
            if (e.target.classList.contains('update-button')) {
                const select = document.querySelector(`.nine-box-select[data-user-id='${userId}']`);
                const textarea = document.querySelector(`.notes-textarea[data-user-id='${userId}']`);
                
                const response = await fetch('/api/update-score', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        userId: userId,
                        nineBoxScore: select.value,
                        notes: textarea.value
                    })
                });

                if (response.ok) {
                    alert('Usuário atualizado com sucesso!');
                } else {
                    alert('Falha ao atualizar usuário.');
                }
            }

            // Ação de EXCLUIR
            if (e.target.classList.contains('delete-button')) {
                if (confirm('Tem certeza que deseja excluir este usuário? Esta ação não pode ser desfeita.')) {
                    const response = await fetch(`/api/delete-user/${userId}`, {
                        method: 'DELETE'
                    });

                    if (response.ok) {
                        alert('Usuário excluído com sucesso!');
                        loadUsers(); // Recarrega a lista
                    } else {
                        alert('Falha ao excluir usuário.');
                    }
                }
            }
        });
    }

    // Event listener para CRIAR usuário
    if (createUserForm) {
        createUserForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('new-username').value;
            const email = document.getElementById('new-email').value;
            const password = document.getElementById('new-password').value;
            const messageEl = document.getElementById('create-user-message');

            const response = await fetch('/api/create-user', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, email, password })
            });

            const resultText = await response.text();
            messageEl.textContent = resultText;
            messageEl.style.color = response.ok ? 'green' : 'red';

            if (response.ok) {
                createUserForm.reset();
                loadUsers(); // Recarrega a lista de usuários
            }
        });
    }

    // Carrega os usuários quando a página de admin é aberta
    if (window.location.pathname.endsWith('/admin') || window.location.pathname.endsWith('/admin.html')) {
        loadUsers();
    }
    
    // --- LÓGICA PARA AS PÁGINAS DE RECUPERAÇÃO DE SENHA ---
    const forgotPasswordForm = document.getElementById('forgot-password-form');
    const resetPasswordForm = document.getElementById('reset-password-form');
    
    if (forgotPasswordForm) {
        const messageEl = forgotPasswordForm.parentElement.querySelector('#message');
        forgotPasswordForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('email').value;
            messageEl.textContent = 'Enviando, aguarde...';
            messageEl.style.color = '#9ca3af';

            const response = await fetch('/api/forgot-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email })
            });

            messageEl.textContent = await response.text();
            messageEl.style.color = response.ok ? '#22c55e' : '#ef4444';
        });
    }

    if (resetPasswordForm) {
        const messageEl = resetPasswordForm.parentElement.querySelector('#message');
        const urlParams = new URLSearchParams(window.location.search);
        const token = urlParams.get('token');

        resetPasswordForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const newPassword = document.getElementById('new-password').value;
            const confirmPassword = document.getElementById('confirm-password').value;

            if (newPassword !== confirmPassword) {
                messageEl.textContent = 'As senhas não coincidem.';
                messageEl.style.color = '#ef4444';
                return;
            }
            
            messageEl.textContent = 'Salvando nova senha...';
            messageEl.style.color = '#9ca3af';

            const response = await fetch('/api/reset-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token, newPassword })
            });
            
            const resultText = await response.text();
            messageEl.textContent = resultText;
            messageEl.style.color = response.ok ? '#22c55e' : '#ef4444';

            if (response.ok) {
                setTimeout(() => window.location.href = '/', 2500);
            }
        });
    }
});