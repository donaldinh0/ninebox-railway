// public/script.js
document.addEventListener('DOMContentLoaded', () => {
    // Funções auxiliares para buscar dados da API
    async function fetchData(url, options = {}) {
        const response = await fetch(url, options);
        if (!response.ok) {
            throw new Error(await response.text() || 'Erro na requisição');
        }
        return response.json();
    }

    async function postData(url, data) {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        if (!response.ok) {
            throw new Error(await response.text() || 'Erro na requisição');
        }
        return response.text();
    }

    // --- Lógica para a página de Login ---
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(loginForm);
            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    body: new URLSearchParams(formData)
                });
                if (response.ok) {
                    window.location.href = response.url;
                } else {
                    document.getElementById('login-message').textContent = await response.text();
                }
            } catch (err) {
                document.getElementById('login-message').textContent = err.message;
            }
        });

        const showChangePasswordBtn = document.getElementById('show-change-password');
        const changePasswordContainer = document.getElementById('password-change-container');
        const changePasswordForm = document.getElementById('change-password-form');
        const cpMessage = document.getElementById('cp-message');

        showChangePasswordBtn.addEventListener('click', () => {
            changePasswordContainer.style.display = changePasswordContainer.style.display === 'none' ? 'block' : 'none';
        });

        changePasswordForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('cp-username').value;
            const currentPassword = document.getElementById('cp-current-password').value;
            const newPassword = document.getElementById('cp-new-password').value;
            const confirmNewPassword = document.getElementById('cp-confirm-new-password').value;

            if (newPassword !== confirmNewPassword) {
                cpMessage.textContent = 'As novas senhas não coincidem.';
                cpMessage.style.color = 'red';
                return;
            }

            try {
                const messageText = await postData('/api/change-password-login', { username, currentPassword, newPassword });
                cpMessage.textContent = messageText;
                cpMessage.style.color = 'green';
                changePasswordForm.reset();
            } catch (err) {
                cpMessage.textContent = err.message;
                cpMessage.style.color = 'red';
            }
        });
    }

    // --- Lógica para a página de Dashboard (Usuário Comum) ---
    const dashboardContainer = document.querySelector('.dashboard-container');
    if (dashboardContainer) {
        const scoreToNineBoxName = {
            1: "B1 Insuficiente", 2: "B2 Eficaz", 3: "B3 Comprometido",
            4: "M1 Questionável", 5: "M2 Mantenedor", 6: "M3 Forte Desempenho",
            7: "A1 Profissional Enigma", 8: "A2 Profissional em Crescimento", 9: "A3 Profissional em Destaque"
        };
        
        async function loadDashboardData() {
            try {
                const userData = await fetchData('/api/my-score');
                document.getElementById('user-name').textContent = userData.username;

                const nineBoxScore = parseInt(userData.nineBoxScore, 10);
                if (nineBoxScore && nineBoxScore >= 1 && nineBoxScore <= 9) {
                    const currentBox = document.getElementById(`box-${nineBoxScore}`);
                    if (currentBox) {
                        currentBox.classList.add('active');
                    }
                    const positionText = document.getElementById('nine-box-current-text');
                    if (positionText) {
                        positionText.textContent = scoreToNineBoxName[nineBoxScore];
                    }
                } else {
                    const positionText = document.getElementById('nine-box-current-text');
                    if (positionText) {
                        positionText.textContent = 'Nenhuma posição definida.';
                    }
                }

                const notesText = document.getElementById('notes-text');
                if (notesText) {
                    notesText.textContent = userData.notes || 'Nenhuma observação no momento.';
                }

            } catch (err) {
                console.error("Erro ao carregar dados do dashboard:", err);
                // Exibe mensagens de erro nas seções apropriadas
            }
        }
        
        loadDashboardData();
    }

    // --- Lógica para a página de Admin ---
    const adminContainer = document.querySelector('.admin-container');
    if (adminContainer) {
        const scoreToNineBoxName = {
            1: "B1 Insuficiente", 2: "B2 Eficaz", 3: "B3 Comprometido",
            4: "M1 Questionável", 5: "M2 Mantenedor", 6: "M3 Forte Desempenho",
            7: "A1 Profissional Enigma", 8: "A2 Profissional em Crescimento", 9: "A3 Profissional em Destaque"
        };
        
        // Função para carregar os textos do Nine Box para edição
        async function loadNineBoxTextsForAdmin() {
            try {
                const texts = await fetchData('/api/nine-box-texts');
                for (let i = 1; i <= 9; i++) {
                    const textarea = document.getElementById(`edit-box-${i}`);
                    if (textarea) {
                        textarea.value = texts[String(i)] || '';
                    }
                }
            } catch (err) {
                console.error("Erro ao carregar textos das caixas:", err);
            }
        }
        
        // Função para salvar os textos do Nine Box
        const saveBoxTextsBtn = document.getElementById('save-box-texts');
        if (saveBoxTextsBtn) {
            saveBoxTextsBtn.addEventListener('click', async () => {
                const saveTextsMessage = document.getElementById('save-texts-message');
                const texts = {};
                for (let i = 1; i <= 9; i++) {
                    const textarea = document.getElementById(`edit-box-${i}`);
                    texts[String(i)] = textarea.value;
                }
                
                try {
                    const message = await postData('/api/update-nine-box-texts', { texts });
                    saveTextsMessage.textContent = message;
                    saveTextsMessage.style.color = 'green';
                } catch (err) {
                    saveTextsMessage.textContent = err.message;
                    saveTextsMessage.style.color = 'red';
                }
            });
        }
        
        function loadScores() {
            const loadingMessage = document.getElementById('loading-message');
            loadingMessage.style.display = 'block';
            loadingMessage.textContent = 'Carregando...';

            fetch('/api/all-scores')
                .then(res => {
                    if (!res.ok) {
                        throw new Error('Não autorizado');
                    }
                    return res.json();
                })
                .then(users => {
                    const tableBody = document.getElementById('user-scores-body');
                    tableBody.innerHTML = '';
                    if (users && users.length > 0) {
                        loadingMessage.style.display = 'none';
                        users.forEach(user => {
                            const row = document.createElement('tr');
                            
                            const selectElement = document.createElement('select');
                            selectElement.setAttribute('data-user-id', user.id);
                            for (let i = 1; i <= 9; i++) {
                                const option = document.createElement('option');
                                option.value = i;
                                option.textContent = scoreToNineBoxName[i];
                                if (i === user.nineBoxScore) {
                                    option.selected = true;
                                }
                                selectElement.appendChild(option);
                            }
                            
                            const notesTextarea = document.createElement('textarea');
                            notesTextarea.setAttribute('data-user-id', user.id);
                            notesTextarea.value = user.notes || '';

                            row.innerHTML = `
                                <td>${user.username}</td>
                                <td>${scoreToNineBoxName[user.nineBoxScore] || 'N/A'}</td>
                                <td class="new-score-cell"></td>
                                <td class="notes-cell"></td>
                                <td class="action-cell">
                                    <button class="update-button" data-user-id="${user.id}">Atualizar</button>
                                    <button class="delete-button" data-user-id="${user.id}">Deletar</button>
                                </td>
                            `;
                            row.querySelector('.new-score-cell').appendChild(selectElement);
                            row.querySelector('.notes-cell').appendChild(notesTextarea);
                            tableBody.appendChild(row);
                        });
                    } else {
                        loadingMessage.textContent = 'Nenhum usuário encontrado.';
                    }

                    document.querySelectorAll('.update-button').forEach(button => {
                        button.addEventListener('click', async (e) => {
                            const userId = e.target.dataset.userId;
                            const scoreSelect = document.querySelector(`select[data-user-id="${userId}"]`);
                            const notesTextarea = document.querySelector(`textarea[data-user-id="${userId}"]`);
                            
                            const nineBoxScore = scoreSelect.value;
                            const notes = notesTextarea.value;

                            try {
                                const message = await postData('/api/update-score', { userId, nineBoxScore, notes });
                                alert(message);
                                loadScores();
                            } catch (err) {
                                alert(err.message);
                            }
                        });
                    });
                    
                    document.querySelectorAll('.delete-button').forEach(button => {
                        button.addEventListener('click', async (e) => {
                            const userId = e.target.dataset.userId;
                            if (confirm('Tem certeza que deseja deletar este usuário?')) {
                                try {
                                    const response = await fetch(`/api/delete-user/${userId}`, { method: 'DELETE' });
                                    if (response.ok) {
                                        alert('Usuário deletado com sucesso!');
                                        loadScores();
                                    } else {
                                        throw new Error(await response.text());
                                    }
                                } catch (err) {
                                    alert(err.message);
                                }
                            }
                        });
                    });
                })
                .catch(err => {
                    console.error("Erro ao carregar a lista de usuários:", err);
                    loadingMessage.textContent = 'Erro ao carregar os dados.';
                });
        }
        
        loadScores();
        loadNineBoxTextsForAdmin();

        const createUserForm = document.getElementById('create-user-form');
        const createUserMessage = document.getElementById('create-user-message');

        createUserForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('new-user-username').value;
            const password = document.getElementById('new-user-password').value;

            try {
                const messageText = await postData('/api/create-user', { username, password });
                createUserMessage.textContent = messageText;
                createUserMessage.style.color = 'green';
                createUserForm.reset();
                loadScores();
            } catch (err) {
                createUserMessage.textContent = err.message;
                createUserMessage.style.color = 'red';
            }
        });
    }
});

// Adiciona a lógica para os novos formulários de senha
document.addEventListener('DOMContentLoaded', () => {
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
            messageEl.style.color = response.ok ? '#22c55e' : '#ef4444'; // Verde para sucesso, vermelho para erro
        });
    }

    if (resetPasswordForm) {
        const messageEl = resetPasswordForm.parentElement.querySelector('#message');
        // Pega o token da URL da página
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
                setTimeout(() => window.location.href = '/', 2500); // Redireciona para o login após o sucesso
            }
        });
    }
});