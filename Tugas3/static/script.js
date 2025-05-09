// static/script.js
document.addEventListener('DOMContentLoaded', () => {
        const loginForm = document.getElementById('loginForm');
        const registerForm = document.getElementById('registerForm');
        const messageForm = document.getElementById('messageForm');
        const responseMessageDiv = document.getElementById('responseMessage');
        const chatMessagesDiv = document.getElementById('chatMessages');
        const chatUsernameInput = document.getElementById('chatUsername');

        const API_BASE_URL = '/api';

        function displayMessage(message, isError = false) {
                if (responseMessageDiv) {
                        responseMessageDiv.textContent = message;
                        responseMessageDiv.className = isError ? 'message error-message' : 'message';
                        setTimeout(() => { responseMessageDiv.textContent = ''; responseMessageDiv.className = 'message'; }, 1000);
                }
        }

        // Restore username from localStorage for chat page
        if (chatUsernameInput && localStorage.getItem('chatUsername')) {
                chatUsernameInput.value = localStorage.getItem('chatUsername');
        }

        if (loginForm) {
                loginForm.addEventListener('submit', async (e) => {
                        e.preventDefault();
                        const username = loginForm.username.value;
                        const password = loginForm.password.value;
                        try {
                                const response = await fetch(`${API_BASE_URL}/login`, {
                                        method: 'POST',
                                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                                        body: new URLSearchParams({ username, password })
                                });
                                const data = await response.json();
                                if (response.ok) {
                                        displayMessage(data.message || 'Login successful!');
                                        localStorage.setItem('chatUsername', username); // Store username for chat
                                        // No automatic redirect, user can choose to go to chat
                                } else {
                                        displayMessage(data.detail || 'Login failed', true);
                                }
                        } catch (error) {
                                displayMessage('An error occurred during login.', true);
                        }
                });
        }

        if (registerForm) {
                registerForm.addEventListener('submit', async (e) => {
                        e.preventDefault();
                        const username = registerForm.username.value;
                        const password = registerForm.password.value;
                        try {
                                const response = await fetch(`${API_BASE_URL}/register`, {
                                        method: 'POST',
                                        headers: { 'Content-Type': 'application/json' },
                                        body: JSON.stringify({ username, password })
                                });
                                const data = await response.json();
                                if (response.ok) {
                                        displayMessage(data.message || 'Registration successful! Please login.');
                                } else {
                                        displayMessage(data.detail || 'Registration failed', true);
                                }
                        } catch (error) {
                                displayMessage('An error occurred during registration.', true);
                        }
                });
        }

        async function loadMessages() {
                if (!chatMessagesDiv) return;
                try {
                        const response = await fetch(`${API_BASE_URL}/messages`);
                        if (response.ok) {
                                const messages = await response.json();
                                chatMessagesDiv.innerHTML = ''; // Clear existing
                                messages.forEach(msg => {
                                        const messageElement = document.createElement('div');
                                        messageElement.classList.add('message-entry');
                                        messageElement.innerHTML = `
                            <span class="username">${msg.username}:</span>
                            <span class="content">${msg.content}</span>
                            <span class="timestamp">${new Date(msg.timestamp).toLocaleTimeString()}</span>
                        `;
                                        chatMessagesDiv.appendChild(messageElement);
                                });
                                chatMessagesDiv.scrollTop = chatMessagesDiv.scrollHeight;
                        } else {
                                displayMessage('Failed to load messages.', true);
                        }
                } catch (error) {
                        displayMessage('Error loading messages.', true);
                }
        }

        if (messageForm) {
                messageForm.addEventListener('submit', async (e) => {
                        e.preventDefault();
                        const username = chatUsernameInput.value.trim();
                        const content = document.getElementById('messageInput').value.trim();

                        if (!username) {
                                displayMessage('Please enter your name.', true);
                                return;
                        }
                        if (!content) {
                                displayMessage('Message cannot be empty.', true);
                                return;
                        }

                        localStorage.setItem('chatUsername', username); // Remember username

                        try {
                                const response = await fetch(`${API_BASE_URL}/messages`, {
                                        method: 'POST',
                                        headers: { 'Content-Type': 'application/json' },
                                        body: JSON.stringify({ username, content })
                                });
                                if (response.ok) {
                                        document.getElementById('messageInput').value = '';
                                        loadMessages();
                                } else {
                                        const data = await response.json();
                                        displayMessage(data.detail || 'Failed to send message.', true);
                                }
                        } catch (error) {
                                displayMessage('Error sending message.', true);
                        }
                });
        }

        // Initial load for chat page
        if (window.location.pathname.includes('chat.html')) {
                loadMessages();
                setInterval(loadMessages, 15000); // Refresh messages periodically
        }
});