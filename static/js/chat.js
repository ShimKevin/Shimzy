document.addEventListener('DOMContentLoaded', () => {
    const socket = io();
    
    // Chat functionality
    const messageForm = document.getElementById('message-form');
    const messageInput = document.getElementById('message-input');
    
    messageForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const message = messageInput.value.trim();
        if (message) {
            socket.emit('send_message', { message });
            messageInput.value = '';
        }
    });
    
    socket.on('receive_message', (data) => {
        // Add message to chat UI
    });
});