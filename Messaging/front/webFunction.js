document.addEventListener('DOMContentLoaded', () => {
    const clientId='uniqueClientId';
    const messageInput = document.getElementById('messageInput');
    const sendButton = document.getElementById('sendButton');
    const recipientInput = document.getElementById('recipientInput');
    const messagesContainer = document.getElementById('messages');
    const sentCiphertextDisplay = document.getElementById('sentCiphertext');
    const receivedCiphertextDisplay = document.getElementById('receivedCiphertext');
    const decryptedTextDisplay = document.getElementById('decryptedText');
    const toggleButton = document.getElementById('toggleEncryption');

    let showEncrypted = false;
    const messageHistory = [];
    let currentRecipient = '';

    // Handle recipient path
    recipientInput.addEventListener('change', () => {
        currentRecipient = recipientInput.value.trim();
        if (currentRecipient) {
            // Clear message history when changing recipients
            messageHistory.length = 0;
            updateChatDisplay();
            // Notify server of recipient change
            ws.send(JSON.stringify({
                type: 'recipient_change',
                recipientId: currentRecipient
            }));
        }
    });

    // non working WebSocket connection to our backend
    const ws = new WebSocket('wss://localhost:49250');

    ws.onopen = () => {
        console.log('Connected to server');
        ws.send(JSON.stringify({type:'init', clientId: clientId}));
    };

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        
        // Display received message
        if (data.type === 'message') {
            // Store message in history
            messageHistory.push({
                plaintext: data.plaintext,
                ciphertext: data.ciphertext,
                isReceived: true
            });

            // Update chat display
            updateChatDisplay();

            // Display ciphertext and decrypted text
            receivedCiphertextDisplay.textContent = data.ciphertext;
            decryptedTextDisplay.textContent = data.plaintext;
        }
    };

    ws.onerror = (error) => {
        console.error('WebSocket error:', error);
    };

    ws.onclose = () => {
        console.log('Disconnected from server');
    };

    // Toggle button click handler
    toggleButton.addEventListener('click', () => {
        showEncrypted = !showEncrypted;
        toggleButton.textContent = showEncrypted ? 'Show Decrypted' : 'Show Encrypted';
        toggleButton.classList.toggle('active');
        updateChatDisplay();
    });

    // Function to update the chat display based on current toggle state (showEncrypted/showPlaintext)
    function updateChatDisplay() {
        messagesContainer.innerHTML = '';
        messageHistory.forEach(msg => {
            const messageElement = document.createElement('div');
            messageElement.className = `message ${msg.isReceived ? 'received' : 'sent'}`;
            messageElement.textContent = showEncrypted ? msg.ciphertext : msg.plaintext;
            messagesContainer.appendChild(messageElement);
        });
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    // Send message
    sendButton.addEventListener('click', () => {
        const message = messageInput.value.trim();
        if (message && currentRecipient) {
            // Send message to server
            ws.send(JSON.stringify({
                type: 'message',
                recipientId: currentRecipient,
                content: message
            }));

            // Store sent message in history
            messageHistory.push({
                plaintext: message,
                ciphertext: '', // This is what is updated when we receive the ciphertext from the server hopefully
                isReceived: false
            });

            // Update chat display
            updateChatDisplay();

            // Clear input
            messageInput.value = '';
        } else if (!currentRecipient) {
            alert('Please enter a recipient name or ID first');
        }
    });

    // Handle Enter key
    messageInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendButton.click();
        }
    });

    // Function to display sent ciphertext (to be called by the backend)
    window.displaySentCiphertext = (ciphertext) => {
        sentCiphertextDisplay.textContent = ciphertext;
        // Update the last sent message's ciphertext
        if (messageHistory.length > 0 && !messageHistory[messageHistory.length - 1].isReceived) {
            messageHistory[messageHistory.length - 1].ciphertext = ciphertext;
            updateChatDisplay();
        }
    };
}); 