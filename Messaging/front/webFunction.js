document.addEventListener('DOMContentLoaded', () => {
    let clientId = null;  // Will be set by server
    const messageInput = document.getElementById('messageInput');
    const sendButton = document.getElementById('sendButton');
    const recipientInput = document.getElementById('recipientInput');
    const messagesContainer = document.getElementById('messages');
    const sentCiphertextDisplay = document.getElementById('sentCiphertext');
    const receivedCiphertextDisplay = document.getElementById('receivedCiphertext');
    const decryptedTextDisplay = document.getElementById('decryptedText');
    const toggleButton = document.getElementById('toggleEncryption');

    // Create and add user ID display element
    const userIdDisplay = document.createElement('div');
    userIdDisplay.id = 'userIdDisplay';
    userIdDisplay.style.cssText = 'position: fixed; top: 10px; right: 10px; background-color: #4CAF50; color: white; padding: 10px; border-radius: 5px; font-weight: bold;';
    document.body.appendChild(userIdDisplay);

    let showEncrypted = false;
    const messageHistory = [];
    let currentRecipient = '';
    let ws = null;
    let reconnectAttempts = 0;
    const maxReconnectAttempts = 5;
    let isConnected = false;

    function connectWebSocket() {
        console.log('Attempting to connect to WebSocket server...');
        try {
            // Create WebSocket connection
            ws = new WebSocket('wss://localhost:8081');
            
            // Set a connection timeout
            const connectionTimeout = setTimeout(() => {
                if (ws.readyState === WebSocket.CONNECTING) {
                    console.error('Connection timeout - server not responding');
                    ws.close();
                }
            }, 5000); // 5 second timeout

            // Add event listeners
            ws.onopen = () => {
                console.log('Connected to server');
                clearTimeout(connectionTimeout);
                isConnected = true;
                reconnectAttempts = 0;
                // Send init message
                ws.send(JSON.stringify({type: 'init'}));
            };

            ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                console.log('Received message:', data);
                
                if (data.type === 'init_ack') {
                    console.log('Server acknowledged connection');
                    clientId = data.clientId;
                    console.log('Assigned client ID:', clientId);
                    sendButton.disabled = false;
                    messageInput.disabled = false;
                    recipientInput.disabled = false;
                    
                    // Update the page title to show the client ID
                    document.title = `UnderCoverChat - ${clientId}`;
                    
                    // Update the user ID display
                    userIdDisplay.textContent = `Your ID: ${clientId}`;
                    
                    // Show a notification to the user
                    alert(`You have been assigned ID: ${clientId}\nPlease share this ID with others to start chatting!`);
                }
                else if (data.type === 'message') {
                    console.log('Received chat message:', data);
                    
                    // If this is a response to our sent message, update the last sent message
                    if (messageHistory.length > 0 && !messageHistory[messageHistory.length - 1].isReceived) {
                        const lastMessage = messageHistory[messageHistory.length - 1];
                        if (lastMessage.plaintext === data.plaintext) {
                            lastMessage.ciphertext = data.ciphertext;
                            sentCiphertextDisplay.textContent = data.ciphertext;
                        } else {
                            // This is a new received message
                            messageHistory.push({
                                plaintext: data.plaintext,
                                ciphertext: data.ciphertext,
                                isReceived: true,
                                sender: data.sender
                            });
                            receivedCiphertextDisplay.textContent = data.ciphertext;
                            decryptedTextDisplay.textContent = data.plaintext;
                        }
                    } else {
                        // This is a new received message
                        messageHistory.push({
                            plaintext: data.plaintext,
                            ciphertext: data.ciphertext,
                            isReceived: true,
                            sender: data.sender
                        });
                        receivedCiphertextDisplay.textContent = data.ciphertext;
                        decryptedTextDisplay.textContent = data.plaintext;
                    }

                    // Update chat display
                    updateChatDisplay();
                }
                else if (data.type === 'error') {
                    console.error('Server error:', data.message);
                    alert(data.message);
                }
            };

            ws.onerror = (error) => {
                console.error('WebSocket error:', error);
                clearTimeout(connectionTimeout);
                isConnected = false;
                sendButton.disabled = true;
                messageInput.disabled = true;
                recipientInput.disabled = true;
                
                // Log more details about the error
                console.log('WebSocket state:', ws.readyState);
                console.log('WebSocket URL:', ws.url);
                
                if (reconnectAttempts < maxReconnectAttempts) {
                    reconnectAttempts++;
                    console.log(`Reconnection attempt ${reconnectAttempts} of ${maxReconnectAttempts}`);
                    setTimeout(connectWebSocket, 2000);
                } else {
                    console.error('Max reconnection attempts reached. Please check if the server is running.');
                }
            };

            ws.onclose = (event) => {
                console.log('WebSocket connection closed:', event.code, event.reason);
                clearTimeout(connectionTimeout);
                isConnected = false;
                sendButton.disabled = true;
                messageInput.disabled = true;
                recipientInput.disabled = true;
                
                if (event.code === 1006) {
                    console.log('Connection closed abnormally, attempting to reconnect...');
                    if (reconnectAttempts < maxReconnectAttempts) {
                        reconnectAttempts++;
                        console.log(`Reconnection attempt ${reconnectAttempts} of ${maxReconnectAttempts}`);
                        setTimeout(connectWebSocket, 2000);
                    }
                }
            };
        } catch (error) {
            console.error('Error creating WebSocket:', error);
            isConnected = false;
            sendButton.disabled = true;
            messageInput.disabled = true;
            recipientInput.disabled = true;
            if (reconnectAttempts < maxReconnectAttempts) {
                reconnectAttempts++;
                setTimeout(connectWebSocket, 2000);
            }
        }
    }

    // Initially disable inputs until connection is established
    sendButton.disabled = true;
    messageInput.disabled = true;
    recipientInput.disabled = true;

    // Handle recipient path
    recipientInput.addEventListener('change', () => {
        currentRecipient = recipientInput.value.trim();
        if (currentRecipient && isConnected && ws.readyState === WebSocket.OPEN) {
            console.log('Setting recipient to:', currentRecipient);
            // Clear message history when changing recipients
            messageHistory.length = 0;
            updateChatDisplay();
            // Notify server of recipient change
            ws.send(JSON.stringify({
                type: 'recipient_change',
                recipientId: currentRecipient
            }));
        } else {
            console.error('Cannot set recipient - connection state:', ws.readyState);
        }
    });

<<<<<<< Updated upstream
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
=======
    // Initial connection
    connectWebSocket();
>>>>>>> Stashed changes

    // Toggle button click handler
    toggleButton.addEventListener('click', () => {
        showEncrypted = !showEncrypted;
        toggleButton.textContent = showEncrypted ? 'Show Decrypted' : 'Show Encrypted';
        toggleButton.classList.toggle('active');
        updateChatDisplay();
    });

    // Function to update the chat display based on current toggle state
    function updateChatDisplay() {
        messagesContainer.innerHTML = '';
        messageHistory.forEach(msg => {
            const messageElement = document.createElement('div');
            messageElement.className = `message ${msg.isReceived ? 'received' : 'sent'}`;
            
            // Add message content
            const content = document.createElement('div');
            content.className = 'message-content';
            content.textContent = showEncrypted ? msg.ciphertext : msg.plaintext;
            messageElement.appendChild(content);
            
            messagesContainer.appendChild(messageElement);
        });
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    // Send message
    function sendMessage() {
        const message = messageInput.value.trim();
        if (message && currentRecipient && isConnected && ws.readyState === WebSocket.OPEN) {
            console.log('Sending message to:', currentRecipient);
            
            // Store sent message in history immediately
            messageHistory.push({
                plaintext: message,
                ciphertext: '', // This will be updated when we receive the encrypted version
                isReceived: false
            });
            
            // Update chat display
            updateChatDisplay();
            
            // Send message to server
            const messageData = {
                type: 'message',
                recipientId: currentRecipient,
                content: message
            };
            console.log('Sending data:', messageData);
            ws.send(JSON.stringify(messageData));

            // Clear input
            messageInput.value = '';
        } else {
            if (!currentRecipient) {
                alert('Please enter a recipient name or ID first');
            } else if (!isConnected || ws.readyState !== WebSocket.OPEN) {
                console.error('WebSocket state:', ws.readyState);
                alert('Not connected to server. Please wait for connection to be established.');
            }
        }
    }

    // Send button click handler
    sendButton.addEventListener('click', sendMessage);

    // Handle Enter key
    messageInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
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