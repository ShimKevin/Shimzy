let peerConnection;
const configuration = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };

// Initialize call
async function startCall(videoEnabled, targetUser) {
    try {
        const stream = await navigator.mediaDevices.getUserMedia({
            audio: true,
            video: videoEnabled
        });
        
        document.getElementById('localVideo').srcObject = stream;
        document.getElementById('video-container').style.display = 'block';
        
        peerConnection = new RTCPeerConnection(configuration);
        stream.getTracks().forEach(track => {
            peerConnection.addTrack(track, stream);
        });
        
        // Send call initiation signal
        socket.emit('call_initiated', {
            from: currentUser,
            to: targetUser,
            video: videoEnabled
        });
        
        // Set up ICE candidate handling
        peerConnection.onicecandidate = (event) => {
            if (event.candidate) {
                socket.emit('ice_candidate', {
                    candidate: event.candidate,
                    to: targetUser
                });
            }
        };
        
    } catch (error) {
        console.error('Error starting call:', error);
    }
}

// End call
function endCall() {
    if (peerConnection) {
        peerConnection.close();
        peerConnection = null;
    }
    document.getElementById('video-container').style.display = 'none';
    const localVideo = document.getElementById('localVideo');
    if (localVideo.srcObject) {
        localVideo.srcObject.getTracks().forEach(track => track.stop());
    }
}