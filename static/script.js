// Webcam for face (from earlier)
async function captureFace() {
    const video = document.getElementById('video');
    const canvas = document.getElementById('canvas');
    const stream = await navigator.mediaDevices.getUserMedia({ video: true });
    video.srcObject = stream;
    video.play();
    setTimeout(() => {
        canvas.getContext('2d').drawImage(video, 0, 0, 320, 240);
        const image_b64 = canvas.toDataURL('image/jpeg');
        // POST to /register or /face_auth
        const formData = new FormData();
        formData.append('face_image_b64', image_b64);
        fetch('/register', { method: 'POST', body: formData }).then(() => location.reload());
        stream.getTracks().forEach(track => track.stop());
    }, 3000);
}

// FIDO2 registration (from earlier)
async function registerFIDO2() {
    const res = await fetch('/fido2/register_start?username=' + document.querySelector('input[name="username"]').value);
    const challengeData = await res.json();
    const credential = await navigator.credentials.create({
        publicKey: {
            challenge: Uint8Array.from(challengeData.challenge),
            rp: { id: challengeData.rp, name: '3FA App' },
            user: { id: Uint8Array.from(challengeData.userId || 'user'), name: 'User', displayName: 'User' },
            pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
            authenticatorSelection: { userVerification: 'required' }
        }
    });
    await fetch('/fido2/register_finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'user', credential: credential })
    });
    location.reload();
}