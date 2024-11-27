function encryptFile() {
    const fileInput = document.getElementById("fileInput");
    const file = fileInput.files[0];

    if (!file) {
        alert("Please select a file to encrypt.");
        return;
    }

    const reader = new FileReader();
    reader.onload = function (event) {
        const fileData = event.target.result;

        // Convert file data to Base64 string
        const base64Data = btoa(String.fromCharCode(...new Uint8Array(fileData)));

        // Generate a random encryption key (16 bytes)
        const encryptionKey = CryptoJS.lib.WordArray.random(16);

        // Encrypt the base64-encoded data
        const encrypted = CryptoJS.AES.encrypt(base64Data, encryptionKey).toString();

        // Create the encrypted file Blob
        const encryptedBlob = new Blob([encrypted], { type: 'text/plain' });

        // Show download button and attach file
        const downloadButton = document.getElementById("downloadEncryptedButton");
        downloadButton.style.display = "inline";
        downloadButton.onclick = () => downloadFile(encryptedBlob, 'encrypted.txt');

        // Show the decryption key to the user in Base64 format
        document.getElementById("decryptionKey").textContent = encryptionKey.toString(CryptoJS.enc.Base64);

        // Show the encryption result section
        document.getElementById("encryptionResult").style.display = "block";
    };
    reader.readAsArrayBuffer(file);
}

function decryptFile() {
    const encryptedFileInput = document.getElementById("encryptedFileInput");
    const decryptKeyInput = document.getElementById("decryptKeyInput");

    const file = encryptedFileInput.files[0];
    const decryptionKey = CryptoJS.enc.Base64.parse(decryptKeyInput.value.trim());

    if (!file || !decryptKeyInput.value.trim()) {
        alert("Please provide both the encrypted file and decryption key.");
        return;
    }

    const reader = new FileReader();
    reader.onload = function (event) {
        const encryptedData = event.target.result;

        try {
            // Decrypt the data
            const decrypted = CryptoJS.AES.decrypt(encryptedData, decryptionKey).toString(CryptoJS.enc.Utf8);

            // Decode the Base64 back to original file content
            const originalFileData = Uint8Array.from(atob(decrypted), c => c.charCodeAt(0));

            // Create the decrypted file Blob
            const decryptedBlob = new Blob([originalFileData], { type: 'application/octet-stream' });

            // Show download button and attach file
            const downloadButton = document.getElementById("downloadDecryptedButton");
            downloadButton.style.display = "inline";
            downloadButton.onclick = () => downloadFile(decryptedBlob, 'decrypted.txt');

            // Show the decryption result section
            document.getElementById("decryptionResult").style.display = "block";
        } catch (e) {
            alert("Failed to decrypt the file. Make sure the key is correct.");
        }
    };
    reader.readAsText(file);
}

// Function to trigger file download
function downloadFile(blob, filename) {
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}
