
function encryptFile() {
    const fileInput = document.getElementById("fileInput");
    const file = fileInput.files[0];
    
    if (!file) {
        alert("Please select a file to encrypt.");
        return;
    }

    const reader = new FileReader();
    reader.onload = function(event) {
        const fileData = event.target.result;
        
        const encryptionKey = CryptoJS.lib.WordArray.random(16);
        const encrypted = CryptoJS.AES.encrypt(fileData, encryptionKey).toString();

        const encryptedBlob = new Blob([encrypted], { type: 'text/plain' });
        const encryptedFileUrl = URL.createObjectURL(encryptedBlob);
        
        const downloadLink = document.getElementById("downloadLink");
        downloadLink.href = encryptedFileUrl;
        downloadLink.style.display = "block";
        
        document.getElementById("decryptionKey").textContent = encryptionKey.toString(CryptoJS.enc.Base64);
        
        document.getElementById("encryptionResult").style.display = "block";
    };
    reader.readAsText(file);
}

function decryptFile() {
    const encryptedFileInput = document.getElementById("encryptedFileInput");
    const decryptKeyInput = document.getElementById("decryptKeyInput");
    
    const file = encryptedFileInput.files[0];
    const decryptionKey = decryptKeyInput.value.trim();

    if (!file || !decryptionKey) {
        alert("Please provide both the encrypted file and decryption key.");
        return;
    }

    const reader = new FileReader();
    reader.onload = function(event) {
        const encryptedData = event.target.result;
        
        try {
            const decrypted = CryptoJS.AES.decrypt(encryptedData, CryptoJS.enc.Base64.parse(decryptionKey)).toString(CryptoJS.enc.Utf8);

            const decryptedBlob = new Blob([decrypted], { type: 'application/octet-stream' });
            const decryptedFileUrl = URL.createObjectURL(decryptedBlob);

            const decryptedDownloadLink = document.getElementById("decryptedDownloadLink");
            decryptedDownloadLink.href = decryptedFileUrl;
            decryptedDownloadLink.style.display = "block";

            document.getElementById("decryptionResult").style.display = "block";
        } catch (e) {
            alert("Failed to decrypt the file. Make sure the key is correct.");
        }
    };
    reader.readAsText(file);
}
