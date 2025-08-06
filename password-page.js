const WORKER_API_URL = 'https://links.domain.com';
const passwordForm = document.getElementById('password-form');
const errorMessageDiv = document.getElementById('error-message');
let shortLinkKey = '';
let errorTimeout;

window.onload = () => {
    const params = new URLSearchParams(window.location.search);
    shortLinkKey = params.get('key');
    if (!shortLinkKey) {
        errorMessageDiv.textContent = 'Error: No short link key provided.';
        errorMessageDiv.style.display = 'block';
        passwordForm.style.display = 'none';
    }
};

passwordForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearTimeout(errorTimeout);
    errorMessageDiv.style.display = 'none';
    errorMessageDiv.textContent = '';

    if (!shortLinkKey) {
        errorMessageDiv.textContent = 'Cannot proceed without a short link key.';
        errorMessageDiv.style.display = 'block';
        errorTimeout = setTimeout(() => { errorMessageDiv.style.display = 'none'; }, 2000);
        return;
    }

    const formData = new FormData(passwordForm);
    try {
        const response = await fetch(`${WORKER_API_URL}/${shortLinkKey}`, {
            method: 'POST',
            body: formData,
            credentials: 'include'
        });
        const data = await response.json();
        if (response.ok && data.success) {
            window.location.href = data.redirectUrl;
        } else {
            errorMessageDiv.textContent = data.error || 'Incorrect password.';
            errorMessageDiv.style.display = 'block';
            errorTimeout = setTimeout(() => { errorMessageDiv.style.display = 'none'; }, 2000);
        }
    } catch (error) {
        console.error('Password submission error:', error);
        errorMessageDiv.textContent = 'Network error or server unreachable.';
        errorMessageDiv.style.display = 'block';
        errorTimeout = setTimeout(() => { errorMessageDiv.style.display = 'none'; }, 2000);
    }
});