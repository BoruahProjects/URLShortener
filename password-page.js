const WORKER_API_URL = 'https://links.yourdomain.com';
const passwordForm = document.getElementById('password-form');
const errorMessageDiv = document.getElementById('error-message');
let shortLinkKey = '';
let errorTimeout;

window.onload = () => {
    const params = new URLSearchParams(window.location.search);
    shortLinkKey = params.get('key');
    if (!shortLinkKey) {
        errorMessageDiv.textContent = 'Error: No short link key provided.';
        errorMessageDiv.classList.remove('hidden');
        passwordForm.classList.add('hidden');
    }
};

passwordForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearTimeout(errorTimeout);
    errorMessageDiv.classList.add('hidden');
    errorMessageDiv.textContent = '';

    if (!shortLinkKey) {
        errorMessageDiv.textContent = 'Cannot proceed without a short link key.';
        errorMessageDiv.classList.remove('hidden');
        errorTimeout = setTimeout(() => { errorMessageDiv.classList.add('hidden'); }, 2000);
        return;
    }

    const formData = new FormData(passwordForm);
    formData.append('key', shortLinkKey);

    try {
        const response = await fetch(`${WORKER_API_URL}/api/verify-link-password`, {
            method: 'POST',
            body: formData,
            credentials: 'include'
        });
        const data = await response.json();
        if (response.ok && data.success) {
            window.location.href = data.redirectUrl;
        } else {
            errorMessageDiv.textContent = data.error || 'Incorrect password.';
            errorMessageDiv.classList.remove('hidden');
            errorTimeout = setTimeout(() => { errorMessageDiv.classList.add('hidden'); }, 2000);
        }
    } catch (error) {
        console.error('Password submission error:', error);
        errorMessageDiv.textContent = 'Network error or server unreachable.';
        errorMessageDiv.classList.remove('hidden');
        errorTimeout = setTimeout(() => { errorMessageDiv.classList.add('hidden'); }, 2000);
    }
});