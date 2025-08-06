const WORKER_API_URL = 'https://links.domain.com/api';
const loginView = document.getElementById('login-view');
const dashboardView = document.getElementById('dashboard-view');
const headerTitle = document.getElementById('header-title');
const loginForm = document.getElementById('login-form');
const loginButton = document.getElementById('loginButton');
const loginErrorMessageDiv = document.getElementById('login-error-message');
const linksTableBody = document.querySelector('#links-table tbody');
const spinnerContainer = document.getElementById('spinner-container');
const loadingMessage = document.getElementById('loading-message');
const errorMessageDiv = document.getElementById('error-message');
const logoutButton = document.getElementById('logoutButton');
const createLinkButton = document.getElementById('createLinkButton');
const createFolderButton = document.getElementById('createFolderButton');
const backButton = document.getElementById('backButton');
const filterContainer = document.getElementById('filter-container');
const filterSection = document.getElementById('filter-section');
const applyFiltersButton = document.getElementById('applyFiltersButton');
const clearFiltersButton = document.getElementById('clearFiltersButton');
const sortContainer = document.getElementById('sort-container');
const sortSection = document.getElementById('sort-section');
const applySortButton = document.getElementById('applySortButton');
const viewOptionsButton = document.getElementById('viewOptionsButton');
const viewOptionsMenu = document.getElementById('viewOptionsMenu');
const sortDropdownOption = document.getElementById('sortDropdownOption');
const filterDropdownOption = document.getElementById('filterDropdownOption');
const closeSortButton = document.getElementById('closeSortButton');
const closeFilterButton = document.getElementById('closeFilterButton');
const selectAllCheckbox = document.getElementById('selectAllCheckbox');
const multiSelectActions = document.getElementById('multi-select-actions');
const selectedCountSpan = document.getElementById('selected-count');
const moveSelectedButton = document.getElementById('moveSelectedButton');
const deleteSelectedButton = document.getElementById('deleteSelectedButton');
const cancelSelectionButton = document.getElementById('cancelSelectionButton');
const paginationControls = document.getElementById('pagination-controls');
const prevPageButton = document.getElementById('prev-page-button');
const nextPageButton = document.getElementById('next-page-button');
const pageInfoSpan = document.getElementById('page-info');
const currentYearSpan = document.getElementById('current-year');
const createModal = document.getElementById('createModal');
const modalCreateError = document.getElementById('modal-create-error');
const modalCreateForm = document.getElementById('modal-create-form');
const createFolderModal = document.getElementById('create-folder-modal');
const newFolderNameInput = document.getElementById('new-folder-name-input');
const confirmCreateFolderBtn = document.getElementById('confirm-create-folder');
const moveModal = document.getElementById('move-modal');
const moveModalTitle = document.getElementById('move-modal-title');
const folderTreeContainer = document.getElementById('folder-tree-container');
const confirmMoveBtn = document.getElementById('confirm-move-button');
const editModal = document.getElementById('editModal');
const modalEditTitle = document.getElementById('modal-edit-title');
const modalEditForm = document.getElementById('modal-edit-form');
const modalErrorMessageDiv = document.getElementById('modal-error-message');
const modalOriginalKey = document.getElementById('modalOriginalKey');
const modalShortPath = document.getElementById('modalShortPath');
const modalLongUrl = document.getElementById('modalLongUrl');
const modalPassword = document.getElementById('modalPassword');
const modalExpiresAt = document.getElementById('modalExpiresAt');
const modalMaxClicks = document.getElementById('modalMaxClicks');
const deleteModal = document.getElementById('delete-modal');
const deleteModalText = document.getElementById('delete-modal-text');
const confirmDeleteBtn = document.getElementById('confirm-delete-button');
const cancelDeleteBtn = document.getElementById('cancel-delete-button');
const removePasswordButton = document.getElementById('removePasswordButton');
const resultModal = document.getElementById('resultModal');
const copyUrlButton = document.getElementById('copyUrlButton');
const renameFolderModal = document.getElementById('rename-folder-modal');
const newFolderNameInputRename = document.getElementById('new-folder-name-input-rename');
const confirmRenameFolderBtn = document.getElementById('confirm-rename-folder-btn');

let csrfToken = null;
let currentPage = 1;
let totalPages = 1;
let currentFolderId = null;
let currentPath = [{ id: null, name: 'Root' }];
let selectedItems = new Set();
let itemsToDelete = [];
let folderToRenameId = null;
let selectedDestinationFolderId = null;
let errorTimeout;
let removePasswordClicked = false;

function getIcon(item) {
    if (item.is_folder) {
        return `<svg class="folder-icon" fill="currentColor" viewBox="0 0 24 24"><path d="M10 4H4c-1.11 0-2 .89-2 2v12c0 1.09.9 2 2 2h16c1.09 0 2-.91 2-2V8c0-1.09-.91-2-2-2h-8l-2-2z"></path></svg>`;
    }
    return `<svg class="folder-icon" style="color: #0cf;" fill="currentColor" viewBox="0 0 24 24"><path d="M3.9 12c0-1.71 1.39-3.1 3.1-3.1h4V7H7c-2.76 0-5 2.24-5 5s2.24 5 5 5h4v-1.9H7c-1.71 0-3.1-1.39-3.1-3.1zM8 13h8v-2H8v2zm9-6h-4v1.9h4c1.71 0 3.1 1.39 3.1 3.1s-1.39 3.1-3.1 3.1h-4V17h4c2.76 0 5-2.24 5-5s-2.24-5-5-5z"></path></svg>`;
}

function createRow(item) {
    const row = document.createElement('tr');
    row.dataset.id = item.id;
    row.dataset.isFolder = item.is_folder;
    row.dataset.expirationTimestamp = item.expirationTimestamp || 0;
    row.dataset.clicks = item.clicks || 0;
    row.dataset.maxClicks = item.maxClicks || 0;
    row.classList.toggle('selected-item', selectedItems.has(item.id));
    const checkboxCell = row.insertCell();
    checkboxCell.innerHTML = `<input type="checkbox" class="item-checkbox" data-id="${item.id}">`;
    checkboxCell.querySelector('.item-checkbox').checked = selectedItems.has(item.id);
    const nameCell = row.insertCell();
    nameCell.innerHTML = `${getIcon(item)} ${item.is_folder ? item.name : item.key}`;
    if (item.is_folder) {
        nameCell.classList.add('folder-link');
        nameCell.dataset.id = item.id;
        nameCell.dataset.name = item.name;
        nameCell.style.cursor = 'pointer';
    } else {
        nameCell.innerHTML = `<a href="${item.fullShortUrl}" target="_blank">${getIcon(item)} ${item.key}</a>`;
    }
    const urlCell = row.insertCell();
    urlCell.className = 'original-url-cell';
    urlCell.innerHTML = item.is_folder ? '—' : `<a href="${item.originalUrl}" target="_blank" title="${item.originalUrl}">${item.originalUrl}</a>`;
    const passwordCell = row.insertCell();
    passwordCell.textContent = item.is_folder ? '—' : (item.hasPassword ? 'Yes' : 'No');
    const clicksCell = row.insertCell();
    clicksCell.textContent = item.is_folder ? '—' : `${item.clicks || 0} / ${item.maxClicks || '∞'}`;
    const expiryCell = row.insertCell();
    expiryCell.textContent = '—';
    const actionsCell = row.insertCell();
    const actionsWrapper = document.createElement('div');
    actionsWrapper.className = 'action-buttons';
    if (item.is_folder) {
        actionsWrapper.innerHTML = `
            <button class="action-btn" data-action="move" title="Move Folder">
                <svg viewBox="0 0 24 24" fill="currentColor"><path d="M20 6h-8l-2-2H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2zm-6 12v-3h-4v-4h4V8l5 5-5 5z"></path></svg>
            </button>
            <button class="action-btn" data-action="rename" title="Rename Folder">
                <svg viewBox="0 0 24 24" fill="currentColor"><path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"></path></svg>
            </button>
            <button class="action-btn" data-action="delete" title="Delete Folder">
                <svg viewBox="0 0 24 24" fill="currentColor"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"></path></svg>
            </button>
        `;
    } else {
         actionsWrapper.innerHTML = `
            <button class="action-btn" data-action="copy" title="Copy Short Link" data-url="${item.fullShortUrl}">
                <svg viewBox="0 0 24 24" fill="currentColor"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"></path></svg>
            </button>
            <button class="action-btn" data-action="move" title="Move Link">
                <svg viewBox="0 0 24 24" fill="currentColor"><path d="M20 6h-8l-2-2H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2zm-6 12v-3h-4v-4h4V8l5 5-5 5z"></path></svg>
            </button>
            <button class="action-btn" data-action="edit" title="Edit Link">
                <svg viewBox="0 0 24 24" fill="currentColor"><path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"></path></svg>
            </button>
            <button class="action-btn" data-action="delete" title="Delete Link">
                <svg viewBox="0 0 24 24" fill="currentColor"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"></path></svg>
            </button>
        `;
    }
    actionsCell.appendChild(actionsWrapper);
    return row;
}

function updateExpiryStatus(row) {
    const expiryCell = row.cells[5];
    const now = Date.now();
    const expirationTimestamp = parseInt(row.dataset.expirationTimestamp, 10);
    const currentClicks = parseInt(row.dataset.clicks, 10);
    const maxClicks = parseInt(row.dataset.maxClicks, 10);
    let isExpiredByTime = false;

    if (!isNaN(expirationTimestamp) && expirationTimestamp > 0) {
        const expirationDate = new Date(expirationTimestamp);
        expiryCell.textContent = expirationDate.toLocaleString('en-IN', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: true });
        if (expirationDate.getTime() < now) {
            isExpiredByTime = true;
        }
    } else {
        expiryCell.textContent = 'Never';
    }

    const isExpiredByClicks = !isNaN(maxClicks) && maxClicks > 0 && currentClicks >= maxClicks;
    if (isExpiredByTime || isExpiredByClicks) {
        row.classList.add('expired-link');
    } else {
        row.classList.remove('expired-link');
    }
}

function renderItems(items) {
    linksTableBody.innerHTML = '';
    if (items.length === 0) {
        linksTableBody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding: 2rem;">This folder is empty.</td></tr>`;
        return;
    }
    items.forEach(item => {
        const row = createRow(item);
        linksTableBody.appendChild(row);
        updateExpiryStatus(row);
    });
}

function updateTableRow(formData) {
    const originalKey = formData.get('originalKey');
    const newKey = formData.get('newKey');
    const row = document.querySelector(`tr[data-id="${originalKey}"]`);
    if (!row) return;

    if (newKey && originalKey !== newKey) {
        row.dataset.id = newKey;
        const nameCellLink = row.cells[1].querySelector('a');
        const newFullUrl = new URL(newKey, 'https://links.domain.com').toString();
        
        if (nameCellLink) {
            nameCellLink.href = newFullUrl;
            nameCellLink.innerHTML = `${getIcon({is_folder: false})} ${newKey}`;
        }
        
        const copyButton = row.querySelector('button[data-action="copy"]');
        if (copyButton) {
            copyButton.dataset.url = newFullUrl;
        }
        
        const checkbox = row.querySelector('.item-checkbox');
        if (checkbox) {
            checkbox.dataset.id = newKey;
        }
    }

    const newUrl = formData.get('longUrl');
    const newMaxClicks = parseInt(formData.get('maxClicks'), 10);
    const newExpiryTimestamp = parseInt(formData.get('expiresAtTimestamp'), 10);

    const urlCellLink = row.cells[2].querySelector('a');
    if (urlCellLink) {
        urlCellLink.href = newUrl;
        urlCellLink.textContent = newUrl;
        urlCellLink.title = newUrl;
    }

    if (formData.has('password')) {
        const hasPassword = !!formData.get('password');
        row.cells[3].textContent = hasPassword ? 'Yes' : 'No';
    }

    const currentClicks = parseInt(row.dataset.clicks, 10);
    row.dataset.maxClicks = newMaxClicks;
    row.cells[4].textContent = `${currentClicks} / ${!isNaN(newMaxClicks) && newMaxClicks > 0 ? newMaxClicks : '∞'}`;
    
    row.dataset.expirationTimestamp = newExpiryTimestamp;
    updateExpiryStatus(row);
}


function renderPagination(currentPage, totalPages) {
    if (totalPages <= 1) {
        paginationControls.style.display = 'none';
        return;
    }
    paginationControls.style.display = 'flex';
    pageInfoSpan.textContent = `Page ${currentPage} of ${totalPages}`;
    prevPageButton.disabled = currentPage === 1;
    nextPageButton.disabled = currentPage === totalPages;
}

function updateMultiSelectActionBar() {
    const count = selectedItems.size;
    if (count > 0) {
        multiSelectActions.style.display = 'flex';
        selectedCountSpan.textContent = `${count} item(s) selected`;
    } else {
        multiSelectActions.style.display = 'none';
    }
    const totalCheckboxes = linksTableBody.querySelectorAll('.item-checkbox').length;
    selectAllCheckbox.checked = totalCheckboxes > 0 && selectedItems.size === totalCheckboxes;
}

function clearSelection() {
    selectedItems.clear();
    linksTableBody.querySelectorAll('tr').forEach(row => {
        row.classList.remove('selected-item');
        const checkbox = row.querySelector('.item-checkbox');
        if (checkbox) checkbox.checked = false;
    });
    selectAllCheckbox.checked = false;
    updateMultiSelectActionBar();
}

async function renderFolderTree() {
    folderTreeContainer.innerHTML = 'Loading folders...';
    try {
        const response = await fetch(`${WORKER_API_URL}/folder-tree`, {
            credentials: 'include',
            headers: { 'X-CSRF-Token': csrfToken }
        });
        const allFolders = await response.json();
        folderTreeContainer.innerHTML = '';
        
        const foldersToExclude = new Set();
        const getDescendants = (folderId) => {
            foldersToExclude.add(folderId);
            const children = allFolders.filter(f => f.parent_folder_id === folderId);
            children.forEach(child => getDescendants(child.id));
        };

        selectedItems.forEach(id => {
            const row = document.querySelector(`tr[data-id="${id}"]`);
            if (row && row.dataset.isFolder === 'true') {
                getDescendants(id);
            }
        });
        
        const rootItem = document.createElement('div');
        rootItem.className = 'folder-tree-item';
        rootItem.dataset.id = 'null';
        rootItem.innerHTML = `${getIcon({is_folder: true})} Root`;
        folderTreeContainer.appendChild(rootItem);

        const buildTree = (parentId, parentElement, depth) => {
            const children = allFolders.filter(f => f.parent_folder_id === parentId);
            children.forEach(folder => {
                if (foldersToExclude.has(folder.id)) {
                    return;
                }
                const folderItem = document.createElement('div');
                folderItem.className = 'folder-tree-item';
                folderItem.dataset.id = folder.id;
                folderItem.style.paddingLeft = `${depth * 1.5}rem`;
                folderItem.innerHTML = `${getIcon({is_folder: true})} ${folder.name}`;
                parentElement.appendChild(folderItem);
                buildTree(folder.id, parentElement, depth + 1);
            });
        };
        buildTree(null, folderTreeContainer, 1);
    } catch (error) {
        folderTreeContainer.innerHTML = 'Error loading folders.';
    }
}

function togglePasswordVisibility(inputElement) {
    inputElement.type = inputElement.type === 'password' ? 'text' : 'password';
}

async function navigateToFolder(folderId, folderName, pathIndex) {
    if (pathIndex !== undefined) {
        currentPath = currentPath.slice(0, pathIndex + 1);
    } else {
        currentPath.push({ id: folderId, name: folderName });
    }
    currentFolderId = folderId;
    currentPage = 1;
    clearSelection();
    backButton.style.display = currentFolderId === null ? 'none' : 'inline-block';
    await fetchLinks();
}

async function fetchLinks(page = 1) {
    currentPage = page;
    spinnerContainer.style.display = 'flex';
    loadingMessage.style.display = 'none';
    linksTableBody.innerHTML = '';
    errorMessageDiv.style.display = 'none';

    const params = new URLSearchParams({ 
        page: currentPage,
        folderId: currentFolderId === null ? 'null' : currentFolderId
    });

    const searchInput = document.getElementById('searchQuery').value;
    if (searchInput) params.append('search', searchInput);

    const minClicks = parseInt(document.getElementById('minClicks').value, 10);
    if (!isNaN(minClicks) && minClicks >= 0) params.append('minClicks', minClicks);

    const maxClicks = parseInt(document.getElementById('maxClicks').value, 10);
    if (!isNaN(maxClicks) && maxClicks >= 0) params.append('maxClicks', maxClicks);

    const expiryStatus = document.getElementById('expiryStatus').value;
    if (expiryStatus && expiryStatus !== 'all') params.append('expiryStatus', expiryStatus);

    const creationDateFrom = document.getElementById('creationDateFrom').value;
    if (creationDateFrom) params.append('creationDateFrom', new Date(creationDateFrom).getTime());

    const creationDateTo = document.getElementById('creationDateTo').value;
    if (creationDateTo) params.append('creationDateTo', new Date(creationDateTo).setHours(23, 59, 59, 999));

    params.append('sortBy', document.getElementById('sortBy').value);
    params.append('sortOrder', document.getElementById('sortOrder').value);

    try {
        const response = await fetch(`${WORKER_API_URL}/admin?${params.toString()}`, {
            credentials: 'include',
            headers: {
                'X-CSRF-Token': csrfToken
            }
        });
        if (response.status === 401) {
            const data = await response.json().catch(() => ({}));
            return handleAuthFailure(data.reason);
        }
        const data = await response.json();
        if (response.ok) {
            renderItems(data.items);
            totalPages = data.totalPages;
            renderPagination(currentPage, totalPages);
        } else {
            errorMessageDiv.textContent = data.error || 'Failed to load data.';
            errorMessageDiv.style.display = 'block';
        }
    } catch (error) {
        errorMessageDiv.textContent = 'Network error or server unreachable.';
        errorMessageDiv.style.display = 'block';
    } finally {
        spinnerContainer.style.display = 'none';
    }
}

async function handleCreateFolder() {
    const folderName = newFolderNameInput.value.trim();
    if (!folderName) {
        alert('Folder name is required.');
        return;
    }
    const tempId = `folder-temp-${Date.now()}`;
    const tempFolder = { id: tempId, name: folderName, is_folder: true };
    const newRow = createRow(tempFolder);
    linksTableBody.prepend(newRow);
    createFolderModal.classList.remove('active');
    newFolderNameInput.value = '';
    try {
        const response = await fetch(`${WORKER_API_URL}/create-folder`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            credentials: 'include',
            body: JSON.stringify({ folderName, parentFolderId: currentFolderId })
        });
        const data = await response.json();
        if (!response.ok) {
            alert(data.error || 'Failed to create folder.');
            newRow.remove();
        } else {
            newRow.dataset.id = data.id;
            newRow.querySelector('.item-checkbox').dataset.id = data.id;
            const folderLink = newRow.querySelector('.folder-link');
            if(folderLink) folderLink.dataset.id = data.id;
        }
    } catch (error) { 
        alert('A network error occurred during folder creation. Please refresh.');
        newRow.remove();
    }
}

async function handleRenameFolder() {
    const newName = newFolderNameInputRename.value.trim();
    const folderId = folderToRenameId;
    if (!newName || !folderId) return;

    const nameCell = document.querySelector(`tr[data-id="${folderId}"] .folder-link`);
    const originalNameHTML = nameCell.innerHTML;
    nameCell.innerHTML = `${getIcon({is_folder: true})} ${newName}`;
    
    renameFolderModal.classList.remove('active');

    try {
        const response = await fetch(`${WORKER_API_URL}/rename-folder`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            credentials: 'include',
            body: JSON.stringify({ folderId, newName })
        });

        if (!response.ok) {
            const data = await response.json();
            alert(data.error || 'Failed to rename folder.');
            nameCell.innerHTML = originalNameHTML;
        }
    } catch (error) {
        alert('A network error occurred.');
        nameCell.innerHTML = originalNameHTML;
    }
}

function openDeleteModal(ids) {
    if (!ids || ids.length === 0) return;
    itemsToDelete = ids;
    const containsFolder = ids.some(id => {
        const row = document.querySelector(`tr[data-id="${id}"]`);
        return row && row.dataset.isFolder === 'true';
    });
    if (containsFolder) {
        deleteModalText.textContent = `Are you sure you want to delete ${ids.length} item(s)? This action is permanent. If you delete a folder, all its contents will also be deleted.`;
    } else {
        deleteModalText.textContent = `Are you sure you want to delete ${ids.length} item(s)? This action is permanent.`;
    }
    deleteModal.classList.add('active');
}

async function executeDelete() {
    const ids = itemsToDelete;
    if (ids.length === 0) return;
    const oldRows = ids.map(id => document.querySelector(`tr[data-id="${id}"]`));
    ids.forEach(id => document.querySelector(`tr[data-id="${id}"]`)?.remove());
    clearSelection();
    deleteModal.classList.remove('active');
    try {
        const response = await fetch(`${WORKER_API_URL}/delete`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            credentials: 'include',
            body: JSON.stringify({ ids })
        });
        if (!response.ok) {
            throw new Error('Server-side deletion failed.');
        }
    } catch (error) { 
        alert('An error occurred while deleting. Please refresh the page to see the latest state.');
        oldRows.forEach(row => linksTableBody.prepend(row));
    } finally {
        itemsToDelete = [];
    }
}

async function handleMove() {
    if (selectedDestinationFolderId === undefined) return;
    const ids = Array.from(selectedItems);
    const originalButtonHTML = confirmMoveBtn.innerHTML;
    confirmMoveBtn.disabled = true;
    confirmMoveBtn.innerHTML = `<div class="spinner-small"></div> Moving...`;

    try {
        const response = await fetch(`${WORKER_API_URL}/move`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            credentials: 'include',
            body: JSON.stringify({ ids, destinationFolderId: selectedDestinationFolderId })
        });
        
        if (!response.ok) {
            const data = await response.json();
            alert(data.error || 'Failed to move items.');
            return;
        }

        ids.forEach(id => document.querySelector(`tr[data-id="${id}"]`)?.remove());
        clearSelection();
        moveModal.classList.remove('active');
    } catch (error) { 
        alert('An error occurred while moving. Please refresh the page.');
        fetchLinks(currentPage);
    } finally {
        confirmMoveBtn.disabled = false;
        confirmMoveBtn.innerHTML = originalButtonHTML;
    }
}

async function openEditModal(key) {
    editModal.classList.add('active');
    modalEditForm.reset();
    removePasswordClicked = false;
    modalPassword.value = '';
    modalErrorMessageDiv.style.display = 'none';
    modalEditTitle.textContent = `Edit Short URL: ${key}`;
    modalOriginalKey.value = key;
    modalShortPath.value = key;
    try {
        const response = await fetch(`${WORKER_API_URL}/edit/${key}`, {
            credentials: 'include',
            headers: {
                'X-CSRF-Token': csrfToken
            }
        });
        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.error || 'Failed to fetch link details.');
        }
        const data = await response.json();
        modalLongUrl.value = data.url;
        if (data.expiresAt) {
            const date = new Date(data.expiresAt);
            const localDate = new Date(date.getTime() - (date.getTimezoneOffset() * 60000));
            modalExpiresAt.value = localDate.toISOString().slice(0, 16);
        } else {
            modalExpiresAt.value = '';
        }
        modalMaxClicks.value = data.maxClicks || '0';
        removePasswordButton.disabled = !data.hasPassword;
    } catch (error) {
        modalErrorMessageDiv.textContent = error.message;
        modalErrorMessageDiv.style.display = 'block';
    }
}

function showLoginError(message) {
    clearTimeout(errorTimeout);
    loginErrorMessageDiv.textContent = message;
    loginErrorMessageDiv.style.display = 'block';
    errorTimeout = setTimeout(() => {
        loginErrorMessageDiv.style.display = 'none';
    }, 4000);
}

function handleAuthFailure(reason) {
    document.body.classList.add('login-page');
    dashboardView.style.cssText = 'display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; overflow: hidden; opacity: 0; pointer-events: none; z-index: -1;';
    loginView.style.display = 'flex';
    if (reason === 'invalid_token') {
        loginErrorMessageDiv.textContent = 'Session expired or invalid. Please log in again.';
        loginErrorMessageDiv.style.display = 'block';
    } else {
        loginErrorMessageDiv.textContent = '';
        loginErrorMessageDiv.style.display = 'none';
    }
}

async function initializeDashboard() {
    try {
        const response = await fetch(`${WORKER_API_URL}/check-auth`, { credentials: 'include' });
        if (response.ok) {
            const sessionResponse = await fetch(`${WORKER_API_URL}/session-info`, { credentials: 'include' });
            if (sessionResponse.ok) {
                const data = await sessionResponse.json();
                csrfToken = data.csrfToken;
            } else {
                throw new Error('Could not fetch session token.');
            }
            document.body.classList.remove('login-page');
            loginView.style.display = 'none';
            dashboardView.style.cssText = 'display: flex; flex-direction: column; position: relative; top: auto; left: auto; width: 100%; height: 100%; overflow: auto; opacity: 1; pointer-events: auto; z-index: auto;';
            await navigateToFolder(null, 'Root', 0);
        } else {
            const data = await response.json().catch(() => ({}));
            handleAuthFailure(data.reason);
        }
    } catch (error) {
        handleAuthFailure();
    }
}

async function checkSessionStatus() {
    const isDashboardVisible = dashboardView.style.opacity === '1';
    if (!isDashboardVisible) return;
    try {
        const response = await fetch(`${WORKER_API_URL}/check-auth`, { credentials: 'include' });
        if (!response.ok) {
            const data = await response.json().catch(() => ({}));
            handleAuthFailure(data.reason);
        }
    } catch (error) {
        handleAuthFailure();
    }
}

document.addEventListener('DOMContentLoaded', () => {
    currentYearSpan.textContent = new Date().getFullYear();
    dashboardView.style.cssText = 'display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; overflow: hidden; opacity: 0; pointer-events: none; z-index: -1;';
    initializeDashboard();
    setInterval(checkSessionStatus, 5000);
    setInterval(() => {
        linksTableBody.querySelectorAll('tr[data-is-folder="false"]').forEach(row => {
            updateExpiryStatus(row);
        });
    }, 5000);
});

headerTitle.addEventListener('click', () => {
    if (currentFolderId !== null) {
        navigateToFolder(null, 'Root', 0);
    }
});

loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    loginButton.textContent = 'Logging in...';
    loginButton.disabled = true;
    const formData = new FormData(loginForm);
    try {
        const response = await fetch(`${WORKER_API_URL}/login`, { method: 'POST', body: formData, credentials: 'include' });
        if (response.ok) {
            const data = await response.json();
            csrfToken = data.csrfToken;

            document.body.classList.remove('login-page');
            loginView.style.display = 'none';
            dashboardView.style.cssText = 'display: flex; flex-direction: column; position: relative; top: auto; left: auto; width: 100%; height: 100%; overflow: auto; opacity: 1; pointer-events: auto; z-index: auto;';
            
            loginForm.reset();
            
            currentPath = [{ id: null, name: 'Root' }];
            await navigateToFolder(null, 'Root', 0);
        } else {
            const data = await response.json();
            showLoginError(data.error || 'Login failed.');
        }
    } catch (error) {
        showLoginError('Network error.');
    } finally {
        loginButton.textContent = 'Login';
        loginButton.disabled = false;
    }
});

logoutButton.addEventListener('click', async () => {
    await fetch(`${WORKER_API_URL}/logout`, { credentials: 'include' });
    handleAuthFailure();
});

linksTableBody.addEventListener('click', (e) => {
    const target = e.target;
    const row = target.closest('tr');
    if (!row || !row.dataset.id) return;
    const id = row.dataset.id;
    if (target.matches('.item-checkbox')) {
        if (target.checked) selectedItems.add(id);
        else selectedItems.delete(id);
        row.classList.toggle('selected-item', target.checked);
        updateMultiSelectActionBar();
        return;
    } 
    const actionButton = target.closest('.action-btn');
    if (actionButton) {
        const action = actionButton.dataset.action;
        e.preventDefault();
        if (action === 'delete') {
            openDeleteModal([id]);
        } else if (action === 'copy') {
            const urlToCopy = actionButton.dataset.url;
            navigator.clipboard.writeText(urlToCopy).then(() => {
                const originalIcon = actionButton.innerHTML;
                actionButton.innerHTML = '✔️';
                setTimeout(() => { actionButton.innerHTML = originalIcon; }, 1500);
            }).catch(err => console.error('Failed to copy!', err));
        } else if (action === 'move') {
            clearSelection();
            selectedItems.add(id);
            moveModalTitle.textContent = `Move 1 item to:`;
            moveModal.classList.add('active');
            renderFolderTree();
        } else if (action === 'edit') {
            openEditModal(id);
        } else if (action === 'rename') {
            folderToRenameId = id;
            const nameCell = row.cells[1];
            const currentName = nameCell.textContent.trim();
            newFolderNameInputRename.value = currentName;
            renameFolderModal.classList.add('active');
            newFolderNameInputRename.focus();
        }
        return;
    }
    if (target.closest('.folder-link')) {
        const folderLink = target.closest('.folder-link');
        navigateToFolder(folderLink.dataset.id, folderLink.dataset.name);
    }
});

backButton.addEventListener('click', () => {
    if (currentPath.length > 1) {
        const parentIndex = currentPath.length - 2;
        const parent = currentPath[parentIndex];
        navigateToFolder(parent.id, parent.name, parentIndex);
    }
});

selectAllCheckbox.addEventListener('change', (e) => {
    const isChecked = e.target.checked;
    linksTableBody.querySelectorAll('.item-checkbox').forEach(cb => {
        const id = cb.dataset.id;
        cb.checked = isChecked;
        if (isChecked) selectedItems.add(id);
        else selectedItems.delete(id);
        cb.closest('tr').classList.toggle('selected-item', isChecked);
    });
    updateMultiSelectActionBar();
});

createFolderButton.addEventListener('click', () => createFolderModal.classList.add('active'));
deleteSelectedButton.addEventListener('click', () => openDeleteModal(Array.from(selectedItems)));
moveSelectedButton.addEventListener('click', () => {
    moveModalTitle.textContent = `Move ${selectedItems.size} item(s) to:`;
    moveModal.classList.add('active');
    renderFolderTree();
});
cancelSelectionButton.addEventListener('click', clearSelection);

[createModal, createFolderModal, moveModal, editModal, deleteModal, resultModal, renameFolderModal].forEach(modal => {
    if (!modal) return;
    const closeButton = modal.querySelector('.close-button');
    if (closeButton) {
        closeButton.addEventListener('click', () => modal.classList.remove('active'));
    }
    modal.addEventListener('click', (e) => { if (e.target === modal) modal.classList.remove('active'); });
});

confirmCreateFolderBtn.addEventListener('click', handleCreateFolder);
confirmRenameFolderBtn.addEventListener('click', handleRenameFolder);
confirmDeleteBtn.addEventListener('click', executeDelete);
cancelDeleteBtn.addEventListener('click', () => deleteModal.classList.remove('active'));

folderTreeContainer.addEventListener('click', (e) => {
    const target = e.target.closest('.folder-tree-item');
    if (!target) return;
    folderTreeContainer.querySelectorAll('.selected-destination').forEach(el => el.classList.remove('selected-destination'));
    target.classList.add('selected-destination');
    selectedDestinationFolderId = target.dataset.id;
});

confirmMoveBtn.addEventListener('click', handleMove);
prevPageButton.addEventListener('click', () => { if (currentPage > 1) fetchLinks(currentPage - 1); });
nextPageButton.addEventListener('click', () => { if (currentPage < totalPages) fetchLinks(currentPage + 1); });

copyUrlButton.addEventListener('click', () => {
    const input = document.getElementById('resultShortUrl');
    const originalText = copyUrlButton.textContent;
    navigator.clipboard.writeText(input.value).then(() => {
        copyUrlButton.textContent = 'Copied!';
        setTimeout(() => { copyUrlButton.textContent = originalText; }, 2000);
    }).catch(err => {
        console.error('Failed to copy!', err);
        alert('Failed to copy to clipboard.');
    });
});

modalCreateForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(modalCreateForm);
    const expiresAtValue = formData.get('expiresAt');
    const expirationTimestamp = expiresAtValue ? new Date(expiresAtValue).getTime() : 0;
    const maxClicksValue = parseInt(formData.get('maxClicks'), 10);
    const tempItem = {
        id: formData.get('shortPath'), key: formData.get('shortPath'), is_folder: false,
        fullShortUrl: new URL(formData.get('shortPath'), 'https://links.domain.com').toString(),
        originalUrl: formData.get('longUrl'),
        hasPassword: !!formData.get('password'), clicks: 0,
        maxClicks: !isNaN(maxClicksValue) && maxClicksValue > 0 ? maxClicksValue : 0,
        expirationTimestamp: !isNaN(expirationTimestamp) && expirationTimestamp > 0 ? expirationTimestamp : 0,
    };
    const newRow = createRow(tempItem);
    const rows = Array.from(linksTableBody.querySelectorAll('tr'));
    const lastFolderRow = rows.reverse().find(row => row.dataset.isFolder === 'true');
    if (lastFolderRow) {
        lastFolderRow.insertAdjacentElement('afterend', newRow);
    } else {
        linksTableBody.prepend(newRow);
    }
    createModal.classList.remove('active');
    formData.append('parentFolderId', currentFolderId);
    formData.append('expiresAtTimestamp', expirationTimestamp);
    formData.delete('expiresAt');
    try {
        const response = await fetch(`${WORKER_API_URL}/shorten`, { 
            method: 'POST', 
            headers: { 'X-CSRF-Token': csrfToken },
            body: formData, 
            credentials: 'include' 
        });
        const data = await response.json();
        if(!response.ok) {
            alert(data.error || 'Failed to create link.');
            newRow.remove();
        } else {
            updateExpiryStatus(newRow);
            document.getElementById('resultShortUrl').value = data.shortUrl;
            resultModal.classList.add('active');
        }
    } catch (error) { 
        alert('A network error occurred.');
        newRow.remove();
    }
});

modalEditForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(modalEditForm);
    formData.append('newKey', modalShortPath.value);
    const expiresAtValue = formData.get('expiresAt');
    const newExpiryTimestamp = expiresAtValue ? new Date(expiresAtValue).getTime() : 0;
    
    if (formData.get('password') === '' && !removePasswordClicked) {
        formData.delete('password');
    }

    formData.append('expiresAtTimestamp', newExpiryTimestamp);
    updateTableRow(formData);
    editModal.classList.remove('active');
    formData.delete('expiresAt');
    try {
        const response = await fetch(`${WORKER_API_URL}/edit`, {
            method: 'POST',
            headers: { 'X-CSRF-Token': csrfToken },
            body: formData,
            credentials: 'include'
        });
        const data = await response.json();
        if (!response.ok) {
            alert(data.error || 'Failed to update link.');
            fetchLinks(currentPage);
        }
    } catch (error) {
         alert('Network error during update.');
         fetchLinks(currentPage);
    }
});

createLinkButton.addEventListener('click', () => {
    modalCreateForm.reset();
    modalCreateError.style.display = 'none';
    createModal.classList.add('active');
});

viewOptionsButton.addEventListener('click', (e) => {
    e.stopPropagation();
    const isHidden = viewOptionsMenu.style.display === 'none';
    viewOptionsMenu.style.display = isHidden ? 'block' : 'none';
});

sortDropdownOption.addEventListener('click', (e) => {
    e.preventDefault();
    viewOptionsMenu.style.display = 'none'; 
    const isHidden = sortContainer.style.display === 'none';
    sortContainer.style.display = isHidden ? 'block' : 'none';
    sortSection.style.display = isHidden ? 'block' : 'none';
    if (isHidden) {
        filterContainer.style.display = 'none';
        filterSection.style.display = 'none';
    }
});

filterDropdownOption.addEventListener('click', (e) => {
    e.preventDefault();
    viewOptionsMenu.style.display = 'none';
    const isHidden = filterContainer.style.display === 'none';
    filterContainer.style.display = isHidden ? 'block' : 'none';
    filterSection.style.display = isHidden ? 'block' : 'none';
    if (isHidden) {
        sortContainer.style.display = 'none';
        sortSection.style.display = 'none';
    }
});

closeSortButton.addEventListener('click', () => {
    sortContainer.style.display = 'none';
    sortSection.style.display = 'none';
});

closeFilterButton.addEventListener('click', () => {
    filterContainer.style.display = 'none';
    filterSection.style.display = 'none';
});

window.addEventListener('click', (e) => {
    if (!viewOptionsButton.contains(e.target)) {
        viewOptionsMenu.style.display = 'none';
    }
});

applyFiltersButton.addEventListener('click', () => fetchLinks(1));
applySortButton.addEventListener('click', () => fetchLinks(1));

clearFiltersButton.addEventListener('click', () => {
    filterSection.querySelectorAll('input, select').forEach(el => el.value = '');
    document.getElementById('expiryStatus').value = 'all';
    fetchLinks(1);
});

createModal.querySelector('.generate-shortpath').addEventListener('click', () => {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = '';
    for (let i = 0; i < 8; i++) result += chars.charAt(Math.floor(Math.random() * chars.length));
    createModal.querySelector('#createShortPath').value = result;
});

editModal.querySelector('.generate-shortpath').addEventListener('click', () => {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = '';
    for (let i = 0; i < 8; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    modalShortPath.value = result;
});

document.querySelectorAll('.toggle-password').forEach(icon => {
    icon.addEventListener('click', () => {
        const input = icon.closest('.input-with-icon').querySelector('input');
        togglePasswordVisibility(input);
    });
});

removePasswordButton.addEventListener('click', () => {
    document.getElementById('modalPassword').value = '';
    removePasswordClicked = true;
    removePasswordButton.disabled = true;
});