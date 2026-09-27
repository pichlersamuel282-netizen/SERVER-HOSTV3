(function () {
  let currentUser = null;

  async function apiRequest(path, options = {}) {
    const response = await fetch(`/api${path}`, {
      credentials: 'same-origin',
      cache: 'no-store',
      ...options,
      headers: {
        ...(options.body ? {'Content-Type': 'application/json'} : {}),
        ...(options.headers || {})
      }
    });
    const body = await response.text();
    let data = {};
    if (body) {
      try { data = JSON.parse(body); }
      catch { data = {message: body}; }
    }
    if (!response.ok) throw new Error(data.message || data.error || `Request failed (${response.status}).`);
    return data;
  }

  async function refreshCurrentUser() {
    try {
      const result = await apiRequest('/me');
      currentUser = result.user;
    } catch {
      currentUser = null;
    }
    return currentUser;
  }

  async function loginAccount(login, password) {
    const result = await apiRequest('/login', {method: 'POST', body: JSON.stringify({login, password})});
    currentUser = result.user;
    return currentUser;
  }

  async function createAccount({username, email, password}) {
    const result = await apiRequest('/register', {method: 'POST', body: JSON.stringify({username, email, password})});
    currentUser = result.user;
    return currentUser;
  }

  async function clearSession() {
    try { await apiRequest('/logout', {method: 'POST'}); }
    finally { currentUser = null; }
  }

  async function getAccounts() {
    const result = await apiRequest('/admin/accounts');
    return result.accounts;
  }

  async function updateAccount(accountId, updates) {
    const result = await apiRequest(`/admin/accounts/${encodeURIComponent(accountId)}`, {
      method: 'PATCH',
      body: JSON.stringify(updates)
    });
    return result.account;
  }

  window.WembuxAccounts = {
    ready: refreshCurrentUser(),
    apiRequest,
    getAccounts,
    getSession: () => currentUser,
    getCurrentUser: () => currentUser,
    loginAccount,
    createAccount,
    clearSession,
    updateAccount,
    banAccount: (accountId, reason) => updateAccount(accountId, {banned: true, reason}),
    unbanAccount: accountId => updateAccount(accountId, {banned: false, reason: ''})
  };
})();