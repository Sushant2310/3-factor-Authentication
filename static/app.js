window.threeFA = {
  getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.content : '';
  },

  async jsonFetch(url, payload, options = {}) {
    const response = await fetch(url, {
      method: options.method || 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': this.getCsrfToken(),
        ...(options.headers || {}),
      },
      body: JSON.stringify({
        ...(payload || {}),
        csrf_token: this.getCsrfToken(),
      }),
      credentials: options.credentials || 'same-origin',
    });
    return response;
  },

  async formFetch(url, formData, options = {}) {
    if (!formData.has('csrf_token')) {
      formData.append('csrf_token', this.getCsrfToken());
    }
    const response = await fetch(url, {
      method: options.method || 'POST',
      headers: {
        'X-CSRF-Token': this.getCsrfToken(),
        ...(options.headers || {}),
      },
      body: formData,
      credentials: options.credentials || 'same-origin',
    });
    return response;
  },
};
