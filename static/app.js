window.threeFA = {
  getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.content : '';
  },

  async jsonFetch(url, payload, options = {}) {
    return fetch(url, {
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
  },

  async formFetch(url, formData, options = {}) {
    if (!formData.has('csrf_token')) formData.append('csrf_token', this.getCsrfToken());
    return fetch(url, {
      method: options.method || 'POST',
      headers: {
        'X-CSRF-Token': this.getCsrfToken(),
        ...(options.headers || {}),
      },
      body: formData,
      credentials: options.credentials || 'same-origin',
    });
  },
};

(() => {
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduceMotion) return;

  function addButtonRipples() {
    document.querySelectorAll('.btn, .btn-linklike').forEach((button) => {
      button.addEventListener('pointerdown', (event) => {
        const rect = button.getBoundingClientRect();
        button.style.setProperty('--tap-x', `${event.clientX - rect.left}px`);
        button.style.setProperty('--tap-y', `${event.clientY - rect.top}px`);
        button.classList.remove('is-tapping');
        void button.offsetWidth;
        button.classList.add('is-tapping');
      });
    });
  }

  function addPointerDepth() {
    document.querySelectorAll('.hero-card, .panel-card, .glass-card').forEach((card) => {
      card.classList.add('dynamic-depth');
      card.addEventListener('pointermove', (event) => {
        const rect = card.getBoundingClientRect();
        const x = ((event.clientX - rect.left) / rect.width - 0.5).toFixed(3);
        const y = ((event.clientY - rect.top) / rect.height - 0.5).toFixed(3);
        card.style.setProperty('--depth-x', x);
        card.style.setProperty('--depth-y', y);
      });
      card.addEventListener('pointerleave', () => {
        card.style.setProperty('--depth-x', 0);
        card.style.setProperty('--depth-y', 0);
      });
    });
  }

  function addStaggeredMotion() {
    document.querySelectorAll('.feature-chip, .option-card, .metric-card, .tile, .data-table tbody tr')
      .forEach((item, index) => item.style.setProperty('--stagger', `${Math.min(index * 45, 360)}ms`));
  }

  window.addEventListener('DOMContentLoaded', () => {
    document.body.classList.add('motion-ready');
    addButtonRipples();
    addPointerDepth();
    addStaggeredMotion();
  });
})();
