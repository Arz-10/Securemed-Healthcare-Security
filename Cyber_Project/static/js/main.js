/*
 * main.js – SecureMed client-side scripts
 * Accessible flash message management and robust alert dismissal.
 */

// 1. Delegated click handler for dismissible alert close buttons
document.addEventListener('click', (event) => {
  const closeBtn = event.target.closest('[data-bs-dismiss="alert"], .btn-close');
  if (!closeBtn) return;

  const alertEl = closeBtn.closest('.alert');
  if (!alertEl) return;

  // If Bootstrap Alert is active, let Bootstrap handle native data-bs-dismiss smoothly
  if (window.bootstrap && typeof window.bootstrap.Alert === 'function') {
    try {
      const bsAlert = bootstrap.Alert.getOrCreateInstance(alertEl);
      if (bsAlert) {
        return;
      }
    } catch (e) {
      // Fall through to manual dismissal
    }
  }

  // Fallback direct dismissal if Bootstrap is absent
  event.preventDefault();
  alertEl.classList.remove('show');
  alertEl.style.transition = 'opacity 0.15s ease-out';
  alertEl.style.opacity = '0';
  setTimeout(() => {
    if (alertEl && alertEl.parentNode) {
      alertEl.remove();
    }
  }, 160);
});

// 2. Auto-dismiss transient flash messages after 8 seconds
document.addEventListener('DOMContentLoaded', () => {
  setTimeout(() => {
    const alerts = document.querySelectorAll('#flash-container .alert, #login-flash-container .alert');
    alerts.forEach(el => {
      if (document.body.contains(el)) {
        if (window.bootstrap && typeof window.bootstrap.Alert === 'function') {
          try {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(el);
            if (bsAlert) {
              bsAlert.close();
              return;
            }
          } catch (e) {
            // fallback
          }
        }
        el.classList.remove('show');
        el.style.transition = 'opacity 0.2s ease-out';
        el.style.opacity = '0';
        setTimeout(() => {
          if (el && el.parentNode) {
            el.remove();
          }
        }, 200);
      }
    });
  }, 8000);
});
