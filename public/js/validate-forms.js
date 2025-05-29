
// Client-side Bootstrap-style validation for all forms
document.addEventListener('DOMContentLoaded', () => {
  const forms = document.querySelectorAll('form.needs-validation');
  Array.from(forms).forEach(form => {
    form.addEventListener('submit', evt => {
      if (!form.checkValidity()) {
        evt.preventDefault();
        evt.stopPropagation();
      }
      form.classList.add('was-validated');
    }, false);
  });
});
