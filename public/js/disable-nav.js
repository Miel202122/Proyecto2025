(function(){
  // Inject style for disabled buttons
  const style = document.createElement('style');
  style.textContent = '.disabled-btn{opacity:.5;cursor:not-allowed;pointer-events:none;}';
  document.head.appendChild(style);

  function normalise(p){return (p||'').toLowerCase();}
  const role = (window.userRole||'guest').toLowerCase();

  // Allowed paths for each role (keep synced with backend)
  const ROLE_ALLOWED = {
    admin: null,
    apiario: ['/main','/apia_rie','/vapiarie','/harvest','/vharvest','/qualityh','/reports','/alerts','/vproducto','/agregarproducto','/standar','/estandare','/estandares','/estandars','/vproductos'],
    user: ['/main']
  };

  function disable(){
    if(role==='admin') return;             // full access
    const allowed = ROLE_ALLOWED[role] || [];
    const btns = document.querySelectorAll('.sidebar .menu-button');
    btns.forEach(btn=>{
      const attr = btn.getAttribute('onclick') || '';
      const m = attr.match(/'(.*?)'/);
      if(!m) return;
      const path = normalise(m[1]);
      if(allowed===null) return;
      const permitted = allowed.some(a=> path.startsWith(a));
      if(!permitted){
        btn.classList.add('disabled-btn');
        btn.removeAttribute('onclick');
      }
    });
  }

  document.addEventListener('DOMContentLoaded', disable);
})();