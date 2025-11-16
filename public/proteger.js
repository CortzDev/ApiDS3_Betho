function protegerPagina(){
  const t = localStorage.getItem('token');
  if(!t){ localStorage.clear(); window.location.href = '/'; }
}
function cerrarSesionReal(){
  localStorage.clear(); sessionStorage.clear();
  history.pushState(null,null,location.href);
  window.onpopstate = function(){ history.go(1); };
  window.location.href = '/';
}
