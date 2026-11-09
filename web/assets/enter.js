// The hero's entrance guard (kit motion.md): set before the first paint so the hero's words wait for
// motion.js, with a 700ms safety mark. An external file because the CSP forbids inline scripts.
const h = document.documentElement;
h.classList.add('m-enter', 'mo-js');
setTimeout(() => h.classList.add('m-enter-done'), 700);
setTimeout(() => h.classList.add('mo-safe'), 2500);
