// „Kopieren“-Knopf neben der Site-ID (Seite „Auftrag bestätigen“): erspart das Abtippen auf dem Handy.
document.querySelectorAll('[data-copy]').forEach((b) => {
  b.onclick = async () => {
    const t = b.dataset.copy;
    try { await navigator.clipboard.writeText(t); } catch {
      // shortcut: Fallback über Textauswahl, falls die Clipboard-API fehlt; ausreichend für alte Browser.
      const r = document.createRange(); r.selectNodeContents(document.getElementById(b.dataset.src)); const s = getSelection(); s.removeAllRanges(); s.addRange(r); document.execCommand('copy');
    }
    const old = b.textContent; b.textContent = 'Kopiert ✓'; setTimeout(() => { b.textContent = old; }, 1500);
  };
});
