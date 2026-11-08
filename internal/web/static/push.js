// Anmeldung dieses Geräts für Push-Nachrichten (Seite „Einstellungen“).
(async () => {
  const box = document.getElementById('push');
  if (!box) return;
  const $ = (id) => document.getElementById(id);
  const msg = (t) => { $('push-msg').textContent = t; };
  if (!('serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window)) {
    msg('Dieses Gerät oder dieser Browser unterstützt hier keine Push-Nachrichten. Auf dem iPhone: Sitewatch über „Teilen → Zum Home-Bildschirm“ installieren und von dort öffnen.');
    return;
  }
  const post = (url, body) => fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
  const key = Uint8Array.from(atob(box.dataset.key.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
  const reg = await navigator.serviceWorker.register('/sw.js');
  async function show() {
    const sub = await reg.pushManager.getSubscription();
    $('push-on').hidden = !!sub;
    $('push-off').hidden = $('push-test').hidden = !sub;
    msg(sub ? 'Dieses Gerät erhält Push-Nachrichten.' : (Notification.permission === 'denied' ? 'Benachrichtigungen sind für diese Seite im System blockiert.' : 'Dieses Gerät ist nicht angemeldet.'));
  }
  $('push-on').onclick = async () => {
    try {
      if (await Notification.requestPermission() !== 'granted') return show();
      const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key });
      const r = await post('/push/subscribe', sub.toJSON());
      if (!r.ok) { await sub.unsubscribe(); msg('Anmeldung abgelehnt (' + r.status + '). Eventuell ist die Sitzung abgelaufen, bitte neu laden.'); return; }
    } catch (e) { msg('Anmeldung fehlgeschlagen: ' + e.message); return; }
    show();
  };
  $('push-off').onclick = async () => {
    const sub = await reg.pushManager.getSubscription();
    if (sub) { await post('/push/unsubscribe', { endpoint: sub.endpoint }); await sub.unsubscribe(); }
    show();
  };
  $('push-test').onclick = async () => { msg((await post('/push/test')).ok ? 'Testnachricht gesendet.' : 'Senden fehlgeschlagen, Details im Log.'); };
  show();
})();
