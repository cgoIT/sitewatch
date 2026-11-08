// Service Worker für Web-Push. Zeigt die Nachricht an und öffnet beim Antippen das Cockpit.
self.addEventListener('push', (e) => {
  let d = {};
  try { d = e.data.json(); } catch (_) {}
  e.waitUntil(self.registration.showNotification(d.title || 'Sitewatch', {
    body: d.body || '', icon: '/icon-192.png', badge: '/icon-192.png', data: { url: /^\/(?!\/)/.test(d.url || '') ? d.url : '/' },
  }));
});
self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: 'window' }).then((list) => {
    for (const c of list) if ('focus' in c) return c.focus();
    return self.clients.openWindow(e.notification.data.url);
  }));
});
