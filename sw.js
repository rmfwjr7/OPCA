// OPCA 서비스 워커: 사이트를 닫아도 새 메시지 푸시 알림을 받을 수 있게 해줍니다.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

self.addEventListener("push", (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch {
    data = { body: event.data ? event.data.text() : "" };
  }
  event.waitUntil(
    self.registration.showNotification(data.title || "OPCA", {
      body: data.body || "새 알림이 도착했어요.",
      tag: data.tag || "opca",
      renotify: true,
      data: { url: data.url || "/?open=mypage" },
    })
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || "/?open=mypage";
  event.waitUntil(
    (async () => {
      const windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
      for (const client of windows) {
        if (new URL(client.url).origin === self.location.origin) {
          await client.focus();
          client.postMessage({ type: "open-mypage" });
          return;
        }
      }
      await self.clients.openWindow(url);
    })()
  );
});
