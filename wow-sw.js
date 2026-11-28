// 2026-11-19 와우 판 앱(홈 화면에 추가)용 서비스 워커
// 범위 = wow.html 하나 (wow.html 이 scope './wow.html' 로 등록) — 같은 저장소의 다른 판(board.html 등)은 안 건드림
// 판 화면·아이콘 : 인터넷 먼저, 안 되면 저장해 둔 것 · 파이어베이스 코드(gstatic, 판 번호 고정) : 저장해 둔 것 먼저
// 판 내용(보고·쪽 그림)은 wow.html 의 파이어베이스 오프라인 저장이 맡음 → 인터넷 없으면 마지막으로 본 판
// 저장 칸 이름은 'wow-board-' 로 시작하는 것만 만들고 지움 (같은 주소의 다른 판 저장 칸은 안 건드림)
const CACHE = 'wow-board-v1';
const SHELL = ['wow.html', 'wow-manifest.json', 'wow-icon-192.png', 'wow-icon-512.png'];
const SDK = [
  'https://www.gstatic.com/firebasejs/10.14.1/firebase-app-compat.js',
  'https://www.gstatic.com/firebasejs/10.14.1/firebase-firestore-compat.js',
];

self.addEventListener('install', (e) => {
  e.waitUntil((async () => {
    const c = await caches.open(CACHE);
    await c.addAll(SHELL);
    await Promise.all(SDK.map(async (u) => {   // 못 받아도 설치는 됨 (다음에 쓸 때 저장)
      try { await c.put(u, await fetch(u, { mode: 'no-cors' })); } catch (err) {}
    }));
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    for (const k of await caches.keys()) if (k.startsWith('wow-board-') && k !== CACHE) await caches.delete(k);
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const u = new URL(req.url);
  if (SDK.includes(u.origin + u.pathname)) {   // 파이어베이스 코드 : 저장해 둔 것 먼저
    e.respondWith((async () => {
      const c = await caches.open(CACHE), hit = await c.match(u.origin + u.pathname);
      if (hit) return hit;
      const r = await fetch(req); try { await c.put(u.origin + u.pathname, r.clone()); } catch (err) {}
      return r;
    })());
    return;
  }
  if (u.origin !== location.origin) return;   // 파이어베이스 통신 등은 그대로 통과
  const name = u.pathname.split('/').pop();
  const key = req.mode === 'navigate' ? 'wow.html' : name;
  if (!SHELL.includes(key)) return;
  e.respondWith((async () => {   // 판 화면·아이콘 : 인터넷 먼저
    const c = await caches.open(CACHE);
    try {
      const r = await fetch(req);
      if (r.ok) await c.put(key, r.clone());
      return r;
    } catch (err) {
      const hit = await c.match(key);
      if (hit) return hit;
      throw err;
    }
  })());
});
