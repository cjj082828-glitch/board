# 업무판 (깃허브 페이지 board.html + 운동 앱 파이어베이스) 읽고 쓰기
# 사용자 2026-10-28 "회사 PC에서 클로드 못 들어가 — 구글 계정도 말고 주소 치면 나오게, 운동 앱도 그런 식으로 만들었는데"
# 파이어베이스 규칙이 운동 앱 컬렉션(ppld)만 열려 있고 누구나 목록을 볼 수 있음 → 문서 이름은 비밀키 해시로, 내용은 AES-GCM 암호화
# 2026-10-30 규칙 잠금 (사용자 "잠궈") : ppld 는 파이어베이스 로그인한 계정(판 아이디·비밀번호로 만든 것)만 읽고 씀 → 모든 호출에 로그인 토큰
# 문서 : ppld/bd_<해시16>_<이름> — days_<날짜>·index·status·cl_<날짜>·inbox_done (내가 씀), chk_·log_·tbm_<날짜> (판이 씀),
#        chat_<날짜>·inbox (둘 다 덧붙임, m 배열)
# 사용 : python board.py put-day 날짜 day.json   오늘 업무 올림 (+ index)
#        python board.py say 날짜 "답"            대화창에 Claude 답
#        python board.py note 날짜 항목id "한 줄"  항목 밑 Claude 한 줄
#        python board.py inbox-done 항목id "반영한 곳"
#        python board.py dump 날짜                 그날 판 내용 전부 (체크·메모·기록·대화·내일 TBM·추가 일정)
#        python board.py send-file 날짜 경로 ["글"]  판 자료실에 파일 올림 / send-files 날짜 "묶음 이름" 경로… (여러 개 한 묶음) / get-file id 조각수 저장경로 (판 파일 다시 받기)
#        python board.py files-done 끝난날짜 "업무" 키워드…  끝난 업무 파일 적어 둠 → files-prune [--dry] 가 2주 뒤 자료실에서 내림 (조각까지) / files-drop [--dry] 키워드… 바로 내림
#        python board.py watch                     새 입력 오면 BOARD_EVENT 출력 후 끝 (백그라운드, 처리 뒤 다시 켬)
import base64, datetime, hashlib, json, os, sys, time, urllib.error, urllib.request, uuid
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

sys.stdout.reconfigure(encoding='utf-8')
HERE = os.path.dirname(os.path.abspath(__file__))
CFG = json.load(open(os.path.join(HERE, 'board_config.json'), encoding='utf-8'))
DOCS = 'projects/%s/databases/(default)/documents' % CFG['projectId']
BASE = 'https://firestore.googleapis.com/v1/' + DOCS
PFX = 'bd_' + hashlib.sha256(CFG['secret'].encode()).hexdigest()[:16] + '_'
AES = AESGCM(PBKDF2HMAC(hashes.SHA256(), 32, b'meritz-board-v1', 150000).derive(CFG['secret'].encode()))
KST = datetime.timezone(datetime.timedelta(hours=9))


def enc(obj):
    iv = os.urandom(12)
    return base64.b64encode(iv + AES.encrypt(iv, json.dumps(obj, ensure_ascii=False).encode(), None)).decode()


def dec(s):
    try:
        u = base64.b64decode(s)
        return json.loads(AES.decrypt(u[:12], u[12:], None))
    except Exception:
        return None


def fb_cred(uid, pw):   # 파이어베이스 로그인 계정 : 판 아이디·비밀번호에서 만듦 (board.html·운동 앱과 같은 방식, 2026-10-30 규칙 잠금)
    u = uid.strip().lower()
    return ('mb-' + hashlib.sha256(('meritz-board-fb|' + u).encode()).hexdigest()[:20] + '@automatic-becf5.firebaseapp.com',
            hashlib.sha256(('meritz-board-fbpw|' + u + '|' + pw).encode()).hexdigest())


def auth_api(method, body):   # 파이어베이스 로그인 REST — 실패하면 (None, 오류 코드)
    req = urllib.request.Request('https://identitytoolkit.googleapis.com/v1/accounts:%s?key=%s' % (method, CFG['apiKey']),
                                 data=json.dumps(body).encode(), headers={'Content-Type': 'application/json'})
    try:
        return json.load(urllib.request.urlopen(req, timeout=20)), None
    except urllib.error.HTTPError as e:
        try: return None, json.load(e)['error']['message']
        except Exception: return None, str(e.code)


_TOKEN = None
def token():   # 규칙 잠금 뒤엔 로그인한 계정만 읽고 씀 — board_config.json 의 fbEmail·fbPass (set-login 때 저장)
    global _TOKEN
    if _TOKEN is None and CFG.get('fbEmail'):
        r, err = auth_api('signInWithPassword', {'email': CFG['fbEmail'], 'password': CFG['fbPass'], 'returnSecureToken': True})
        if err: raise SystemExit('파이어베이스 로그인 실패 : ' + err)
        _TOKEN = r['idToken']
    return _TOKEN


def call(method, url, body=None):
    hd = {'Content-Type': 'application/json'}
    if token(): hd['Authorization'] = 'Bearer ' + token()
    req = urllib.request.Request(url + ('&' if '?' in url else '?') + 'key=' + CFG['apiKey'], method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers=hd)
    try:
        return json.load(urllib.request.urlopen(req, timeout=20))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise SystemExit('파이어베이스 오류 %s : %s' % (e.code, e.read().decode()[:200]))


def get_raw(name):
    return call('GET', BASE + '/ppld/' + PFX + name)


def get(name):
    d = get_raw(name)
    v = d and d.get('fields', {}).get('v', {}).get('stringValue')
    return dec(v) if v else None


def get_list(name):
    d = get_raw(name)
    vals = (d or {}).get('fields', {}).get('m', {}).get('arrayValue', {}).get('values', [])
    return [o for o in (dec(x.get('stringValue', '')) for x in vals) if o]


def put(name, obj):
    call('PATCH', BASE + '/ppld/' + PFX + name, {'fields': {'v': {'stringValue': enc(obj)}}})


def append(name, obj):
    call('POST', BASE + ':commit', {'writes': [{
        'update': {'name': DOCS + '/ppld/' + PFX + name, 'fields': {}}, 'updateMask': {'fieldPaths': []},
        'updateTransforms': [{'fieldPath': 'm', 'appendMissingElements': {'values': [{'stringValue': enc(obj)}]}}]}]})


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def kst_today():
    return datetime.datetime.now(KST).strftime('%Y-%m-%d')


PART, FMAX = 600000, 15 * 1024 * 1024   # 파일 조각 60만 바이트(문서 한도 1MB), 15MB까지 (board.html 과 같음)
def enc_bytes(b):
    iv = os.urandom(12)
    return base64.b64encode(iv + AES.encrypt(iv, b, None)).decode()
def upload_file(path):   # 파일 → fil_<id>_<번호> 조각 (60만 바이트씩 암호화)
    data = open(path, 'rb').read()
    if len(data) > FMAX: raise SystemExit('15MB 넘음 : %d' % len(data))
    fid = 'f' + uuid.uuid4().hex[:12]; n = max(1, -(-len(data) // PART))
    for i in range(n):
        call('PATCH', BASE + '/ppld/' + PFX + 'fil_%s_%d' % (fid, i), {'fields': {'v': {'stringValue': enc_bytes(data[i * PART:(i + 1) * PART])}}})
    ext = os.path.splitext(path)[1].lower()
    types = {'.pdf': 'application/pdf', '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', '.xls': 'application/vnd.ms-excel', '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation', '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', '.hwp': 'application/x-hwp', '.zip': 'application/zip', '.txt': 'text/plain', '.png': 'image/png', '.jpg': 'image/jpeg'}
    return {'id': fid, 'name': os.path.basename(path), 'size': len(data), 'type': types.get(ext, ''), 'n': n}


def send_files(date, title, paths):   # 여러 파일을 한 묶음으로 자료실에 — 판에서 '모두 받기' 한 번 (사용자 10/30 "여러 개 한 번에 보낼 때도 원클릭으로 받아지나?")
    bid, at = 'b' + uuid.uuid4().hex[:10], now_iso()
    out = [dict(upload_file(p), date=date, at=at, text='', batch={'id': bid, 'title': title, 'n': len(paths)}) for p in paths]
    put('files', {'list': out + (get('files') or {'list': []})['list']})
    say(date, '자료실에 올림 · %s (%d개)' % (title, len(paths)))
    return out


def send_file(date, path, text=''):   # PC → 판 자료실 : fil_<id>_<번호> 조각 + files 목록(최근 것 먼저) + 대화엔 한 줄 알림 (사용자 2026-10-29 "보드 채팅창으로 파일도 주고받을 수 있게", 10/30 "너는 자료실 탭 만들어서 내가 받고")
    f = upload_file(path)
    lst = (get('files') or {'list': []})['list']
    lst.insert(0, dict(f, date=date, at=now_iso(), text=text))
    put('files', {'list': lst})
    say(date, '자료실에 올림 · ' + f['name'] + (' · ' + text if text else ''))
    return f
def get_file(fid, n, out):   # 판 파일 다시 받기 (감시가 놓쳤을 때)
    parts = []
    for i in range(n):
        d = get_raw('fil_%s_%d' % (fid, i))
        u = base64.b64decode(d['fields']['v']['stringValue'])
        parts.append(AES.decrypt(u[:12], u[12:], None))
    open(out, 'wb').write(b''.join(parts))
    return out
DONE, KEEP = os.path.join(HERE, 'files_done.json'), 14   # 끝난 업무 파일은 2주 뒤 자료실에서 내림 (사용자 11/2 "완료됐어도 2주 뒤에 지우게")
def match_files(keys):   # 이름·묶음 이름·글에 키워드가 하나라도 든 자료실 파일
    lst = (get('files') or {'list': []})['list']
    return [f for f in lst if keys and any(k in ' '.join([f.get('name', ''), f.get('text', ''), (f.get('batch') or {}).get('title', '')]) for k in keys)]
def drop_files(drop, dry=False):   # 자료실 목록에서 빼고 조각까지 지움 (원본은 드라이브에 있음)
    for f in drop: print('(시험) ' if dry else '내림 ', f.get('date'), (f.get('batch') or {}).get('title', ''), '|', f['name'])
    if drop and not dry:
        ids = {f['id'] for f in drop}
        put('files', {'list': [f for f in (get('files') or {'list': []})['list'] if f['id'] not in ids]})
        for f in drop:
            for i in range(f.get('n', 1)): call('DELETE', BASE + '/ppld/' + PFX + 'fil_%s_%d' % (f['id'], i))
    return drop
def say(date, text):
    append('chat_' + date, {'id': 'c' + uuid.uuid4().hex[:10], 'from': 'claude', 'text': text, 'at': now_iso()})


def login_doc(uid):
    return 'bd_login_' + hashlib.sha256(('meritz-board-login|' + uid.strip().lower()).encode()).hexdigest()[:24]


def set_login(uid, pw):   # 판 로그인 봉투 : 비밀키를 아이디·비밀번호로 잠가 ppld/bd_login_<아이디 해시>에 (board.html 과 같은 방식, 2026-10-29)
    salt, iv = os.urandom(16), os.urandom(12)
    key = PBKDF2HMAC(hashes.SHA256(), 32, salt, 310000).derive(pw.encode())
    v = base64.b64encode(salt + iv + AESGCM(key).encrypt(iv, CFG['secret'].encode(), None)).decode()
    call('PATCH', BASE + '/ppld/' + login_doc(uid), {'fields': {'v': {'stringValue': v}}})
    u = base64.b64decode(call('GET', BASE + '/ppld/' + login_doc(uid))['fields']['v']['stringValue'])
    k2 = PBKDF2HMAC(hashes.SHA256(), 32, u[:16], 310000).derive(pw.encode())
    assert AESGCM(k2).decrypt(u[16:28], u[28:], None).decode() == CFG['secret'], '다시 읽어 보니 안 맞음'
    # 파이어베이스 로그인 계정도 같은 아이디·비밀번호로 (없으면 만들고, 있으면 비밀번호 맞춤) → PC 쪽(board.py·watch.mjs)용으로 설정에 저장
    email, fpw = fb_cred(uid, pw)
    r, err = auth_api('signUp', {'email': email, 'password': fpw, 'returnSecureToken': True})
    if err == 'EMAIL_EXISTS':
        r, err = auth_api('signInWithPassword', {'email': email, 'password': fpw, 'returnSecureToken': True})
        if err and CFG.get('fbEmail') == email:   # 비밀번호를 바꾼 경우 : 예전 것으로 들어가서 바꿈
            old, err = auth_api('signInWithPassword', {'email': email, 'password': CFG['fbPass'], 'returnSecureToken': True})
            if old: r, err = auth_api('update', {'idToken': old['idToken'], 'password': fpw, 'returnSecureToken': True})
    if err in ('OPERATION_NOT_ALLOWED', 'CONFIGURATION_NOT_FOUND'):
        raise SystemExit('판 로그인은 등록됐는데, 파이어베이스 콘솔 Authentication에서 "이메일/비밀번호"가 꺼져 있어 — 켜고 다시 해줘')
    if err:
        raise SystemExit('판 로그인은 등록됐는데 파이어베이스 계정 등록 실패 : ' + err)
    old_uid = CFG.get('fbUid')
    CFG.update(fbEmail=email, fbPass=fpw, fbUid=r['localId'])
    json.dump(CFG, open(os.path.join(HERE, 'board_config.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    return r['localId'], old_uid


def beat(text='대기 중'):
    put('status', {'at': now_iso(), 'text': text})


def watch():
    seen_path = os.path.join(HERE, 'seen.json')
    seen = set(json.load(open(seen_path, encoding='utf-8'))) if os.path.exists(seen_path) else set()
    last = 0
    while True:
        day = kst_today()
        try:
            new = [m for m in get_list('chat_' + day) if m.get('from') in ('me', 'event') and m.get('id') not in seen]
        except (urllib.error.URLError, TimeoutError, OSError):   # 인터넷이 잠깐 끊겨도 감시는 계속 (10/28 시간 초과로 멈춘 일)
            time.sleep(30)
            continue
        if new:
            seen.update(m['id'] for m in new)
            json.dump(sorted(seen)[-800:], open(seen_path, 'w', encoding='utf-8'))
            print('BOARD_EVENT', day)
            for m in new:
                print('-', m.get('from'), m.get('text'))
            return
        if time.time() - last > 300:   # 판에 '연결 중' 표시용, 무료 한도 아끼려고 5분마다
            try:
                beat()
                last = time.time()
            except (urllib.error.URLError, TimeoutError, OSError):
                pass
        time.sleep(15)


def dump(date):
    nxt = datetime.date.fromisoformat(date) + datetime.timedelta(days=1)
    while nxt.weekday() >= 5:
        nxt += datetime.timedelta(days=1)
    out = {'checks': get('chk_' + date), 'log': get('log_' + date), 'chat': get_list('chat_' + date),
           'claude_notes': get('cl_' + date), 'tbm_next': get('tbm_' + nxt.isoformat()),
           'inbox': get_list('inbox'), 'inbox_done': get('inbox_done')}
    print(json.dumps(out, ensure_ascii=False, indent=1))


if __name__ == '__main__':
    a = sys.argv[1:]
    if not a:
        raise SystemExit('명령 : put-day | say | note | inbox-done | status | dump | get | watch')
    cmd = a[0]
    if cmd == 'put-day':
        day = json.load(open(a[2], encoding='utf-8'))
        put('days_' + a[1], day)
        put('index', {'dates': sorted(set((get('index') or {}).get('dates', []) + [a[1]]))})   # 지난 날 판도 목록에 남김 (사용자 2026-11-02 "그전 것도 보이게 하자" — 10/28엔 당일만이었음)
        print('ok put-day', a[1])
    elif cmd == 'say':
        say(a[1], a[2]); print('ok say')
    elif cmd == 'set-login':   # 판 아이디·비밀번호 등록·변경 — 사용자가 이 PC 터미널에서 직접 (사용자 2026-10-29 "아무나 생성하니까 나만 여기서 등록하는 게 맞아")
        import getpass
        uid = input('아이디 : ').strip()
        pw = getpass.getpass('비밀번호 (쳐도 화면에 안 보임) : ')
        if not uid or len(pw) < 6:
            raise SystemExit('아이디를 넣고, 비밀번호는 6자 이상으로 해줘')
        if getpass.getpass('비밀번호 한 번 더 : ') != pw:
            raise SystemExit('두 번 친 비밀번호가 달라 — 다시 해줘')
        fuid, old_uid = set_login(uid, pw)
        print('등록 끝 — 판·운동 앱에서 이 아이디·비밀번호로 로그인하면 돼')
        print('파이어베이스 계정 번호(UID) :', fuid + ('  ← 예전과 달라졌어, 파이어베이스 규칙의 번호도 바꿔야 해' if old_uid and old_uid != fuid else ''))
    elif cmd == 'put-report':   # 자료 탭 (사용자 2026-10-29 "2페이지에 니가 정리한 자료 PPT로") : rep_<id> + rep_index(최근 것 먼저)
        r = json.load(open(a[1], encoding='utf-8'))
        put('rep_' + r['id'], r)
        idx = [x for x in (get('rep_index') or {'list': []})['list'] if x.get('id') != r['id']]
        idx.append({'id': r['id'], 'title': r['title'], 'sub': r.get('sub', ''), 'date': r['date'], 'slides': len(r['slides'])})
        idx.sort(key=lambda x: (x['date'], x['id']), reverse=True)
        put('rep_index', {'list': idx})
        print('ok put-report', r['id'], '목록', len(idx))
    elif cmd == 'send-file':   # send-file 날짜 경로 ["글"] : 판 자료실에 파일 올림 (판에서 '눌러서 받기')
        f = send_file(a[1], a[2], a[3] if len(a) > 3 else '')
        print('ok send-file', f['name'], f['size'], '조각', f['n'])
    elif cmd == 'send-files':  # send-files 날짜 "묶음 이름" 경로1 경로2 … : 한 묶음으로 자료실에 (판에서 '모두 받기')
        for f in send_files(a[1], a[2], a[3:]): print('ok', f['name'], f['size'], '조각', f['n'])
    elif cmd == 'get-file':    # get-file 파일id 조각수 저장경로
        print('ok get-file', get_file(a[1], int(a[2]), a[3]))
    elif cmd == 'files-drop':  # files-drop [--dry] 키워드… : 이름·묶음 이름·글에 키워드가 든 파일을 자료실에서 바로 내림
        dry, keys = '--dry' in a, [k for k in a[1:] if k != '--dry']
        print('ok files-drop', len(drop_files(match_files(keys), dry)), '개')
    elif cmd == 'files-done':  # files-done 끝난날짜 "무슨 업무" 키워드… : 지금 그 키워드에 걸리는 파일을 '끝남'으로 적어 둠 → 2주 뒤 files-prune 이 내림
        ids = [f['id'] for f in match_files(a[3:])]
        reg = json.load(open(DONE, encoding='utf-8')) if os.path.exists(DONE) else []
        reg.append({'done': a[1], 'what': a[2], 'ids': ids})
        json.dump(reg, open(DONE, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
        print('ok files-done', a[2], len(ids), '개 →', (datetime.date.fromisoformat(a[1]) + datetime.timedelta(days=KEEP)).isoformat(), '에 내림')
    elif cmd == 'files-prune':  # files-prune [--dry] : 끝난 지 2주 지난 업무 파일을 자료실에서 내림 (아침 판 만들 때)
        dry, today = '--dry' in a, datetime.date.fromisoformat(kst_today())
        reg = json.load(open(DONE, encoding='utf-8')) if os.path.exists(DONE) else []
        due = [e for e in reg if datetime.date.fromisoformat(e['done']) + datetime.timedelta(days=KEEP) <= today]
        ids = {i for e in due for i in e['ids']}
        lst = (get('files') or {'list': []})['list']
        gone = drop_files([f for f in lst if f['id'] in ids], dry)
        if not dry:
            json.dump([e for e in reg if e not in due], open(DONE, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
        print('ok files-prune', [e['what'] for e in due], len(gone), '개')
    elif cmd == 'memo-done':   # 반영한 판 메모 지움 : memo-done 날짜 id [id ...] (사용자 2026-10-29 "니가 내 메모 보고 수정했으면 내 기존 메모 없애놔야지")
        c = get('chk_' + a[1]) or {'date': a[1], 'done': {}, 'notes': {}, 'result': {}}
        gone = [i for i in a[2:] if c.setdefault('notes', {}).pop(i, None) is not None]
        c['at'] = now_iso(); put('chk_' + a[1], c); print('ok memo-done', gone)
    elif cmd == 'note':
        cl = get('cl_' + a[1]) or {'notes': {}}
        cl.setdefault('notes', {})[a[2]] = a[3]
        put('cl_' + a[1], cl); print('ok note')
    elif cmd == 'inbox-done':
        d = get('inbox_done') or {}
        d[a[1]] = a[2]
        put('inbox_done', d); print('ok inbox-done')
    elif cmd == 'status':
        beat(a[1] if len(a) > 1 else '대기 중'); print('ok status')
    elif cmd == 'dump':
        dump(a[1] if len(a) > 1 else kst_today())
    elif cmd == 'get':
        print(json.dumps(get(a[1]), ensure_ascii=False, indent=1))
    elif cmd == 'watch':
        watch()
    else:
        raise SystemExit('모르는 명령 : ' + cmd)
