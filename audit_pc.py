import json, re, sys

PATH = '/Users/rayjuggar/.claude/projects/-Users-rayjuggar-Desktop-primcool/d90a6ae5-b603-40cf-b43b-976f8174589d.jsonl'

def text_of(msg):
    if msg is None:
        return ''
    c = msg.get('content')
    if isinstance(c, str):
        return c
    out = []
    if isinstance(c, list):
        for b in c:
            if isinstance(b, dict):
                t = b.get('type')
                if t == 'text':
                    out.append(b.get('text', ''))
                elif t == 'tool_result':
                    rc = b.get('content')
                    if isinstance(rc, str):
                        out.append(rc)
                    elif isinstance(rc, list):
                        for rb in rc:
                            if isinstance(rb, dict) and rb.get('type') == 'text':
                                out.append(rb.get('text', ''))
                elif t == 'tool_use':
                    out.append('[tool_use:%s]' % b.get('name',''))
    return '\n'.join(out)

rows = []
with open(PATH) as f:
    for i, line in enumerate(f):
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except Exception:
            continue
        typ = o.get('type')
        msg = o.get('message') if isinstance(o.get('message'), dict) else None
        if typ in ('user', 'assistant') and msg:
            rows.append((i, typ, text_of(msg)))

print('PARSED rows:', len(rows), file=sys.stderr)

SEEDS = [
    r'\blater\b', r'\bdefer', r'for now', r'not now', r'next time', r'eventually',
    r'\bfuture\b', r'phase\s*2', r'\bv2\b', r'\bTODO\b', r"we'?ll\b", r'we should',
    r'we could', r'leave (that|it|this)', r'\bpunt', r'skip for now', r'come back to',
    r'\bbacklog\b', r"won'?t .{0,20}\byet\b", r"haven'?t", r'still need', r'\bremaining\b',
    r'next step', r'follow.?up', r'another (time|session)', r'nice to have', r'wishlist',
    r'\broadmap\b', r'down the (road|line)', r'\bpostpone', r'\bhold off', r'not yet',
    r'placeholder', r'\bstub\b', r'not implemented', r'\bwip\b', r'out of scope',
    r'didn.?t get to', r'still (need|have) to', r'to be done', r'left to do',
]
pat = re.compile('|'.join(SEEDS), re.IGNORECASE)

hits = []
for (i, typ, txt) in rows:
    for m in pat.finditer(txt):
        s = max(0, m.start()-130)
        e = min(len(txt), m.end()+180)
        snippet = txt[s:e].replace('\n', ' ')
        hits.append((i, typ, m.group(0), snippet))

print('HITS:', len(hits), file=sys.stderr)
with open('/Users/rayjuggar/Desktop/primcool/audit_out.txt', 'w') as fo:
    fo.write('PARSED rows: %d  HITS: %d\n' % (len(rows), len(hits)))
    for (i, typ, kw, sn) in hits:
        fo.write('=== line %d [%s] kw=%r\n' % (i, typ, kw))
        fo.write('    ' + sn + '\n')
