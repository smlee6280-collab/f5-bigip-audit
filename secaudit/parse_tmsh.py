"""F5 BIG-IP tmsh 설정(bigip.conf, bigip_base.conf, bigip_user.conf, `tmsh list` 출력) 파서.

`a b c { ... }` 형태의 중괄호 계층 구조를 TNode 트리로 변환한다.
iRule(ltm rule)·iCall 스크립트는 Tcl 본문을 파싱하지 않고 원문 그대로 보관한다.
"""
import re

RAW_BLOCK_PREFIXES = ("ltm rule ", "gtm rule ", "sys icall script ", "rule ")


class TNode:
    __slots__ = ("stmts",)

    def __init__(self):
        self.stmts = []   # (tokens, child TNode | None)

    def get(self, key):
        """`key v1 v2` 형태의 값 토큰 리스트."""
        for toks, child in self.stmts:
            if toks and toks[0] == key and child is None:
                return toks[1:]
        return None

    def getstr(self, key, default=None):
        v = self.get(key)
        return " ".join(v) if v is not None else default

    def block(self, key):
        for toks, child in self.stmts:
            if toks and toks[0] == key and child is not None:
                return child
        return None

    def has(self, key):
        return any(toks and toks[0] == key for toks, _ in self.stmts)

    def flat(self):
        """리스트형 블록(allow { a b } 등)의 모든 토큰."""
        out = []
        for toks, child in self.stmts:
            out.extend(toks)
            if child is not None:
                out.extend(child.flat())
        return out

    def named(self):
        """이름 { ... } 형태 자식들: [(name, child)]."""
        return [(toks[0], child) for toks, child in self.stmts if toks and child is not None]


class TmshConfig:
    def __init__(self, root: TNode, raw_blocks: dict, version: str | None):
        self.root = root
        self.raw = raw_blocks   # 이름 -> 원문
        self.version = version

    def objects(self, *prefix):
        """최상위 객체 중 prefix로 시작하는 것: [(name or None, child)]."""
        n = len(prefix)
        out = []
        for toks, child in self.root.stmts:
            if tuple(toks[:n]) == prefix:
                name = toks[n] if len(toks) > n else None
                out.append((name, child if child is not None else TNode()))
        return out

    def obj(self, *prefix):
        o = self.objects(*prefix)
        return o[0][1] if o else None

    def db(self, key):
        node = self.obj("sys", "db", key)
        return node.getstr("value") if node else None


_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|\{|\}|\n|[^\s{}"]+')


def _tokens(text):
    for m in _TOKEN.finditer(text):
        t = m.group(0)
        if t.startswith('"'):
            yield ("W", t[1:-1].replace('\\"', '"'))
        elif t == "\n":
            yield ("NL", None)
        elif t in "{}":
            yield (t, None)
        else:
            yield ("W", t)


def _parse_block(it, node):
    cur = []
    for kind, val in it:
        if kind == "W":
            cur.append(val)
        elif kind == "NL":
            if cur:
                node.stmts.append((cur, None))
                cur = []
        elif kind == "{":
            child = TNode()
            _parse_block(it, child)
            node.stmts.append((cur, child))
            cur = []
        elif kind == "}":
            if cur:
                node.stmts.append((cur, None))
            return
    if cur:
        node.stmts.append((cur, None))


def _extract_raw_blocks(text):
    """Tcl 본문을 가진 블록을 원문으로 분리하고 나머지 텍스트를 반환."""
    raw = {}
    out_lines = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        s = line.strip()
        if s.startswith(RAW_BLOCK_PREFIXES) and s.endswith("{") and not line.startswith((" ", "\t")):
            name = s[:-1].strip()
            depth = line.count("{") - line.count("}")
            body = [line]
            i += 1
            while i < len(lines) and depth > 0:
                depth += lines[i].count("{") - lines[i].count("}")
                body.append(lines[i])
                i += 1
            raw[name] = "\n".join(body)
            out_lines.append(name + " { }")   # 존재 자체는 트리에 남긴다
            continue
        out_lines.append(line)
        i += 1
    return raw, "\n".join(out_lines)


def parse(text: str) -> TmshConfig:
    version = None
    m = re.search(r"#TMSH-VERSION:\s*([\d.]+)", text)
    if m:
        version = m.group(1)
    text = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
    raw, rest = _extract_raw_blocks(text)
    root = TNode()
    _parse_block(iter(list(_tokens(rest))), root)
    return TmshConfig(root, raw, version)
