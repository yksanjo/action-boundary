"""Deterministic preflight checks. Not a sandbox or a secrets detector."""
import argparse
import hashlib
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path

OPERATIONS = {'read', 'draft', 'send', 'publish', 'spend', 'delete', 'deploy'}
EFFECTS = {'send', 'publish', 'spend', 'delete', 'deploy'}
ACTION_FIELDS = {'operation', 'destination', 'data_categories', 'amount', 'currency', 'payload_sha256'}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def digest(action):
    return hashlib.sha256(canonical(action).encode()).hexdigest()


def valid_number(n):
    return type(n) in (float, int) and math.isfinite(n) and n >= 0


def evaluate(action, policy, approval=None, now=None):
    """Fail closed on malformed input. No effects are performed."""
    now = now or datetime.now(timezone.utc)
    if type(action) is not dict or type(policy) is not dict:
        return {'decision': 'deny', 'reason': 'invalid input'}
    if set(action) - ACTION_FIELDS:
        return {'decision': 'deny', 'reason': 'unknown action field'}
    op = action.get('operation')
    dest = action.get('destination')
    cats = action.get('data_categories')
    payload = action.get('payload_sha256')
    if (type(op) is not str or op not in OPERATIONS or type(dest) is not str or not dest
            or type(cats) is not list or any(type(c) is not str for c in cats)
            or type(payload) is not str or len(payload) != 64
            or any(c not in '0123456789abcdef' for c in payload)):
        return {'decision': 'deny', 'reason': 'invalid action schema'}
    for key in ('allow_operations', 'allow_destinations', 'deny_data_categories'):
        items = policy.get(key)
        if type(items) is not list or any(type(x) is not str for x in items):
            return {'decision': 'deny', 'reason': 'invalid policy schema'}
    try:
        identity = digest(action)
    except (ValueError, TypeError):
        return {'decision': 'deny', 'reason': 'action is not canonical JSON'}
    result = {'action_sha256': identity}
    def finish(decision, reason):
        return dict(result, decision=decision, reason=reason)
    if op not in policy['allow_operations']:
        return finish('deny', 'operation not allowed')
    if dest not in policy['allow_destinations']:
        return finish('deny', 'destination not allowed (exact match required)')
    if set(cats) & set(policy['deny_data_categories']):
        return finish('deny', 'declared sensitive category is blocked')
    if op == 'spend':
        amount = action.get('amount')
        cap = policy.get('max_amount')
        currency = policy.get('currency')
        if not valid_number(amount) or not valid_number(cap):
            return finish('deny', 'invalid amount or spending cap')
        if type(currency) is not str or not currency or action.get('currency') != currency:
            return finish('deny', 'currency mismatch')
        if amount > cap:
            return finish('deny', 'spending cap exceeded')
    elif 'amount' in action or 'currency' in action:
        return finish('deny', 'amount fields require spend operation')
    if op in EFFECTS:
        if type(approval) is not dict or approval.get('action_sha256') != identity:
            return finish('needs-review', 'exact action approval required')
        try:
            expiry = datetime.fromisoformat(approval['expires_at'].replace('Z', '+00:00'))
            if expiry.tzinfo is None or expiry <= now:
                raise ValueError('expired')
        except (KeyError, ValueError, TypeError, AttributeError):
            return finish('needs-review', 'approval expired or invalid')
        return finish('allow', 'within policy and exact approval present')
    return finish('allow', 'within policy; no external effect')


def audit_record(result, now=None):
    """Deliberately omit bodies, destinations, categories and approval tokens."""
    return dict(result, at=(now or datetime.now(timezone.utc)).isoformat())


def load(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('non-finite JSON')))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--action', required=True)
    parser.add_argument('--policy', required=True)
    parser.add_argument('--approval')
    parser.add_argument('--audit', help='Optional local JSONL file; no raw payload stored')
    args = parser.parse_args()
    try:
        result = evaluate(load(args.action), load(args.policy), load(args.approval) if args.approval else None)
        if args.audit:
            with open(args.audit, 'a', encoding='utf-8') as f:
                f.write(canonical(audit_record(result)) + '\n')
    except (OSError, ValueError, TypeError) as exc:
        print(json.dumps({'decision': 'deny', 'reason': 'input or audit failure', 'error_type': type(exc).__name__}))
        return 2
    print(canonical(result))
    return {'allow': 0, 'needs-review': 3, 'deny': 2}[result['decision']]


if __name__ == '__main__':
    sys.exit(main())
