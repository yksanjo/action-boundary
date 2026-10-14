# action-boundary

Check the exact proposed agent action before a controller lets it send, publish or spend.

## Try the safe demo

```sh
python3 demo.py
```

The synthetic demo requires review, accepts an exact fixture approval, rejects a changed payload and denies declared credential data. It never sends. Fixture approval is not human consent. Keep the trusted controller, policy and real approvals outside the agent's write access.

A small, local preflight check for agent actions. An agent proposes structured JSON. The gate checks an explicit policy and returns `allow`, `needs-review`, or `deny`. It never performs the action.

Python 3.10+, standard library only. No model API, network, telemetry, or private accounts.

## Try it

```sh
python3 -m unittest discover -s tests -v
python3 boundary.py --action examples/action.json --policy examples/policy.json
```

The example returns `needs-review` with exit code 3. `allow` exits 0, and `deny` exits 2. Optional `--audit audit.jsonl` appends a minimal local record.

## Rules

- Only known action fields and operations are accepted.
- Destinations must exactly match the policy allowlist. No wildcard or substring matching.
- Declared sensitive categories can be denied.
- Spending requires a finite nonnegative amount, the policy currency, and a cap.
- Send, publish, spend, delete and deploy always require a reviewed action digest and a timezone-aware future expiry.
- Any change to the proposed action invalidates the reviewed digest.
- Audit records contain the action digest, decision, reason and time. No message body, destination or declared sensitive categories are logged.

## Integration contract

1. A trusted controller hashes the exact payload bytes as SHA-256 and constructs the action metadata.
2. The gate evaluates that metadata against policy held outside the agent's write access.
3. The human reviews the full payload, destination and cost in the controller. A trusted approval store records the returned action digest and expiry.
4. Immediately before execution, the controller recomputes the payload hash and calls the gate again with the protected approval record.
5. The controller performs only the exact reviewed action if the result is `allow`.

An approval record looks like this:

```json
{"action_sha256":"DIGEST_FROM_GATE","expires_at":"2030-01-01T00:00:00Z"}
```

This project does not provide a human approval UI or an authenticated approval store. Passing `--approval` is only a local demonstration of the contract. An agent able to modify policy or approval files can bypass it. An expiry bounds validity, not replay count; there is no single-use approval ledger yet.

## Limits

- Not a security sandbox. A controller must enforce every decision and keep policy and approvals outside agent write access.
- Not a PII detector or redactor. Categories are declarations supplied by the controller, and cannot be trusted if the proposing agent labels its own data. It does not claim to discover undeclared sensitive data.
- A payload hash binds bytes only if the controller computes and rechecks it. The CLI receives metadata, not the payload.
- No executor, credential storage, connectors, cumulative spending ledger, concurrency-safe audit store or cryptographic approval signing.
- An allowlisted destination does not establish a person's identity or permission to disclose.
- Audit hashes may still be sensitive metadata. Protect the local audit file and do not publish it.
- Tests prove these fixture behaviors, not universal agent safety or superiority to any assistant product.

## Tests

22 test cases cover schema errors, exact destination matching, denied categories, nonfinite and negative money, caps and currencies, expired or changed approvals, canonical hashes and audit minimization.

## Roadmap

- Protected, single-use approval ledger with atomic consumption.
- Controller adapter that recomputes hashes from payload bytes.
- Policy fixtures for email and file publication, with synthetic data only.
- Separate optional PII detection module, evaluated for both misses and false alarms before any claims.

## License

MIT. Built as agent infrastructure, not an assistant app.
