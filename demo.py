"""Synthetic policy demo. No operation is executed and no approval file is written."""
from datetime import datetime, timedelta, timezone
from boundary import evaluate, digest

now = datetime.now(timezone.utc)
policy = {'allow_operations':['send'], 'allow_destinations':['fixture:inbox'],
          'deny_data_categories':['credential']}
action = {'operation':'send', 'destination':'fixture:inbox', 'data_categories':[],
          'payload_sha256':'a'*64}
review = evaluate(action, policy, now=now)
assert review['decision']=='needs-review'
print('1. Unreviewed action:', review['decision'])
# Fixture approval stands in for a trusted controller, not real human consent.
approval = {'action_sha256':digest(action), 'expires_at':(now+timedelta(minutes=1)).isoformat()}
assert evaluate(action,policy,approval,now)['decision']=='allow'
print('2. Matching fixture approval: allow')
changed = dict(action,payload_sha256='b'*64)
assert evaluate(changed,policy,approval,now)['decision']=='needs-review'
print('3. Changed payload: needs-review')
blocked = dict(action,data_categories=['credential'])
assert evaluate(blocked,policy,approval,now)['decision']=='deny'
print('4. Declared credential data: deny')
print('No message sent. No operation executed.');
