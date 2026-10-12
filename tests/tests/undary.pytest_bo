import copy
import unittest
from datetime import datetime, timezone
from boundary import evaluate, digest, audit_record

NOW = datetime(2026, 10, 12, tzinfo=timezone.utc)
POLICY = {'allow_operations': ['read', 'draft', 'send', 'publish', 'spend', 'delete', 'deploy'],
          'allow_destinations': ['fixture:inbox'], 'deny_data_categories': ['credential', 'health'],
          'max_amount': 10, 'currency': 'USD'}
ACTION = {'operation': 'send', 'destination': 'fixture:inbox', 'data_categories': [], 'payload_sha256': 'a' * 64}

class BoundaryTests(unittest.TestCase):
    def check(self, expected, action=None, policy=None, approval=None):
        self.assertEqual(evaluate(action or ACTION, policy or POLICY, approval, NOW)['decision'], expected)
    def test_review_required(self): self.check('needs-review')
    def test_approval(self): self.check('allow', approval={'action_sha256': digest(ACTION), 'expires_at': '2026-10-13T00:00:00Z'})
    def test_expired(self): self.check('needs-review', approval={'action_sha256': digest(ACTION), 'expires_at': '2026-10-11T00:00:00Z'})
    def test_naive_expiry(self): self.check('needs-review', approval={'action_sha256': digest(ACTION), 'expires_at': '2026-10-13'})
    def test_wrong_hash(self): self.check('needs-review', approval={'action_sha256': 'wrong', 'expires_at': '2026-10-13T00:00:00Z'})
    def test_mutation(self):
        for field, value in [('destination','fixture:other'), ('operation','publish'), ('payload_sha256','b'*64), ('data_categories',['contact'])]:
            a = dict(ACTION, **{field:value})
            r = evaluate(a, POLICY, {'action_sha256':digest(ACTION),'expires_at':'2026-10-13T00:00:00Z'}, NOW)
            self.assertNotEqual(r['decision'], 'allow')
    def test_unknown_operation(self): self.check('deny', dict(ACTION, operation='shell'))
    def test_extra_body_rejected(self): self.check('deny', dict(ACTION, body='secret'))
    def test_destination_exact(self): self.check('deny', dict(ACTION, destination='fixture:inbox.attacker'))
    def test_category(self): self.check('deny', dict(ACTION, data_categories=['health']))
    def test_missing_category(self):
        a=copy.deepcopy(ACTION); del a['data_categories']; self.check('deny',a)
    def test_invalid_categories(self): self.check('deny',dict(ACTION,data_categories='credential'))
    def test_unhashable_operation(self): self.check('deny',dict(ACTION,operation=[]))
    def test_bad_payload_digest(self): self.check('deny',dict(ACTION,payload_sha256='Z'*64))
    def test_read(self): self.check('allow',dict(ACTION,operation='read'))
    def test_no_money_on_read(self): self.check('deny',dict(ACTION,operation='read',amount=1))
    def test_spend_caps(self):
        for amount in [-1, float('nan'), float('inf'), True, '1', 11]:
            self.check('deny',dict(ACTION,operation='spend',amount=amount,currency='USD'))
    def test_spend_at_cap(self): self.check('needs-review',dict(ACTION,operation='spend',amount=10,currency='USD'))
    def test_currency(self): self.check('deny',dict(ACTION,operation='spend',amount=1,currency='EUR'))
    def test_policy_validation(self): self.check('deny',policy={'allow_operations':'send'})
    def test_audit_no_payload(self):
        record=audit_record(evaluate(ACTION,POLICY),NOW)
        self.assertFalse(set(record)&{'destination','data_categories','payload_sha256','body'})
    def test_hash_key_order(self): self.assertEqual(digest(ACTION),digest(dict(reversed(list(ACTION.items())))))

if __name__ == '__main__': unittest.main()
