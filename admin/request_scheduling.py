"""Finite pool sweeps and short database transactions for inference requests."""
from admin.account_binding import scope_accounts
from admin.models import Account


class SweepBudget:
    """Try each scoped identity/model pair, plus one connection recovery.

    Socket timeouts still bound each stalled operation. An elapsed-time cutoff
    must not skip healthy identities merely because earlier accounts were slow.
    """
    def __init__(self, accounts, models):
        self.limit = max(1, accounts) * max(1, models) + 1
        self.used = 0

    def available(self):
        return self.used < self.limit

    def consume(self):
        self.used += 1


def release_connection(db):
    """Return the connection before network I/O without expiring loaded data."""
    previous = db.expire_on_commit
    try:
        db.expire_on_commit = False
        db.commit()
    finally:
        db.expire_on_commit = previous


def pool_budget(db, key, models):
    count = scope_accounts(db.query(Account), None, key.id).filter(
        Account.status == 'active').count()
    release_connection(db)
    return SweepBudget(count, len(models))
