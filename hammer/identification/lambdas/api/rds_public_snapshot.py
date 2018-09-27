import logging


from library.aws.rds import RdsSnapshotsChecker, RdsSnapshotOperations
from responses import server_error, bad_request


def identify(security_feature, account, config, ids, tags):
    checker = RdsSnapshotsChecker(account=account)
    result = []
    if checker.check():
        for snapshot in checker.snapshots:
            result.append({
                'name': snapshot.name,
                'db': snapshot.db,
                'engine': snapshot.engine,
            })
        response = {
            security_feature: result
        }
        return response
    else:
        return server_error(text="Failed to check RDS public snapshots")


def remediate(security_feature, account, config, ids, tags):
    response = {
        security_feature: {}
    }

    checker = RdsSnapshotsChecker(account=account)
    if checker.check():
        public_snapshots = [ snapshot.name for snapshot in checker.snapshots ]

        if not ids:
            # remediate all public snapshots if ids was not set
            # ids = public_snapshots
            return bad_request(text=f"'ids' parameter must be set")
        for snapshot_name in ids:
            if snapshot_name in public_snapshots:
                snapshot = checker.get_snapshot(name=snapshot_name)
                try:
                    RdsSnapshotOperations.make_private(account.client("rds"), snapshot.engine, snapshot.name)
                    result = "remediated"
                except Exception:
                    logging.exception(f"Failed to remediate '{snapshot.name} / {snapshot.engine}'")
                    result = "failed"
            else:
                result = "skipped"
            response[security_feature][snapshot_name] = result
        return response
    else:
        return server_error(text="Failed to check RDS snapshots")