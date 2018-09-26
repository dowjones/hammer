from library.aws.rds import RdsSnapshotsChecker
from responses import server_error


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
