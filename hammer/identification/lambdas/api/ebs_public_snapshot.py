import logging


from library.aws.ebs import EBSPublicSnapshotsChecker
from responses import server_error


def identify(security_feature, account, config, ids, tags):
    checker = EBSPublicSnapshotsChecker(account=account)
    result = []
    if checker.check(ids=ids, tags=tags):
        snapshots = []
        for snapshot in checker.snapshots:
            snapshots.append(f"{snapshot.id}")
            if snapshot.public:
                result.append({
                    'id': snapshot.id,
                    'volume_id': snapshot.volume_id,
                })
        response = {
            security_feature: result,
            'checked_snapshots': snapshots,
        }
        return response
    else:
        return server_error(text="Failed to check EBS public snapshots")


def remediate(security_feature, account, config, ids, tags):
    response = {
        security_feature: {}
    }

    checker = EBSPublicSnapshotsChecker(account=account)
    if checker.check(ids=ids):
        for snapshot in checker.snapshots:
            if snapshot.public:
                try:
                    snapshot.make_private()
                    result = "remediated"
                except Exception:
                    logging.exception(f"Failed to remediate '{snapshot.id}'")
                    result = "failed"
            else:
                result = "skipped"
            response[security_feature][snapshot.id] = result
        return response
    else:
        return server_error(text="Failed to check EBS snapshots")
