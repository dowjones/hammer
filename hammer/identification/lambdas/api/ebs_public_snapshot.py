from library.aws.ebs import EBSPublicSnapshotsChecker
from responses import server_error


def handler(security_feature, account, config, ids, tags):
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
