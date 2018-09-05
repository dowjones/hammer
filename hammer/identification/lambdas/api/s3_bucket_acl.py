from library.aws.s3 import S3BucketsAclChecker
from responses import server_error


def handler(security_feature, account, config, ids, tags):
    checker = S3BucketsAclChecker(account=account)
    result = []
    if checker.check(buckets=ids):
        buckets = []
        for bucket in checker.buckets:
            buckets.append(f"{bucket.name}")
            if bucket.public:
                result.append({
                    'name': bucket.name,
                    'public_acls': bucket.get_public_acls(),
                })
        response = {
            security_feature: result,
            'checked_buckets': buckets,
        }
        if ids:
            response.setdefault("filterby", {})["ids"] = ids
        if tags:
            response.setdefault("errors", []).append("At the moment, S3 does not offer filtering objects by tags")
        return response
    else:
        return server_error(text="Failed to check s3 public acl")
