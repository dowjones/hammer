from library.aws.s3 import S3BucketsPolicyChecker
from responses import server_error


def handler(security_feature, config, account, ids, tags):
    checker = S3BucketsPolicyChecker(account=account)
    result = []
    if checker.check(buckets=ids, tags=tags):
        buckets = []
        for bucket in checker.buckets:
            buckets.append(f"{bucket.name}")
            if bucket.public:
                result.append({
                    'name': bucket.name,
                })
        response = {
            security_feature: result,
            'checked_buckets': buckets,
        }
        if ids:
            response.setdefault("filterby", {})["ids"] = ids
        if tags:
            response.setdefault("filterby", {})["tags"] = tags
        return response
    else:
        return server_error(text="Failed to check s3 public policies")
