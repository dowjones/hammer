from library.aws.s3 import S3EncryptionChecker
from responses import server_error


def identify(security_feature, account, config, ids, tags):
    checker = S3EncryptionChecker(account=account)
    result = []
    if checker.check(buckets=ids):
        buckets = []
        for bucket in checker.buckets:
            buckets.append(f"{bucket.name}")
            if not bucket.is_encrypted:
                result.append({
                    'name': bucket.name
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
        return server_error(text="Failed to check S3 bucket un-encryption")


def remediate(security_feature, account, config, ids, tags):
    response = {
        security_feature: {}
    }

    checker = S3EncryptionChecker(account=account)
    if checker.check(buckets=ids):
        for bucket in checker.buckets:
            if bucket.is_encrypted:
                result = "skipped"
            else:
                if bucket.encrypt_bucket():
                    result = "remediated"
                else:
                    result = "failed"
            response[security_feature][bucket.name] = result
        return response
    else:
        return server_error(text="Failed to check S3 encryption")