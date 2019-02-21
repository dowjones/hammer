from library.aws.iam import IAMKeyChecker
from responses import server_error


def identify(security_feature, account, config, ids, tags):
    checker = IAMKeyChecker(account=account,
                            now=config.now,
                            rotation_criteria_days=config.iamUserKeysRotation.rotation_criteria_days)
    result = []
    if checker.check(users_to_check=ids, last_used_check_enabled=False):
        for user in checker.users:
            if len(user.stale_keys) > 0:
                keys = {}
                for key in user.stale_keys:
                    keys[key.id] = {
                        'create_date': key.create_date.isoformat(),
                    }
                result.append({
                    'user': user.id,
                    'keys': keys,
                })
        response = {
            security_feature: result,
        }
        if ids:
            response.setdefault("filterby", {})["ids"] = ids
        return response
    else:
        return server_error(text="Failed to check IAM stale keys")
