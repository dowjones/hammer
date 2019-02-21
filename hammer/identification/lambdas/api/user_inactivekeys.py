from library.aws.iam import IAMKeyChecker
from responses import server_error


def identify(security_feature, account, config, ids, tags):
    checker = IAMKeyChecker(account=account,
                            now=config.now,
                            inactive_criteria_days=config.iamUserInactiveKeys.inactive_criteria_days)
    result = []
    if checker.check(users_to_check=ids, last_used_check_enabled=True):
        for user in checker.users:
            if len(user.inactive_keys) > 0:
                keys = {}
                for key in user.inactive_keys:
                    keys[key.id] = {
                        'last_used': key.last_used.isoformat(),
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
        return server_error(text="Failed to check IAM inactive keys")
