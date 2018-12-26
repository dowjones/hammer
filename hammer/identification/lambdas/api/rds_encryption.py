from library.aws.rds import RdsEncryptionChecker
from responses import server_error


def identify(security_feature, account, config, ids, tags):
    checker = RdsEncryptionChecker(account=account)
    result = []
    if checker.check():
        for instance in checker.instances:
            result.append({
                'name': instance.name,
                'id': instance.id,
                'engine': instance.engine,
            })
        response = {
            security_feature: result
        }
        return response
    else:
        return server_error(text="Failed to check RDS instance un-encryption")

