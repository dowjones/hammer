from library.aws.ebs import EBSUnencryptedVolumesChecker
from responses import server_error


def identify(security_feature, account, config, ids, tags):
    checker = EBSUnencryptedVolumesChecker(account)
    result = []
    if checker.check(ids=ids, tags=tags):
        volumes = []
        for volume in checker.volumes:
            volumes.append(f"{volume.id}")
            if not volume.encrypted:
                result.append({
                    'id': volume.id,
                    'name': volume.name,
                    'state': volume.state,
                })
        response = {
            security_feature: result,
            'checked_volumes': volumes,
        }
        if ids:
            response.setdefault("filterby", {})["ids"] = ids
        if tags:
            response.setdefault("filterby", {})["tags"] = tags
        return response
    else:
        return server_error(text="Failed to check EBS unencrypted volumes")
