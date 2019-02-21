from library.aws.security_groups import SecurityGroupsChecker, RestrictionStatus
from responses import server_error


def identify(security_feature, account, config, ids, tags):
    checker = SecurityGroupsChecker(account=account,
                                    restricted_ports=config.sg.restricted_ports)
    result = []
    if checker.check(ids=ids, tags=tags):
        groups = []
        for sg in checker.groups:
            groups.append(f"{sg.name} / {sg.id}")
            if not sg.restricted:
                permissions = []
                for perm in sg.permissions:
                    for ip_range in perm.ip_ranges:
                        if not ip_range.restricted:
                            permissions.append({
                                'ports': f"{perm.to_port}" if perm.from_port == perm.to_port else f"{perm.from_port}-{perm.to_port}",
                                'protocol': perm.protocol,
                                'cidr': ip_range.cidr,
                            })
                result.append({
                    'id': sg.id,
                    'name': sg.name,
                    'status': sg.status.value,
                    'permissions': permissions,
                })
        response = {
            security_feature: result,
            'checked_groups': groups,
        }
        if ids:
            response.setdefault("filterby", {})["ids"] = ids
        if tags:
            response.setdefault("filterby", {})["tags"] = tags
        return response
    else:
        return server_error(text="Failed to check insecure services")


def remediate(security_feature, account, config, ids, tags):
    response = {
        security_feature: {}
    }

    checker = SecurityGroupsChecker(account=account,
                                restricted_ports=config.sg.restricted_ports)
    if checker.check(ids=ids):
        for sg in checker.groups:
            processed = sg.restrict(RestrictionStatus.OpenCompletely)
            if processed == 0:
                 result = "skipped"
            elif processed is None:
                result = "failed"
            else:
                result = "remediated"
            response[security_feature][sg.id] = result
        return response
    else:
        return server_error(text="Failed to check insecure services")