from library.aws.security_groups import SecurityGroupsChecker
from responses import server_error


def handler(security_feature, config, account, ids, tags):
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
