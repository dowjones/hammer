import pytest


from . import mock_ec2
from library.aws.security_groups import SecurityGroupsChecker
from library.aws.utility import Account


region = "us-west-1"
restricted_ports = [22, 23, 1433, 1521, 3306, 3389, 5432, 27017]
suffix = "/0"

# moto does not support Description for IPRanges
# so it is impossible to distinguish rules while searching for CheckShouldPass
# that's why one rule - one security group
secgroups = {
    "SecurityGroup1": {
        "Description": "World-wide open ports from 20 to 80 (in restricted_ports)",
        "FromPort": 20,
        "ToPort": 80,
        "IpProtocol": "tcp",
        "IpRanges": ["8.8.8.8/32", "4.4.4.0/24", "0.0.0.0/0"],
        "CheckShouldPass": False
    },
    "SecurityGroup2": {
        "Description": "Restricted ports from 20 to 80 (in restricted_ports)",
        "FromPort": 20,
        "ToPort": 80,
        "IpProtocol": "tcp",
        "IpRanges": ["8.8.8.8/32"],
        "CheckShouldPass": False
    },
    "SecurityGroup3": {
        "Description": "World-wide open ports from 80 to 443 (not in restricted_ports)",
        "FromPort": 80,
        "ToPort": 443,
        "IpProtocol": "tcp",
        "IpRanges": ["0.0.0.0/0"],
        "CheckShouldPass": True
    },
    "SecurityGroup4": {
        "Description": "Restricted ports from 80 to 443 (not in restricted_ports)",
        "FromPort": 80,
        "ToPort": 443,
        "IpProtocol": "tcp",
        "IpRanges": ["8.8.8.8/32"],
        "CheckShouldPass": True
    },
    "SecurityGroup5": {
        "Description": "Restricted port 21 (not in restricted_ports)",
        "FromPort": 21,
        "ToPort": 21,
        "IpProtocol": "tcp",
        "IpRanges": ["8.8.8.8/32", "4.4.4.0/24"],
        "CheckShouldPass": True
    },
    "SecurityGroup6": {
        "Description": "World-wide open port 21 (not in restricted_ports)",
        "FromPort": 21,
        "ToPort": 21,
        "IpProtocol": "tcp",
        "IpRanges": ["0.0.0.0/0"],
        "CheckShouldPass": True
    },
    "SecurityGroup7": {
        "Description": f"Restricted port {restricted_ports[0]} (in restricted_ports)",
        "FromPort": restricted_ports[0],
        "ToPort": restricted_ports[0],
        "IpProtocol": "tcp",
        "IpRanges": ["8.8.8.8/32", "4.4.4.0/24"],
        "CheckShouldPass": False
    },
    "SecurityGroup8": {
        "Description": f"World-wide open port {restricted_ports[0]} (in restricted_ports)",
        "FromPort": restricted_ports[0],
        "ToPort": restricted_ports[0],
        "IpProtocol": "tcp",
        "IpRanges": ["0.0.0.0/0", "4.4.4.0/24"],
        "CheckShouldPass": False
    },
    "SecurityGroup9": {
        "Description": f"Restricted by security group port 3306",
        "FromPort": 3306,
        "ToPort": 3306,
        "IpProtocol": "tcp",
        "UserIdGroupPairs": "SecurityGroup1",
        "CheckShouldPass": True
    },
   "SecurityGroup10": {
        "Description": f"World-wide open all protocols",
        "IpProtocol": "-1",
        "IpRanges": ["0.0.0.0/0"],
        "CheckShouldPass": False
    },
    "SecurityGroup11": {
        "Description": f"Restricted all protocols",
        "IpProtocol": "-1",
        "IpRanges": ["10.6.0.0/16"],
        "CheckShouldPass": True
    },
    "SecurityGroup12": {
        "Description": f"World-wide open ESP",
        "IpProtocol": "50",
        "IpRanges": ["0.0.0.0/0"],
        "CheckShouldPass": False
    },
    "SecurityGroup13": {
        "Description": f"Restricted ESP",
        "IpProtocol": "50",
        "IpRanges": ["192.168.0.0/24"],
        "CheckShouldPass": True
    },
    "SecurityGroup14": {
        "Description": f"World-wide open ICMPv6",
        "IpProtocol": "58",
        "IpRanges": ["0.0.0.0/0"],
        "CheckShouldPass": True
    },
    "SecurityGroup15": {
        "Description": f"Restricted ICMPv6 rule",
        "IpProtocol": "58",
        "IpRanges": ["10.0.0.0/8"],
        "CheckShouldPass": True
    },
    "SecurityGroup16": {
        "Description": f"World-wide open ICMPv6 with range types",
        "IpProtocol": "58",
        "FromPort": 1,
        "ToPort": 1024,
        "IpRanges": ["0.0.0.0/0"],
        "CheckShouldPass": True
    },
    "SecurityGroup17": {
        "Description": f"World-wide open ICMP",
        "IpProtocol": "icmp",
        "IpRanges": ["0.0.0.0/0"],
        "CheckShouldPass": True
    },
    "SecurityGroup18": {
        "Description": f"World-wide open ICMP with range types",
        "IpProtocol": "icmp",
        "FromPort": 1,
        "ToPort": 1024,
        "IpRanges": ["0.0.0.0/0"],
        "CheckShouldPass": True
    },
    "SecurityGroup19": {
        "Description": f"Empty security group",
        "CheckShouldPass": True
    },
    "SecurityGroup20": {
        "Description": f"World-wide open TCP with range 0-65535",
        "IpProtocol": "tcp",
        "FromPort": 0,
        "ToPort": 65535,
        "IpRanges": ["0.0.0.0/0"],
        "CheckShouldPass": False
    }
}


def find_rule_prop(group, prop, default):
    try:
        return secgroups[group.name][prop]
    except KeyError:
        return default

def ident_test(arg):
    """
    Used to build identification string for each autogenerated test (for easy recognition of failed tests).

    :param sg_details: dict with information about rules from
                        describe_sec_grps_unrestricted_access.validate_secgrps_unrestricted_access(...)
    :return: identification string with security group name, rule index number and human-readable description.
    """
    #print(jsonDumps(sg_details))
    if isinstance(arg, bool):
        return "remediated" if arg else "original"
    else:
        descr = find_rule_prop(arg, "Description", "default description")
        return f"params: {arg.name} ({descr})"

def pytest_generate_tests(metafunc):
    """
    Entrypoint for tests (built-in pytest function for dynamic generation of test cases).
    """
    # Launch EC2 mocking and env preparation
    mock_ec2.start()
    mock_ec2.create_env(secgroups, region)

    account = Account(region=region)

    checker = SecurityGroupsChecker(account,
                                    restricted_ports=restricted_ports)
    checker.check()
    for sg in checker.groups:
        sg.restrict()

    checker_remediated = SecurityGroupsChecker(account,
                                               restricted_ports=restricted_ports)
    checker_remediated.check()
    groups = [(group, False) for group in checker.groups ]
    groups += [(group, True) for group in checker_remediated.groups ]
    metafunc.parametrize("group,remediated", groups, ids=ident_test)

@pytest.mark.sg
def test_sg(group, remediated):
    """
    Actual testing function.

    :param key_details: dict with information about rules from
                        describe_sec_grps_unrestricted_access.validate_secgrps_unrestricted_access(...)
    :return: nothing, raises AssertionError if actual test result is not matched with expected
    """
    expected = True if remediated else find_rule_prop(group, "CheckShouldPass", True)
    assert expected == group.restricted