import logging


from botocore.exceptions import ClientError
from functools import lru_cache
from collections import namedtuple
from library.aws.utility import convert_tags
from library.utility import timeit


# structure which describes EC2 instance
EC2Instance = namedtuple('EC2Instance', [
    # instance ID
    'id',
    # list with private IPs
    'private_ips',
    # list with public IPs
    'public_ips',
    # dict with tags
    'tags',
    # str with instance state - 'pending'|'running'|'shutting-down'|'terminated'|'stopping'|'stopped'
    'state',
    # boolean if instance has network interfaces in public subnets (with Internet Gateway attached)
    'public_subnet',
    # instance iam profile id and arn details.
    'iam_profile_id'
    ])

# structure which describes EC2 instance
ELB = namedtuple('ELBDetails', [
    # Load Balancer Name
    'id',
    # scheme details of Load balancer
    'scheme',
    # load balancer type (classic or application)
    'elb_type',
    # ELB instance details
    'instances'
    ])


class EC2Operations:
    @staticmethod
    def route_table_inet_facing(ec2_client, route_table):
        """
        Verifying route table gateway points to Internet Gateway or not

        :param ec2_client: EC2 boto3 client
        :param route_table: route table Id

        :return: boolean, True - if route table has entry with Internet Gateway
        """
        for route in route_table["Routes"]:
            if route.get("GatewayId", "").startswith("igw-"):
                logging.debug(f"inet-facing route table {route_table['RouteTableId']}")
                # inet-facing route table
                return True
        logging.debug(f"local route table {route_table['RouteTableId']}")
        # local route table
        return False

    @classmethod
    @lru_cache(maxsize=256)
    def subnet_inet_facing(cls, ec2_client, subnet_id):
        """
        Verifying subnet is public or not

        :param ec2_client: EC2 boto3 client
        :param subnet_id: subnet Id

        :return: boolean, True - if subnet is public
        """
        if subnet_id is None:
            # EC2-Classic ???
            return False

        # explicitly associated route tables
        logging.debug(f"checking if {subnet_id} inet facing")
        route_tables = ec2_client.describe_route_tables(
            DryRun=False,
            Filters=[{
                'Name': 'association.subnet-id',
                'Values': [subnet_id]
            }],
        )["RouteTables"]
        if route_tables == []:
            logging.debug("no explicit route_table<->subnet association -> need to find out main route table")
            subnets = ec2_client.describe_subnets(
                DryRun=False,
                SubnetIds=[subnet_id],
            )['Subnets']
            assert len(subnets) == 1
            vpc_id = subnets[0]['VpcId']
            logging.debug(f"found vpc id - {vpc_id}")
            # main route table (implicit association)
            route_tables = ec2_client.describe_route_tables(
                DryRun=False,
                Filters=[
                    {'Name': 'association.main', 'Values': ['true']},
                    {'Name': 'vpc-id', 'Values': [vpc_id]}
                ]
            )["RouteTables"]
        assert len(route_tables) == 1
        route_table = route_tables[0]
        return cls.route_table_inet_facing(ec2_client, route_table)

    @classmethod
    def get_instance_meta_data(cls, ec2_client, instance_id):
        """ Retrieve instance meta data

        :param ec2_client: boto3 ec2 client
        :param instance_id: instance Id

        :return: Instance details.
        """
        try:
            reservations = ec2_client.describe_instances(InstanceIds=[instance_id])['Reservations']
        except ClientError as err:
            if err.response['Error']['Code'] == "InvalidInstanceID.NotFound":
                return None
            raise

        instance = reservations[0]["Instances"][0]
        private_ips = []
        public_ips = []
        for net_if in instance['NetworkInterfaces']:
            # gather all private and public ip addresses
            for private_ip in net_if['PrivateIpAddresses']:
                private_ips.append(private_ip.get('PrivateIpAddress'))
                public_ips.append(private_ip.get('Association', {}).get('PublicIp'))

        # filter empty/None elements
        private_ips = [ip for ip in private_ips if ip]
        public_ips = [ip for ip in public_ips if ip]

        ec2_instance = EC2Instance(
            id=instance["InstanceId"],
            private_ips=private_ips,
            public_ips=public_ips,
            tags=convert_tags(instance.get("Tags", [])),
            state=instance["State"]["Name"],
            public_subnet=None,
            iam_profile_id=instance.get("IamInstanceProfile", {}).get("Id"),
        )
        return ec2_instance

    @classmethod
    @timeit
    def get_instance_details_of_sg_associated(cls, ec2_client, group_id):
        """ Retrieve instances meta data with security group attached

        :param ec2_client: boto3 ec2 client
        :param group_id: security group id

        :return: list with instance details
        """
        # describe instances with security group attached
        reservations = ec2_client.describe_instances(
            DryRun=False,
            Filters=[{
                'Name': 'network-interface.group-id',
                'Values': [group_id]
            }])["Reservations"]

        ec2_instances = []
        for reservation in reservations:
            for instance in reservation['Instances']:
                public_subnet = False
                instance_private_ips = []
                instance_public_ips = []
                # find all network interfaces with group_id attached
                for net_if in instance['NetworkInterfaces']:
                    if len([ group for group in net_if['Groups'] if group['GroupId'] == group_id ]) > 0:
                        # subnet for current network interface
                        net_if_subnet = net_if.get('SubnetId')
                        # private ip addresses for current network interface
                        net_if_private_ips = []
                        # public ip addresses for current network interface
                        net_if_public_ips = []
                        # gather all private and public ip addresses
                        for private_ip in net_if['PrivateIpAddresses']:
                            net_if_private_ips.append(private_ip.get('PrivateIpAddress'))
                            net_if_public_ips.append(private_ip.get('Association', {}).get('PublicIp'))
                        # filter empty/None elements
                        net_if_private_ips = [ip for ip in net_if_private_ips if ip]
                        net_if_public_ips = [ip for ip in net_if_public_ips if ip]
                        # if current subnet is internet facing mark instance as "running in public subnet"
                        if cls.subnet_inet_facing(ec2_client, net_if_subnet):
                            public_subnet = True
                        # add network interface ips to instance ip list
                        instance_private_ips += net_if_private_ips
                        instance_public_ips += net_if_public_ips

                ec2_instance = EC2Instance(
                    id=instance["InstanceId"],
                    private_ips=instance_private_ips,
                    public_ips=instance_public_ips,
                    tags=convert_tags(instance.get("Tags", [])),
                    state=instance["State"]["Name"],
                    public_subnet=public_subnet,
                    iam_profile_id=instance.get("IamInstanceProfile", {}).get("Id"),
                )
                ec2_instances.append(ec2_instance)
        return ec2_instances

    @classmethod
    @timeit
    def get_elb_details_of_sg_associated(cls, elb_client, elbv2_client, group_id):
        """ Retrieve elb meta data with security group attached
        :param elb_client: boto3 elb client
        :param elbv2_client: boto3 elb v2 client
        :param group_id: security group id
         :return: list with elb details
        """
        # describe elb with security group attached
        elb_details = []

        elb_response = elb_client.describe_load_balancers()["LoadBalancerDescriptions"]
        elb_response += elbv2_client.describe_load_balancers()["LoadBalancers"]

        for elb in elb_response:
            if group_id in elb.get("SecurityGroups", []):
                elb_details.append(
                    ELB(
                        id=elb["LoadBalancerName"],
                        scheme=elb["Scheme"],
                        elb_type=elb.get("Type", "classic"),
                        instances=[ instance['InstanceId'] for instance in elb.get("Instances", []) ],
                    )
                )

        return elb_details