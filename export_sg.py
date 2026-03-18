import boto3
import csv

def flatten_rule(sg_id, sg_name, direction, rule, writer):
    ip_protocol = rule.get('IpProtocol', '')
    from_port = rule.get('FromPort')
    to_port = rule.get('ToPort')

    # Format port range
    if from_port is not None and to_port is not None:
        port_range = f"{from_port}-{to_port}"
    else:
        port_range = "All"

    # Handle IPv4 ranges
    for ip_range in rule.get('IpRanges', []):
        cidr = ip_range.get('CidrIp', '')
        desc = ip_range.get('Description', '')
        writer.writerow([sg_id, sg_name, direction, ip_protocol, port_range, cidr, desc])

    # Handle IPv6 ranges
    for ip_range in rule.get('Ipv6Ranges', []):
        cidr = ip_range.get('CidrIpv6', '')
        desc = ip_range.get('Description', '')
        writer.writerow([sg_id, sg_name, direction, ip_protocol, port_range, cidr, desc])

    # Handle referenced security groups
    for user_group in rule.get('UserIdGroupPairs', []):
        src_sg = user_group.get('GroupId', '')
        desc = user_group.get('Description', '')
        writer.writerow([sg_id, sg_name, direction, ip_protocol, port_range, src_sg, desc])


def export_sg_rules_to_csv(output_file='security_groups.csv', region='us-east-1'):
    ec2 = boto3.client('ec2', region_name=region)

    response = ec2.describe_security_groups()
    with open(output_file, mode='w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['GroupId', 'GroupName', 'Direction', 'Protocol', 'PortRange', 'Source/Destination', 'Description'])

        for sg in response['SecurityGroups']:
            sg_id = sg['GroupId']
            sg_name = sg.get('GroupName', '')

            # Inbound rules
            for rule in sg.get('IpPermissions', []):
                flatten_rule(sg_id, sg_name, 'Inbound', rule, writer)

            # Outbound rules
            for rule in sg.get('IpPermissionsEgress', []):
                flatten_rule(sg_id, sg_name, 'Outbound', rule, writer)

    print(f"[+] Exported all security group rules to {output_file}")


if __name__ == "__main__":
    export_sg_rules_to_csv(region="ap-southeast-1")  # change to your AWS region
