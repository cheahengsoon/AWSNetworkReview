import boto3
import csv

# Initialize EC2 client
ec2 = boto3.client('ec2')

# Risky ports to highlight
RISKY_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 1433: "SQL Server", 5432: "PostgreSQL"}

# Get all security groups
sgs = ec2.describe_security_groups()['SecurityGroups']

with open('sg_audit.csv', 'w', newline='') as csvfile:
    fieldnames = [
        'GroupId', 'GroupName', 'Direction', 'Protocol', 'FromPort', 'ToPort',
        'SourceOrDestination', 'SourceType', 'Description', 'Finding'
    ]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()

    for sg in sgs:
        group_id = sg['GroupId']
        group_name = sg['GroupName']

        # Inbound rules
        for rule in sg.get('IpPermissions', []):
            protocol = rule.get('IpProtocol', '')
            from_port = rule.get('FromPort', 0)
            to_port = rule.get('ToPort', 65535)

            for ip_range in rule.get('IpRanges', []):
                source = ip_range.get('CidrIp', '')
                description = ip_range.get('Description', '')
                finding = ''
                if source == '0.0.0.0/0':
                    finding = 'Overly permissive: allows traffic from any IP.'
                    if from_port in RISKY_PORTS or to_port in RISKY_PORTS:
                        finding += f' Risky port open: {RISKY_PORTS.get(from_port, "")}.'

                writer.writerow({
                    'GroupId': group_id,
                    'GroupName': group_name,
                    'Direction': 'Inbound',
                    'Protocol': protocol,
                    'FromPort': from_port,
                    'ToPort': to_port,
                    'SourceOrDestination': source,
                    'SourceType': 'CIDR',
                    'Description': description,
                    'Finding': finding
                })

        # Outbound rules
        for rule in sg.get('IpPermissionsEgress', []):
            protocol = rule.get('IpProtocol', '')
            from_port = rule.get('FromPort', 0)
            to_port = rule.get('ToPort', 65535)

            for ip_range in rule.get('IpRanges', []):
                dest = ip_range.get('CidrIp', '')
                description = ip_range.get('Description', '')
                finding = ''
                if dest == '0.0.0.0/0':
                    finding = 'Overly permissive: allows traffic to any IP.'
                    if from_port in RISKY_PORTS or to_port in RISKY_PORTS:
                        finding += f' Risky port open: {RISKY_PORTS.get(from_port, "")}.'

                writer.writerow({
                    'GroupId': group_id,
                    'GroupName': group_name,
                    'Direction': 'Outbound',
                    'Protocol': protocol,
                    'FromPort': from_port,
                    'ToPort': to_port,
                    'SourceOrDestination': dest,
                    'SourceType': 'CIDR',
                    'Description': description,
                    'Finding': finding
                })

print("Security Group audit exported to sg_audit.csv")
