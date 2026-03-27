import boto3
import csv

# Initialize EC2 client
ec2 = boto3.client('ec2')

nacls = ec2.describe_network_acls()['NetworkAcls']

with open('nacl_audit.csv', 'w', newline='') as csvfile:
    fieldnames = [
        'NACL_ID', 'RuleNumber', 'Direction', 'RuleAction', 'Protocol',
        'PortFrom', 'PortTo', 'CidrBlock', 'Ipv6CidrBlock', 'Finding'
    ]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()

    for nacl in nacls:
        nacl_id = nacl['NetworkAclId']  # This is your "Rule ID"
        for entry in nacl['Entries']:
            rule_number = entry.get('RuleNumber')
            direction = 'Outbound' if entry.get('Egress') else 'Inbound'
            action = entry.get('RuleAction')
            protocol = entry.get('Protocol')
            
            # Handle port ranges
            if protocol == '-1':  # all protocols
                port_from = 0
                port_to = 65535
            else:
                port_range = entry.get('PortRange', {})
                port_from = port_range.get('From', 0)
                port_to = port_range.get('To', 65535)

            cidr_block = entry.get('CidrBlock', '')
            ipv6_cidr_block = entry.get('Ipv6CidrBlock', '')
            finding = ''

            # Detect overly permissive rules
            if action == 'ALLOW':
                if protocol == '-1' and \
                   (cidr_block == '0.0.0.0/0' or ipv6_cidr_block == '::/0'):
                    finding = f'Overly permissive {direction.lower()} rule: allows all traffic from/to any IP.'

            writer.writerow({
                'NACL_ID': nacl_id,
                'RuleNumber': rule_number,
                'Direction': direction,
                'RuleAction': action,
                'Protocol': protocol,
                'PortFrom': port_from,
                'PortTo': port_to,
                'CidrBlock': cidr_block,
                'Ipv6CidrBlock': ipv6_cidr_block,
                'Finding': finding
            })

print("NACL audit exported to nacl_audit.csv")
