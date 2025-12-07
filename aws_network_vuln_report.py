#!/usr/bin/env python3
"""
aws_network_vuln_report.py
Creates unified view of AWS network resources and scans for common vulnerabilities
"""

import boto3
import pandas as pd
from datetime import datetime
import json

# Vulnerability severity and recommendations
VULNERABILITY_METADATA = {
    'WorldOpenSecurityGroups': {
        'Severity': 'High',
        'Recommendation': 'Restrict ingress rules to specific IPs or CIDR ranges, avoid 0.0.0.0/0.'
    },
    'PublicEC2Instances': {
        'Severity': 'High',
        'Recommendation': 'Remove public IPs from sensitive instances or place behind a NAT/Load Balancer.'
    },
    'PublicRDSInstances': {
        'Severity': 'High',
        'Recommendation': 'Move RDS instances to private subnets, restrict access via security groups.'
    },
    'SGAllowAllProtocols': {
        'Severity': 'Medium',
        'Recommendation': 'Limit protocols to only necessary ones, avoid -1 (all protocols).'
    },
    'PermissiveNACLs': {
        'Severity': 'Medium',
        'Recommendation': 'Restrict ACL rules to minimum required ports and IP ranges.'
    },
    'DefaultVPCs': {
        'Severity': 'Low',
        'Recommendation': 'Avoid using default VPCs for production workloads.'
    },
    'UnencryptedVolumes': {
        'Severity': 'High',
        'Recommendation': 'Encrypt EBS volumes and RDS storage at rest.'
    },
    'InstancesNoIAMRole': {
        'Severity': 'Medium',
        'Recommendation': 'Assign IAM roles with least privilege to all instances.'
    },
    'RouteTablesIGW': {
        'Severity': 'Medium',
        'Recommendation': 'Ensure private subnets do not have routes to an Internet Gateway unless required.'
    },
    'SubnetsNoFlowLogs': {
        'Severity': 'Low',
        'Recommendation': 'Enable VPC Flow Logs for monitoring and troubleshooting.'
    }
}

def create_unified_table():
    """Create a unified DataFrame from all network resources"""
    ec2 = boto3.client('ec2')

    print("Collecting AWS network data...")

    # Network resources
    network_acls = ec2.describe_network_acls()['NetworkAcls']
    instances = []
    for res in ec2.describe_instances()['Reservations']:
        instances.extend(res['Instances'])
    subnets = ec2.describe_subnets()['Subnets']
    route_tables = ec2.describe_route_tables()['RouteTables']
    security_groups = ec2.describe_security_groups()['SecurityGroups']

    # Network ACLs DataFrame
    acl_data = []
    for acl in network_acls:
        subnet_ids = [a['SubnetId'] for a in acl.get('Associations', []) if 'SubnetId' in a]
        acl_data.append({
            'ResourceType': 'NetworkACL',
            'ResourceID': acl['NetworkAclId'],
            'VPCID': acl['VpcId'],
            'SubnetIDs': ';'.join(subnet_ids),
            'IsDefault': acl['IsDefault'],
            'IngressRules': len([e for e in acl.get('Entries', []) if not e.get('Egress', True)]),
            'EgressRules': len([e for e in acl.get('Entries', []) if e.get('Egress', False)]),
            'Tags': json.dumps({tag['Key']: tag['Value'] for tag in acl.get('Tags', [])})
        })

    # Instances DataFrame
    instance_data = []
    for instance in instances:
        security_group_ids = [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
        name_tag = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), '')
        instance_data.append({
            'ResourceType': 'EC2-Instance',
            'ResourceID': instance['InstanceId'],
            'Name': name_tag,
            'VPCID': instance.get('VpcId', ''),
            'SubnetID': instance.get('SubnetId', ''),
            'AvailabilityZone': instance.get('Placement', {}).get('AvailabilityZone', ''),
            'PrivateIP': instance.get('PrivateIpAddress', ''),
            'PublicIP': instance.get('PublicIpAddress', ''),
            'State': instance['State']['Name'],
            'InstanceType': instance['InstanceType'],
            'SecurityGroups': ';'.join(security_group_ids),
            'Tags': json.dumps({tag['Key']: tag['Value'] for tag in instance.get('Tags', [])})
        })

    # Subnets DataFrame
    subnet_data = []
    for subnet in subnets:
        name_tag = next((tag['Value'] for tag in subnet.get('Tags', []) if tag['Key'] == 'Name'), '')
        subnet_data.append({
            'ResourceType': 'Subnet',
            'ResourceID': subnet['SubnetId'],
            'Name': name_tag,
            'VPCID': subnet['VpcId'],
            'SubnetID': subnet['SubnetId'],
            'AvailabilityZone': subnet['AvailabilityZone'],
            'CIDR': subnet['CidrBlock'],
            'AvailableIPs': subnet['AvailableIpAddressCount'],
            'MapPublicIP': subnet.get('MapPublicIpOnLaunch', False),
            'Tags': json.dumps({tag['Key']: tag['Value'] for tag in subnet.get('Tags', [])})
        })

    # Route Tables DataFrame
    route_table_data = []
    for rt in route_tables:
        subnet_assocs = [a['SubnetId'] for a in rt.get('Associations', []) if 'SubnetId' in a]
        is_main = any(a.get('Main', False) for a in rt.get('Associations', []))
        name_tag = next((tag['Value'] for tag in rt.get('Tags', []) if tag['Key'] == 'Name'), '')
        route_table_data.append({
            'ResourceType': 'RouteTable',
            'ResourceID': rt['RouteTableId'],
            'Name': name_tag,
            'VPCID': rt['VpcId'],
            'AssociatedSubnets': ';'.join(subnet_assocs),
            'IsMain': is_main,
            'RouteCount': len(rt.get('Routes', [])),
            'Tags': json.dumps({tag['Key']: tag['Value'] for tag in rt.get('Tags', [])})
        })

    # Security Groups DataFrame
    sg_data = []
    for sg in security_groups:
        sg_data.append({
            'ResourceType': 'SecurityGroup',
            'ResourceID': sg['GroupId'],
            'Name': sg['GroupName'],
            'VPCID': sg.get('VpcId', ''),
            'Description': sg.get('Description', ''),
            'InboundRules': len(sg.get('IpPermissions', [])),
            'OutboundRules': len(sg.get('IpPermissionsEgress', [])),
            'Tags': json.dumps({tag['Key']: tag['Value'] for tag in sg.get('Tags', [])})
        })

    # Combine all DataFrames
    dfs = [pd.DataFrame(d) for d in [acl_data, instance_data, subnet_data, route_table_data, sg_data]]
    all_columns = set(col for df in dfs for col in df.columns)
    for df in dfs:
        for col in all_columns:
            if col not in df.columns:
                df[col] = None
    unified_df = pd.concat(dfs, ignore_index=True)

    column_order = [
        'ResourceType', 'ResourceID', 'Name', 'VPCID', 'SubnetID', 
        'AvailabilityZone', 'CIDR', 'PrivateIP', 'PublicIP', 'State',
        'InstanceType', 'IsDefault', 'IsMain', 'SecurityGroups',
        'AssociatedSubnets', 'AvailableIPs', 'MapPublicIP',
        'InboundRules', 'OutboundRules', 'RouteCount',
        'Description', 'Tags'
    ]
    existing_columns = [col for col in column_order if col in unified_df.columns]
    unified_df = unified_df[existing_columns]

    return unified_df

# ----------------- Vulnerability Scan ----------------- #
def scan_aws_network_vulnerabilities_extended():
    """Scan AWS networking resources for common vulnerabilities (extended) and return DataFrames"""
    ec2 = boto3.client('ec2')
    rds = boto3.client('rds')
    vulnerabilities = {}

    # 1. World-open Security Groups
    world_open_sgs = []
    for sg in ec2.describe_security_groups()['SecurityGroups']:
        for perm in sg.get('IpPermissions', []):
            for ip_range in perm.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    world_open_sgs.append({
                        'GroupId': sg['GroupId'],
                        'GroupName': sg['GroupName'],
                        'VpcId': sg.get('VpcId'),
                        'FromPort': perm.get('FromPort'),
                        'ToPort': perm.get('ToPort'),
                        'Protocol': perm.get('IpProtocol')
                    })
    vulnerabilities['WorldOpenSecurityGroups'] = pd.DataFrame(world_open_sgs)

    # 2. Publicly Accessible EC2 Instances
    public_instances = []
    for res in ec2.describe_instances()['Reservations']:
        for inst in res['Instances']:
            if 'PublicIpAddress' in inst:
                public_instances.append({
                    'InstanceId': inst['InstanceId'],
                    'PublicIP': inst['PublicIpAddress'],
                    'State': inst['State']['Name'],
                    'VpcId': inst.get('VpcId'),
                    'SecurityGroups': ';'.join([sg['GroupId'] for sg in inst.get('SecurityGroups', [])])
                })
    vulnerabilities['PublicEC2Instances'] = pd.DataFrame(public_instances)

    # 3. Publicly Accessible RDS Instances
    public_rds = []
    for db in rds.describe_db_instances()['DBInstances']:
        if db.get('PubliclyAccessible'):
            public_rds.append({
                'DBInstanceIdentifier': db['DBInstanceIdentifier'],
                'Engine': db['Engine'],
                'DBInstanceClass': db['DBInstanceClass'],
                'VPCId': db.get('DBSubnetGroup', {}).get('VpcId'),
                'Endpoint': db.get('Endpoint', {}).get('Address')
            })
    vulnerabilities['PublicRDSInstances'] = pd.DataFrame(public_rds)

    # 4. Security Groups Allowing All Protocols (-1)
    sg_all_protocols = []
    for sg in ec2.describe_security_groups()['SecurityGroups']:
        for perm in sg.get('IpPermissions', []):
            if perm.get('IpProtocol') == '-1':
                sg_all_protocols.append({
                    'GroupId': sg['GroupId'],
                    'GroupName': sg['GroupName'],
                    'VpcId': sg.get('VpcId')
                })
    vulnerabilities['SGAllowAllProtocols'] = pd.DataFrame(sg_all_protocols)

    # 5. Network ACLs with permissive rules
    permissive_acls = []
    for acl in ec2.describe_network_acls()['NetworkAcls']:
        for entry in acl.get('Entries', []):
            cidr = entry.get('CidrBlock', '')
            action = entry.get('RuleAction', '')
            if cidr == '0.0.0.0/0' and action.lower() == 'allow':
                permissive_acls.append({
                    'NetworkAclId': acl['NetworkAclId'],
                    'VpcId': acl['VpcId'],
                    'RuleNumber': entry['RuleNumber'],
                    'Protocol': entry['Protocol'],
                    'PortRange': entry.get('PortRange'),
                    'Egress': entry.get('Egress')
                })
    vulnerabilities['PermissiveNACLs'] = pd.DataFrame(permissive_acls)

    # 6. Default VPCs
    default_vpcs = []
    for vpc in ec2.describe_vpcs(Filters=[{'Name':'isDefault','Values':['true']}])['Vpcs']:
        default_vpcs.append({
            'VpcId': vpc['VpcId'],
            'CidrBlock': vpc['CidrBlock']
        })
    vulnerabilities['DefaultVPCs'] = pd.DataFrame(default_vpcs)

    # 7. Unencrypted Volumes
    unencrypted_vols = []
    for vol in ec2.describe_volumes(Filters=[{'Name':'encrypted','Values':['false']}])['Volumes']:
        unencrypted_vols.append({
            'VolumeId': vol['VolumeId'],
            'Size': vol['Size'],
            'AvailabilityZone': vol['AvailabilityZone'],
            'Attachments': ';'.join([att['InstanceId'] for att in vol.get('Attachments', [])])
        })
    vulnerabilities['UnencryptedVolumes'] = pd.DataFrame(unencrypted_vols)

    # 8. Instances without IAM roles
    instances_no_iam = []
    for res in ec2.describe_instances()['Reservations']:
        for inst in res['Instances']:
            if 'IamInstanceProfile' not in inst:
                instances_no_iam.append({
                    'InstanceId': inst['InstanceId'],
                    'State': inst['State']['Name'],
                    'VpcId': inst.get('VpcId')
                })
    vulnerabilities['InstancesNoIAMRole'] = pd.DataFrame(instances_no_iam)

    # 9. Route Tables with Internet Gateway exposure
    route_tables = ec2.describe_route_tables()['RouteTables']
    exposed_routes = []
    for rt in route_tables:
        for route in rt.get('Routes', []):
            gw = route.get('GatewayId', '')
            if gw and gw.startswith('igw-'):
                exposed_routes.append({
                    'RouteTableId': rt['RouteTableId'],
                    'VpcId': rt['VpcId'],
                    'DestinationCidr': route.get('DestinationCidrBlock')
                })
    vulnerabilities['RouteTablesIGW'] = pd.DataFrame(exposed_routes)

    # 10. Subnets without VPC Flow Logs
    flow_logs = ec2.describe_flow_logs()['FlowLogs']
    vpcs_with_logs = set([fl['ResourceId'] for fl in flow_logs])
    subnets_no_logs = []
    for subnet in ec2.describe_subnets()['Subnets']:
        if subnet['VpcId'] not in vpcs_with_logs:
            subnets_no_logs.append({
                'SubnetId': subnet['SubnetId'],
                'VpcId': subnet['VpcId'],
                'CidrBlock': subnet['CidrBlock']
            })
    vulnerabilities['SubnetsNoFlowLogs'] = pd.DataFrame(subnets_no_logs)

    # Add severity & recommendation
    for sheet_name, vuln_df in vulnerabilities.items():
        meta = VULNERABILITY_METADATA.get(sheet_name, {})
        if not vuln_df.empty:
            vuln_df['Severity'] = meta.get('Severity', 'N/A')
            vuln_df['Recommendation'] = meta.get('Recommendation', 'N/A')
        vulnerabilities[sheet_name] = vuln_df

    return vulnerabilities

# ----------------- Main ----------------- #
if __name__ == "__main__":
    # Unified network table
    unified_df = create_unified_table()
    print("\nFirst 5 rows of unified table:")
    print(unified_df.head())

    # Run extended vulnerability scan
    vuln_dfs = scan_aws_network_vulnerabilities_extended()

    # Export to Excel
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    excel_file = f"aws_network_unified_and_vulns_{timestamp}.xlsx"

    with pd.ExcelWriter(excel_file, engine='openpyxl') as writer:
        # Unified table
        unified_df.to_excel(writer, sheet_name='Unified', index=False)
        # Vulnerability sheets
        for sheet_name, df_vuln in vuln_dfs.items():
            sheet_name_safe = sheet_name[:31]  # Excel sheet name limit
            df_vuln.to_excel(writer, sheet_name=sheet_name_safe, index=False)

    print(f"\nExcel workbook with unified table and vulnerabilities saved to: {excel_file}")
