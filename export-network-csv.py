#!/usr/bin/env python3
"""
aws_network_join.py
Creates unified view by joining all network resources
"""

import boto3
import pandas as pd
from datetime import datetime
import json

def create_unified_table():
    """Create a unified DataFrame from all network resources"""
    
    ec2 = boto3.client('ec2')
    
    # 1. Collect all data
    print("Collecting AWS network data...")
    
    # Get all resources
    network_acls = ec2.describe_network_acls()['NetworkAcls']
    instances = []
    for res in ec2.describe_instances()['Reservations']:
        instances.extend(res['Instances'])
    subnets = ec2.describe_subnets()['Subnets']
    route_tables = ec2.describe_route_tables()['RouteTables']
    security_groups = ec2.describe_security_groups()['SecurityGroups']
    
    # 2. Create DataFrames for each resource type
    print("Creating DataFrames...")
    
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
    
    # 3. Create unified DataFrame
    print("Creating unified table...")
    
    # Convert to DataFrames
    df_acls = pd.DataFrame(acl_data)
    df_instances = pd.DataFrame(instance_data)
    df_subnets = pd.DataFrame(subnet_data)
    df_route_tables = pd.DataFrame(route_table_data)
    df_sgs = pd.DataFrame(sg_data)
    
    # Standardize columns for union
    all_columns = set()
    for df in [df_acls, df_instances, df_subnets, df_route_tables, df_sgs]:
        all_columns.update(df.columns)
    
    # Add missing columns to each DataFrame
    for df in [df_acls, df_instances, df_subnets, df_route_tables, df_sgs]:
        for col in all_columns:
            if col not in df.columns:
                df[col] = None
    
    # Combine all DataFrames
    unified_df = pd.concat([df_acls, df_instances, df_subnets, df_route_tables, df_sgs], 
                          ignore_index=True)
    
    # Reorder columns
    column_order = [
        'ResourceType', 'ResourceID', 'Name', 'VPCID', 'SubnetID', 
        'AvailabilityZone', 'CIDR', 'PrivateIP', 'PublicIP', 'State',
        'InstanceType', 'IsDefault', 'IsMain', 'SecurityGroups',
        'AssociatedSubnets', 'AvailableIPs', 'MapPublicIP',
        'InboundRules', 'OutboundRules', 'RouteCount',
        'Description', 'Tags'
    ]
    
    # Only include columns that exist
    existing_columns = [col for col in column_order if col in unified_df.columns]
    unified_df = unified_df[existing_columns]
    
    # 4. Save to CSV and Excel
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_file = f"aws_network_unified_{timestamp}.csv"
    excel_file = f"aws_network_unified_{timestamp}.xlsx"
    
    unified_df.to_csv(csv_file, index=False)
    
    # Save to Excel with multiple sheets
    with pd.ExcelWriter(excel_file, engine='openpyxl') as writer:
        unified_df.to_excel(writer, sheet_name='Unified', index=False)
        df_instances.to_excel(writer, sheet_name='Instances', index=False)
        df_subnets.to_excel(writer, sheet_name='Subnets', index=False)
        df_acls.to_excel(writer, sheet_name='NetworkACLs', index=False)
        df_route_tables.to_excel(writer, sheet_name='RouteTables', index=False)
        df_sgs.to_excel(writer, sheet_name='SecurityGroups', index=False)
    
    print(f"\nUnified CSV saved to: {csv_file}")
    print(f"Excel workbook saved to: {excel_file}")
    print(f"Total resources: {len(unified_df)}")
    print("\nBreakdown by resource type:")
    print(unified_df['ResourceType'].value_counts())
    
    return unified_df

if __name__ == "__main__":
    df = create_unified_table()
    print("\nFirst 5 rows of unified table:")
    print(df.head())
