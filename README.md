# AWSNetworkReview
# Common Vulnerabilities in AWS Network Configuration

## **1. Network ACL Vulnerabilities**

| Vulnerability | Description | Severity | Detection Command |
|---------------|-------------|----------|------------------|
| **Overly Permissive Rules** | Allow 0.0.0.0/0 (all traffic) | Critical | `aws ec2 describe-network-acls --query "NetworkAcls[*].{ACL:NetworkAclId, Rules:Entries[?CidrBlock=='0.0.0.0/0']}" --output table` |
| **Missing Deny-All Rule** | No explicit deny at end of rules | High | Check for final rule with 32767 and Deny action |
| **Rule Order Issues** | Higher-numbered rule bypassing restrictions | Medium | `aws ec2 describe-network-acls --query "NetworkAcls[*].{ACL:NetworkAclId, Rules:Entries[?RuleNumber<100 && Action=='allow']}"` |
| **No Logging** | Missing flow logs for ACL | Low | Check VPC Flow Logs configuration |
| **Inconsistent Egress/Ingress** | Mismatched inbound/outbound rules | Medium | Compare egress vs ingress rule counts |

## **2. Subnet Vulnerabilities**

| Vulnerability | Description | Severity | Detection Command |
|---------------|-------------|----------|------------------|
| **Large CIDR Blocks** | /16 or larger subnets increasing attack surface | High | `aws ec2 describe-subnets --query "Subnets[*].{Subnet:SubnetId, CIDR:CidrBlock}[?contains(CidrBlock, '/16') || contains(CidrBlock, '/8')]"` |
| **Public Subnet with Private Resources** | Databases in public subnets | Critical | Check subnet route table for IGW |
| **IP Exhaustion** | Subnets running out of IP addresses | Medium | `aws ec2 describe-subnets --query "Subnets[*].{Subnet:SubnetId, AvailableIPs:AvailableIpAddressCount, TotalIPs:to_number(split(CidrBlock, '/')[1])}[?AvailableIPs/TotalIPs<0.2]"` |
| **Overlapping CIDRs** | VPC peering with overlapping ranges | Critical | Check VPC peering connections |
| **Default VPC Usage** | Using AWS default VPC for production | Medium | `aws ec2 describe-vpcs --filters "Name=isDefault,Values=true"` |

## **3. Route Table Vulnerabilities**

| Vulnerability | Description | Severity | Detection Command |
|---------------|-------------|----------|------------------|
| **Blackhole Routes** | Routes pointing to nonexistent targets | Medium | `aws ec2 describe-route-tables --query "RouteTables[*].{RT:RouteTableId, Routes:Routes[?State=='blackhole']}"` |
| **Overly Permissive Routes** | 0.0.0.0/0 to internet for private subnets | Critical | `aws ec2 describe-route-tables --query "RouteTables[*].{RT:RouteTableId, IGW:Routes[?GatewayId.starts_with('igw-')]} | [?IGW]"` |
| **Missing NAT Gateway** | Private subnets without outbound internet | Low | Check for nat-gateway in routes |
| **Route Propagation Issues** | VPN/DX routes not propagating | Medium | Check route propagation flags |
| **Inconsistent Routing** | Multiple route tables with different paths | Medium | Compare routes across route tables |

## **4. Security Group Vulnerabilities**

| Vulnerability | Description | Severity | Detection Command |
|---------------|-------------|----------|------------------|
| **World-Open Ports** | 0.0.0.0/0 on any port | Critical | `aws ec2 describe-security-groups --query "SecurityGroups[*].{SG:GroupId, Rules:IpPermissions[?IpRanges[?CidrIp=='0.0.0.0/0']]} | [?Rules]" --output table` |
| **Overly Permissive Protocols** | Allow all protocols (-1) | Critical | `aws ec2 describe-security-groups --query "SecurityGroups[*].{SG:GroupId, Rules:IpPermissions[?IpProtocol=='-1']}"` |
| **Large Port Ranges** | Wide port ranges (e.g., 0-65535) | High | `aws ec2 describe-security-groups --query "SecurityGroups[*].{SG:GroupId, Rules:IpPermissions[?(FromPort==0 && ToPort==65535)]}"` |
| **Unused Security Groups** | SGs not attached to any resource | Low | `aws ec2 describe-network-interfaces --query "NetworkInterfaces[*].Groups[].GroupId"` |
| **No Egress Restrictions** | Allowing all outbound traffic | Medium | Check IpPermissionsEgress for 0.0.0.0/0 |
| **Referencing Non-Existent SGs** | SG rules referencing deleted groups | Medium | Check UserIdGroupPairs |
| **Excessive Rules** | More than 50 rules per SG (limits) | Low | Count rules per SG |

## **5. VPC-Level Vulnerabilities**

| Vulnerability | Description | Severity |
|---------------|-------------|----------|
| **DNS Hostname Enabled** | Unintended public DNS resolution | Medium |
| **Default DHCP Options** | Using AmazonProvidedDNS without logging | Low |
| **Missing Flow Logs** | No network traffic monitoring | High |
| **No VPC Endpoints** | Internet egress for AWS services | Medium |
| **Unrestricted NACLs** | Default VPC NACLs allowing all traffic | Critical |

