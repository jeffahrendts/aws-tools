# Name: AWS EC2 Security Group Whitelisting Lambda
# Description:
#  This lambda utilizes AWS EC2 API to append AWS EC2 security group(s) ingress
# rules utlizing boto. This exampl performs an HTTP GET request against a
# specified URI.

import os
import requests
import boto3
import datetime


# Define variables
AWS_REGION = os.environ['AWS_REGION']
URL = "INSERT URL HERE"
GROUP_NAMES = [ "example_ip_whitelist" ]
TIME_STAMP = datetime.now().strftime('%Y%m%d').to_string()

# Instantiate boto client
awsClient = boto3.resource( 'ec2', region_name=AWS_REGION )

# Perform GET request againts provided URL
def getIPAddresses( url ):
    headers = {'content-type': 'application/json'}
    response = requests.get( url=url, headers=headers )
    data = response.json()
    return data

# Retrieve details for a specified security grooup
def getSecurityGroups( groupNames ):
    # Set filter by group name
    filter = [ { "GroupNames" : groupNames } ]
    response = awsClient.describe_security_groups(Filters)
    data = response.json()
    return data

# Appends Security group if difference in IP whitelist
def updateSecurityGroup( group, whiteList ):
    # Temp placeholder for missing cidrs
    missing_cidrs = []
    securityGroupId = group['GroupId']
    securityGroupName = group['GroupName']
    securityGroupPermissions = group['IpPermissions']

    # Search sgPermissions for https/http protocol
    https_list = list(filter(lambda ip_list: ip_list['FromPort'] == 443, securityGroupPermissions))[0]['IpRanges']
    http_list = list(filter(lambda ip_list: ip_list['FromPort'] == 80, securityGroupPermissions))[0]['IpRanges']

    # Find missing IPs for each protocol
    diff_https = set(https_list).difference(whiteList)
    diff_http = set(http_list).difference(whiteList)

    # Extend list with object if not empty
    if diff_https:
        missing_cidrs.extend( createIpPermissions( "https", 443, 443, diff_https ) )

    # Extend list with object if not empty
    if diff_http:
        missing_cidrs.extend( createIpPermissions( "http", 80, 80, diff_http ) )

    # Attempt to update the security group if not empty
    if missing_cidrs:
        try:
            response = awsClient.authorize_security_group_ingress( GroupId=securityGroupId,
                IpPermissions=list)
            # Print Post Message
            print("[INFO] - Appended Security Group Ingress for '[%s]%s' with: %s"
                %(securityGroupId, securityGroupName, missing_cidrs))
        except ClientError as e:
            print("[ERROR] - Failed upating Security Group Ingress for '[%s]%s' with: %s"
                %(securityGroupId, securityGroupName, missing_cidrs))
            print(e)
    else:
        print("[INFO] - Skipping Security Group '[%s]%s'."
            %(securityGroupId, securityGroupName))
    return

# Create list of IP Permissions
def createIpPermissions( protocol, toPort, fromPort, ip_list):
    list = []
    description = "IP Whitelist " + TIME_STAMP
    for ip in ip_list:
        list.append(
            {'IpProtocol': protocol,
            'FromPort': fromPort,
            'ToPort': toPort,
            'IpRanges': [{'CidrIp': ip, 'Description': description }]})
    return list

# Lambda handler
def lambda_handler( event, context ):
    print("[INFO] - Performing GET Request on %s." %URL)
    cidr_list = getIPAddresses( URL )
    print("[INFO] - Returned CIDRs from Request: %s" %cidr_list.to_string())

    print("[INFO] - Retrieving Security Groups: %s" %GROUP_NAMES)
    groups = getSecurityGroups( GROUP_NAMES )
    print("[INFO] - Returned Security: %s" %groups)

    # Loop through security groups
    for group in groups['SecurityGroups']:
        updateSecurityGroup( group, whiteList )
