import boto3

# Constants
TAG_KEY = 'Environment'
TAG_VALUE = 'prod'
ADDITIONAL_TAGS = {
    'Department': 'Digital Transformation',
    'ApplicationName': 'MT-Capitalization',
    'CreatedBy': 'DevOps Automation',
    'ManagedBy': 'DevOps Digital Transformation',
    'BusinessUnit': 'Information Technology',
    'Product': 'MT-Capitalization',
    'project': 'MT-Capitalization',
    'Env': 'PROD',
    'MaintenanceSchedule': 'ad-hoc'
}

REGION = 'us-east-2'

def tag_ec2_instances_and_volumes():
    ec2_client = boto3.client('ec2', region_name=REGION)
    
    response = ec2_client.describe_instances()
    instance_ids = []
    volume_ids = []
    nat_gateway_ids = []
    
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            instance_ids.append(instance['InstanceId'])
            for block_device in instance['BlockDeviceMappings']:
                if 'Ebs' in block_device:
                    volume_ids.append(block_device['Ebs']['VolumeId'])
            
            # Check for associated NAT gateway
            if 'NetworkInterfaces' in instance:
                for iface in instance['NetworkInterfaces']:
                    if 'Attachment' in iface and 'NatGatewayId' in iface['Attachment']:
                        nat_gateway_ids.append(iface['Attachment']['NatGatewayId'])
    
    tags = [{'Key': TAG_KEY, 'Value': TAG_VALUE}]
    tags += [{'Key': key, 'Value': value} for key, value in ADDITIONAL_TAGS.items()]
    
    if instance_ids:
        ec2_client.create_tags(Resources=instance_ids, Tags=tags)
        print(f"Tags applied to instances: {instance_ids}")
    else:
        print("No instances found to tag.")
    
    if volume_ids:
        ec2_client.create_tags(Resources=volume_ids, Tags=tags)
        print(f"Tags applied to volumes: {volume_ids}")
    else:
        print("No volumes found to tag.")
    
    if nat_gateway_ids:
        ec2_client.create_tags(Resources=nat_gateway_ids, Tags=tags)
        print(f"Tags applied to NAT gateways: {nat_gateway_ids}")
    else:
        print("No NAT gateways found to tag.")

def tag_vpcs():
    ec2_client = boto3.client('ec2', region_name=REGION)
    vpc_ids = [vpc['VpcId'] for vpc in ec2_client.describe_vpcs()['Vpcs']]
    
    tags = [{'Key': TAG_KEY, 'Value': TAG_VALUE}]
    tags += [{'Key': key, 'Value': value} for key, value in ADDITIONAL_TAGS.items()]
    
    for vpc_id in vpc_ids:
        ec2_client.create_tags(Resources=[vpc_id], Tags=tags)
        print(f"Tags applied to VPC: {vpc_id}")
        
def tag_rds_instances():
    rds_client = boto3.client('rds', region_name=REGION)
    
    response = rds_client.describe_db_instances()
    db_instance_arns = [db_instance['DBInstanceArn'] for db_instance in response['DBInstances']]
    
    tags = [{'Key': TAG_KEY, 'Value': TAG_VALUE}]
    tags += [{'Key': key, 'Value': value} for key, value in ADDITIONAL_TAGS.items()]
    
    for db_instance_arn in db_instance_arns:
        rds_client.add_tags_to_resource(
            ResourceName=db_instance_arn,
            Tags=tags
        )
        print(f"Tags applied to RDS instance: {db_instance_arn}")

def tag_ecs_resources():
    ecs_client = boto3.client('ecs', region_name=REGION)
    
    clusters = ecs_client.list_clusters()['clusterArns']
    
    tags = [{'key': TAG_KEY, 'value': TAG_VALUE}]
    tags += [{'key': key, 'value': value} for key, value in ADDITIONAL_TAGS.items()]
    
    for cluster_arn in clusters:
        ecs_client.tag_resource(resourceArn=cluster_arn, tags=tags)
        print(f"Tags applied to ECS cluster: {cluster_arn}")
        
        services = ecs_client.list_services(cluster=cluster_arn)['serviceArns']
        for service_arn in services:
            ecs_client.tag_resource(resourceArn=service_arn, tags=tags)
            print(f"Tags applied to ECS service: {service_arn}")
            
def tag_ecs_task_definitions():
    ecs_client = boto3.client('ecs', region_name=REGION)
    
    task_definitions = ecs_client.list_task_definitions()['taskDefinitionArns']
    
    tags = [{'key': TAG_KEY, 'value': TAG_VALUE}]
    tags += [{'key': key, 'value': value} for key, value in ADDITIONAL_TAGS.items()]
    
    for task_definition_arn in task_definitions:
        ecs_client.tag_resource(resourceArn=task_definition_arn, tags=tags)
        print(f"Tags applied to ECS task definition: {task_definition_arn}")

def tag_ecr_repositories():
    ecr_client = boto3.client('ecr', region_name=REGION)
    
    repositories = ecr_client.describe_repositories()['repositories']
    
    tags = [{'Key': TAG_KEY, 'Value': TAG_VALUE}]
    tags += [{'Key': key, 'Value': value} for key, value in ADDITIONAL_TAGS.items()]
    
    for repo in repositories:
        ecr_client.tag_resource(
            resourceArn=repo['repositoryArn'],
            tags=tags
        )
        print(f"Tags applied to ECR repository: {repo['repositoryName']}")

def tag_cloudwatch_log_groups():
    logs_client = boto3.client('logs', region_name=REGION)
    
    log_groups = logs_client.describe_log_groups()['logGroups']
    
    tags = [{'Key': TAG_KEY, 'Value': TAG_VALUE}]
    tags += [{'Key': key, 'Value': value} for key, value in ADDITIONAL_TAGS.items()]
    
    for log_group in log_groups:
        logs_client.tag_log_group(
            logGroupName=log_group['logGroupName'],
            tags={tag['Key']: tag['Value'] for tag in tags}
        )
        print(f"Tags applied to CloudWatch log group: {log_group['logGroupName']}")
        
def tag_albs():
    elbv2_client = boto3.client('elbv2', region_name=REGION)
    alb_arns = [alb['LoadBalancerArn'] for alb in elbv2_client.describe_load_balancers()['LoadBalancers']]
    
    tags = [{'Key': TAG_KEY, 'Value': TAG_VALUE}]
    tags += [{'Key': key, 'Value': value} for key, value in ADDITIONAL_TAGS.items()]
    
    for alb_arn in alb_arns:
        elbv2_client.add_tags(
            ResourceArns=[alb_arn],
            Tags=tags
        )
        print(f"Tags applied to ALB: {alb_arn}")
        
def tag_secrets_manager():
    secrets_client = boto3.client('secretsmanager', region_name=REGION)
    
    secrets = secrets_client.list_secrets()['SecretList']
    
    tags = [{'Key': TAG_KEY, 'Value': TAG_VALUE}]
    tags += [{'Key': key, 'Value': value} for key, value in ADDITIONAL_TAGS.items()]
    
    for secret in secrets:
        secrets_client.tag_resource(
            SecretId=secret['ARN'],
            Tags=tags
        )
        print(f"Tags applied to Secrets Manager secret: {secret['Name']}")
        
def tag_s3_buckets():
    s3_client = boto3.client('s3')
    buckets = [bucket['Name'] for bucket in s3_client.list_buckets()['Buckets']]
    
    tags = [{'Key': TAG_KEY, 'Value': TAG_VALUE}]
    tags += [{'Key': key, 'Value': value} for key, value in ADDITIONAL_TAGS.items()]
    
    for bucket in buckets:
        s3_client.put_bucket_tagging(
            Bucket=bucket,
            Tagging={
                'TagSet': tags
            }
        )
        print(f"Tags applied to S3 bucket: {bucket}") 
        
def tag_dynamo_db_tables():
    dynamodb_client = boto3.client('dynamodb', region_name=REGION)
    
    tables = dynamodb_client.list_tables()['TableNames']
    
    tags = [{'Key': TAG_KEY, 'Value': TAG_VALUE}]
    tags += [{'Key': key, 'Value': value} for key, value in ADDITIONAL_TAGS.items()]
    
    for table_name in tables:
        table_arn = dynamodb_client.describe_table(TableName=table_name)['Table']['TableArn']
        dynamodb_client.tag_resource(
            ResourceArn=table_arn,
            Tags=tags
        )
        print(f"Tags applied to DynamoDB table: {table_name}")
        
def tag_cloudfront_distributions():
    cloudfront_client = boto3.client('cloudfront', region_name=REGION)
    
    distributions = cloudfront_client.list_distributions()['DistributionList'].get('Items', [])
    
    tags = {
        'Items': [{'Key': TAG_KEY, 'Value': TAG_VALUE}]
    }
    for key, value in ADDITIONAL_TAGS.items():
        tags['Items'].append({'Key': key, 'Value': value})
    
    for distribution in distributions:
        distribution_id = distribution['Id']
        distribution_arn = f"arn:aws:cloudfront::1234567890:distribution/{distribution_id}"
        cloudfront_client.tag_resource(
            Resource=distribution_arn,
            Tags=tags
        )
        print(f"Tags applied to CloudFront distribution: {distribution_id}")
        
def tag_sqs_queues():
    sqs_client = boto3.client('sqs', region_name=REGION)
    
    queues = sqs_client.list_queues()['QueueUrls']
    
    tags = [{'Key': TAG_KEY, 'Value': TAG_VALUE}]
    tags += [{'Key': key, 'Value': value} for key, value in ADDITIONAL_TAGS.items()]
    
    for queue_url in queues:
        queue_name = queue_url.split('/')[-1]
        sqs_client.tag_queue(
            QueueUrl=queue_url,
            Tags={tag['Key']: tag['Value'] for tag in tags}
        )
        print(f"Tags applied to SQS queue: {queue_url}")
        
def tag_sns_topics():
    sns_client = boto3.client('sns', region_name=REGION)
    
    topics = sns_client.list_topics()['Topics']
    
    tags = [{'Key': TAG_KEY, 'Value': TAG_VALUE}]
    tags += [{'Key': key, 'Value': value} for key, value in ADDITIONAL_TAGS.items()]
    
    for topic in topics:
        sns_client.tag_resource(
            ResourceArn=topic['TopicArn'],
            Tags=tags
        )
        print(f"Tags applied to SNS topic: {topic['TopicArn']}")
        
def tag_lambda_functions():
    lambda_client = boto3.client('lambda', region_name=REGION)
    
    functions = lambda_client.list_functions()['Functions']
    
    tags = [{'Key': TAG_KEY, 'Value': TAG_VALUE}]
    tags += [{'Key': key, 'Value': value} for key, value in ADDITIONAL_TAGS.items()]
    
    for function in functions:
        lambda_client.tag_resource(
            Resource=function['FunctionArn'],
            Tags=dict(tags)
        )
        print(f"Tags applied to Lambda function: {function['FunctionArn']}")
        
def lambda_handler(event, context):
    tag_ec2_instances_and_volumes()
    tag_vpcs()
    tag_rds_instances()
    tag_ecs_resources()
    tag_ecs_task_definitions()
    tag_ecr_repositories()
    tag_cloudwatch_log_groups()
    tag_albs()
    tag_secrets_manager()
    tag_s3_buckets()
    tag_dynamo_db_tables()
    tag_cloudfront_distributions()
    tag_sqs_queues()
    tag_sns_topics()
    tag_lambda_functions()
   
    
    return {
        'statusCode': 200,
        'body': 'Tags have been successfully applied to all specified resources.'
    }
