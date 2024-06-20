import boto3
import os


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

# Define constants
ECS_CLUSTER_NAME = 'devcluster' # Add your ECS_CLUSTER_NAME here
CLUSTER_NAME = 'devcluster' # Add your CLUSTER_NAME here
TASK_DEFINITION_NAME = 'testing' # Add TASK_DEFINITION_NAME here
EC2_INSTANCE_IDS = ['i-01fba4452271a8b7d', 'i-0e88a75a706b51194']  # Add your EC2 instance IDs here
RDS_INSTANCE_IDENTIFIER = 'postgres'  # Add your RDS instance identifier here
ECR_REPOSITORY_NAME = 'docker'  # Add your ECR repository name here
VPC_ID = 'vpc-0ab79ea985eb3fa45'  # Add your VPC ID here
LOG_GROUP_NAME = '/ecs/testing'  # CloudWatch Log Group name
SECRET_NAME = 'prod'  # Secrets Manager secret name
S3_BUCKET_NAME = 'mybucket91894819839'  # Add your S3 bucket name here
ALB_NAME = 'Application' # Add your ALB name here
CLOUDMAP_NAMESPACE_ID = 'ns-zrmuul4gw6j6jamd' # Add your Cloud Map Namespace ID here
DYNAMODB_TABLE_NAME = 'DynamoDB'  # Add your DynamoDB table name here

# Function to check if a tag exists for an Cluster resource
def ecs_tag_exists(cluster_name, key, value, session):
        ecs_client = session.client('ecs')
        response = ecs_client.list_tags_for_resource(
               resourceArn=f'arn:aws:ecs:{session.region_name}:{session.client("sts").get_caller_identity()["Account"]}:cluster/{cluster_name}'
        )
        for tag in response['tags']:
               if tag['key'] == key and tag['value'] == value:
                       return True
        return False
        
# Function to check if a tag exists for an ECS resource
def tag_exists(resource_arn, key, value, session):
        try:
               ecs_client = session.client('ecs')
               existing_tags = ecs_client.list_tags_for_resource(resourceArn=resource_arn).get('tags', [])
               return any(tag['key'] == key and tag['value'] == value for tag in existing_tags)
        except Exception as e:
               print(f"Error checking tags for {resource_arn}: {str(e)}")
               raise e

# Function to check if a tag exists for an EC2 instance
def ec2_tag_exists(instance_id, key, value, session):
        try:
               ec2_client = session.client('ec2')
               response = ec2_client.describe_tags(
                       Filters=[
                              {'Name': 'resource-id', 'Values': [instance_id]},
                              {'Name': 'key', 'Values': [key]},
                              {'Name': 'value', 'Values': [value]}
                       ]
               )
               return len(response['Tags']) > 0
        except Exception as e:
               print(f"Error checking tags for EC2 instance {instance_id}: {str(e)}")
               raise e

# Function to check if a tag exists for an RDS instance
def rds_tag_exists(instance_arn, key, value, session):
        try:
               rds_client = session.client('rds')
               response = rds_client.list_tags_for_resource(ResourceName=instance_arn)
               existing_tags = response.get('TagList', [])
               return any(tag['Key'] == key and tag['Value'] == value for tag in existing_tags)
        except Exception as e:
               print(f"Error checking tags for RDS instance {instance_arn}: {str(e)}")
               raise e

# Function to check if a tag exists for an ECR repository
def ecr_tag_exists(repository_name, key, value, session):
        try:
               ecr_client = session.client('ecr')
               response = ecr_client.list_tags_for_resource(
                       resourceArn=f'arn:aws:ecr:{session.region_name}:{session.client("sts").get_caller_identity()["Account"]}:repository/{repository_name}'
               )
               existing_tags = response.get('tags', [])
               return any(tag['Key'] == key and tag['Value'] == value for tag in existing_tags)
        except Exception as e:
               print(f"Error checking tags for ECR repository {repository_name}: {str(e)}")
               raise e

# Function to check if a tag exists for a VPC
def vpc_tag_exists(vpc_id, key, value, session):
        try:
               ec2_client = session.client('ec2')
               response = ec2_client.describe_tags(
                       Filters=[
                              {'Name': 'resource-id', 'Values': [vpc_id]},
                              {'Name': 'key', 'Values': [key]},
                              {'Name': 'value', 'Values': [value]}
                       ]
               )
               return len(response['Tags']) > 0
        except Exception as e:
               print(f"Error checking tags for VPC {vpc_id}: {str(e)}")
               raise e

# Function to check if a tag exists for a CloudWatch Log Group
def cloudwatch_log_group_tag_exists(log_group_name, key, value, session):
        try:
               cloudwatch_logs = session.client('logs')
               response = cloudwatch_logs.list_tags_log_group(logGroupName=log_group_name)
               existing_tags = response.get('tags', {})
               return existing_tags.get(key) == value
        except Exception as e:
               print(f"Error checking tags for CloudWatch Log Group {log_group_name}: {str(e)}")
               raise e

# Function to check if a tag exists for a Secrets Manager secret
def secrets_manager_tag_exists(secret_arn, key, value, session):
        try:
               secrets_client = session.client('secretsmanager')
               response = secrets_client.describe_secret(SecretId=secret_arn)
               existing_tags = response.get('Tags', [])
               return any(tag['Key'] == key and tag['Value'] == value for tag in existing_tags)
        except Exception as e:
               print(f"Error checking tags for Secrets Manager secret {secret_arn}: {str(e)}")
               raise e



# Function to check if a tag exists for an EBS volume
def ebs_tag_exists(volume_id, key, value, session):
        try:
               ec2_client = session.client('ec2')
               response = ec2_client.describe_tags(
                       Filters=[
                              {'Name': 'resource-id', 'Values': [volume_id]},
                              {'Name': 'key', 'Values': [key]},
                              {'Name': 'value', 'Values': [value]}
                       ]
               )
               return len(response['Tags']) > 0
        except Exception as e:
               print(f"Error checking tags for EBS volume {volume_id}: {str(e)}")
               raise e
               
# Function to check if a tag exists for an S3 bucket
def s3_tag_exists(bucket_name, key, value, session):
        try:
               s3_client = session.client('s3')
               response = s3_client.get_bucket_tagging(Bucket=bucket_name)
               existing_tags = response.get('TagSet', [])
               return any(tag['Key'] == key and tag['Value'] == value for tag in existing_tags)
        except Exception as e:
               print(f"Error checking tags for S3 bucket {bucket_name}: {str(e)}")
               return False  # If there's an error (e.g., no tags exist), assume the tag doesn't exist
               
# Function to check if a tag exists for an ALB
def alb_tag_exists(alb_arn, key, value, session):
        try:
               elbv2_client = session.client('elbv2')
               response = elbv2_client.describe_tags(
                       ResourceArns=[alb_arn]
               )
               existing_tags = response.get('TagDescriptions', [])[0].get('Tags', [])
               return any(tag['Key'] == key and tag['Value'] == value for tag in existing_tags)
        except Exception as e:
               print(f"Error checking tags for ALB {alb_arn}: {str(e)}")
               raise e
               
# Function to check if a tag exists for a Cloud Map resource
def cloudmap_tag_exists(resource_arn, key, value, session):
        try:
               cloudmap_client = session.client('servicediscovery')
               response = cloudmap_client.list_tags_for_resource(
                       ResourceARN=resource_arn
               )
               existing_tags = response.get('Tags', [])
               return any(tag['Key'] == key and tag['Value'] == value for tag in existing_tags)
        except Exception as e:
               print(f"Error checking tags for Cloud Map resource {resource_arn}: {str(e)}")
               raise e
               
# Function to check if a tag exists for DynamoDB table
def dynamodb_tag_exists(table_name, key, value, session):
        try:
               dynamodb_client = session.client('dynamodb')
               response = dynamodb_client.list_tags_of_resource(
                       ResourceArn=f'arn:aws:dynamodb:{session.region_name}:{session.client("sts").get_caller_identity()["Account"]}:table/{table_name}'
               )
               existing_tags = response.get('Tags', [])
               return any(tag['Key'] == key and tag['Value'] == value for tag in existing_tags)
        except dynamodb_client.exceptions.ResourceNotFoundException as e:
               print(f"DynamoDB table {table_name} not found: {str(e)}")
               return False
        except Exception as e:
               print(f"Error checking tags for DynamoDB table {table_name}: {str(e)}")
               raise e  
               
# Lambda handler function
def lambda_handler(event, context):
        try:
               # Initialize Boto3 session
               session = boto3.Session(
                       aws_access_key_id=os.getenv('YOUR_AWS_ACCESS_KEY_ID'),
                       aws_secret_access_key=os.getenv('YOUR_AWS_SECRET_ACCESS_KEY'),
                       region_name='YOUR_REGION_NAME'
               )

               # ECS client
               ecs_client = session.client('ecs')
               
               # List all services in the cluster
               paginator = ecs_client.get_paginator('list_services')
               service_arns = []
               for page in paginator.paginate(cluster=CLUSTER_NAME):
                       service_arns.extend(page['serviceArns'])
               
               # If no services found, return error response
               if not service_arns:
                       print("No services found in the cluster.")
                       return {
                              'statusCode': 404,
                              'body': 'No services found in the cluster'
                       }
               
               # Process each service
               for service_arn in service_arns:
                       # Add primary tag if not exists
                       if not tag_exists(service_arn, TAG_KEY, TAG_VALUE, session):
                              ecs_client.tag_resource(
                                      resourceArn=service_arn,
                                      tags=[
                                             {'key': TAG_KEY, 'value': TAG_VALUE}
                                      ]
                              )
                              print(f"Added tag: {TAG_KEY} = {TAG_VALUE} to {service_arn}")
                       else:
                              print(f"Tag: {TAG_KEY} = {TAG_VALUE} already exists on {service_arn}")
                       
                       # Add additional tags
                       for key, value in ADDITIONAL_TAGS.items():
                              if not tag_exists(service_arn, key, value, session):
                                      ecs_client.tag_resource(
                                             resourceArn=service_arn,
                                             tags=[
                                                     {'key': key, 'value': value}
                                             ]
                                      )
                                      print(f"Added additional tag: {key} = {value} to {service_arn}")
                              else:
                                      print(f"Additional tag: {key} = {value} already exists on {service_arn}")
                                      
               # Get the ARN of the task definition
               task_definition_arn = ecs_client.describe_task_definition(taskDefinition=TASK_DEFINITION_NAME)['taskDefinition']['taskDefinitionArn']

               # Add primary tag for task definition if not exists
               if not tag_exists(task_definition_arn, TAG_KEY, TAG_VALUE, session):
                       ecs_client.tag_resource(
                              resourceArn=task_definition_arn,
                              tags=[
                                      {'key': TAG_KEY, 'value': TAG_VALUE}
                              ]
                       )
                       print(f"Added tag: {TAG_KEY} = {TAG_VALUE} to task definition {TASK_DEFINITION_NAME}")
               else:
                       print(f"Tag: {TAG_KEY} = {TAG_VALUE} already exists on {task_definition_arn}")

               # Add additional tags for task definition
               for key, value in ADDITIONAL_TAGS.items():
                       if not tag_exists(task_definition_arn, key, value, session):
                              ecs_client.tag_resource(
                                      resourceArn=task_definition_arn,
                                      tags=[
                                             {'key': key, 'value': value}
                                      ]
                              )
                              print(f"Added additional tag: {key} = {value} to task definition {TASK_DEFINITION_NAME}")
                       else:
                              print(f"Additional tag: {key} = {value} already exists on {task_definition_arn}")

               # EC2 client
               ec2_client = session.client('ec2')

               # Process each EC2 instance
               for instance_id in EC2_INSTANCE_IDS:
                       # Add primary tag for EC2 instance if not exists
                       if not ec2_tag_exists(instance_id, TAG_KEY, TAG_VALUE, session):
                              ec2_client.create_tags(
                                      Resources=[instance_id],
                                      Tags=[
                                             {'Key': TAG_KEY, 'Value': TAG_VALUE}
                                      ]
                              )
                              print(f"Added tag: {TAG_KEY} = {TAG_VALUE} to EC2 instance {instance_id}")
                       else:
                              print(f"Tag: {TAG_KEY} = {TAG_VALUE} already exists on EC2 instance {instance_id}")

                       # Add additional tags for EC2 instance
                       for key, value in ADDITIONAL_TAGS.items():
                              if not ec2_tag_exists(instance_id, key, value, session):
                                      ec2_client.create_tags(
                                             Resources=[instance_id],
                                             Tags=[
                                                     {'Key': key, 'Value': value}
                                             ]
                                      )
                                      print(f"Added additional tag: {key} = {value} to EC2 instance {instance_id}")
                              else:
                                      print(f"Additional tag: {key} = {value} already exists on EC2 instance {instance_id}")

                       # Get the EBS volumes attached to the EC2 instance
                       instance_volumes = ec2_client.describe_volumes(
                              Filters=[
                                      {'Name': 'attachment.instance-id', 'Values': [instance_id]}
                              ]
                       )['Volumes']

                       for volume in instance_volumes:
                              volume_id = volume['VolumeId']

                              # Add primary tag for EBS volume if not exists
                              if not ebs_tag_exists(volume_id, TAG_KEY, TAG_VALUE, session):
                                      ec2_client.create_tags(
                                             Resources=[volume_id],
                                             Tags=[
                                                     {'Key': TAG_KEY, 'Value': TAG_VALUE}
                                             ]
                                      )
                                      print(f"Added tag: {TAG_KEY} = {TAG_VALUE} to EBS volume {volume_id}")
                              else:
                                      print(f"Tag: {TAG_KEY} = {TAG_VALUE} already exists on EBS volume {volume_id}")

                              # Add additional tags for EBS volume
                              for key, value in ADDITIONAL_TAGS.items():
                                      if not ebs_tag_exists(volume_id, key, value, session):
                                             ec2_client.create_tags(
                                                     Resources=[volume_id],
                                                     Tags=[
                                                            {'Key': key, 'Value': value}
                                                     ]
                                             )
                                             print(f"Added additional tag: {key} = {value} to EBS volume {volume_id}")
                                      else:
                                             print(f"Additional tag: {key} = {value} already exists on EBS volume {volume_id}")

               # RDS client
               rds_client = session.client('rds')

               # Get the ARN of the RDS instance
               rds_arn = rds_client.describe_db_instances(DBInstanceIdentifier=RDS_INSTANCE_IDENTIFIER)['DBInstances'][0]['DBInstanceArn']

               # Add primary tag for RDS instance if not exists
               if not rds_tag_exists(rds_arn, TAG_KEY, TAG_VALUE, session):
                       rds_client.add_tags_to_resource(
                              ResourceName=rds_arn,
                              Tags=[
                                      {'Key': TAG_KEY, 'Value': TAG_VALUE}
                              ]
                       )
                       print(f"Added tag: {TAG_KEY} = {TAG_VALUE} to RDS instance {RDS_INSTANCE_IDENTIFIER}")
               else:
                       print(f"Tag: {TAG_KEY} = {TAG_VALUE} already exists on RDS instance {RDS_INSTANCE_IDENTIFIER}")

               # Add additional tags for RDS instance
               for key, value in ADDITIONAL_TAGS.items():
                       if not rds_tag_exists(rds_arn, key, value, session):
                              rds_client.add_tags_to_resource(
                                      ResourceName=rds_arn,
                                      Tags=[
                                             {'Key': key, 'Value': value}
                                      ]
                              )
                              print(f"Added additional tag: {key} = {value} to RDS instance {RDS_INSTANCE_IDENTIFIER}")
                       else:
                              print(f"Additional tag: {key} = {value} already exists on RDS instance {RDS_INSTANCE_IDENTIFIER}")

               # ECR client
               ecr_client = session.client('ecr')

               # Add primary tag for ECR repository if not exists
               if not ecr_tag_exists(ECR_REPOSITORY_NAME, TAG_KEY, TAG_VALUE, session):
                       ecr_client.tag_resource(
                              resourceArn=f'arn:aws:ecr:{session.region_name}:{session.client("sts").get_caller_identity()["Account"]}:repository/{ECR_REPOSITORY_NAME}',
                              tags=[
                                      {'Key': TAG_KEY, 'Value': TAG_VALUE}
                              ]
                       )
                       print(f"Added tag: {TAG_KEY} = {TAG_VALUE} to ECR repository {ECR_REPOSITORY_NAME}")
               else:
                       print(f"Tag: {TAG_KEY} = {TAG_VALUE} already exists on ECR repository {ECR_REPOSITORY_NAME}")

               # Add additional tags for ECR repository
               for key, value in ADDITIONAL_TAGS.items():
                       if not ecr_tag_exists(ECR_REPOSITORY_NAME, key, value, session):
                              ecr_client.tag_resource(
                                      resourceArn=f'arn:aws:ecr:{session.region_name}:{session.client("sts").get_caller_identity()["Account"]}:repository/{ECR_REPOSITORY_NAME}',
                                      tags=[
                                             {'Key': key, 'Value': value}
                                      ]
                              )
                              print(f"Added additional tag: {key} = {value} to ECR repository {ECR_REPOSITORY_NAME}")
                       else:
                              print(f"Additional tag: {key} = {value} already exists on ECR repository {ECR_REPOSITORY_NAME}")

               # Add primary tag for VPC if not exists
               if not vpc_tag_exists(VPC_ID, TAG_KEY, TAG_VALUE, session):
                       ec2_client.create_tags(
                              Resources=[VPC_ID],
                              Tags=[
                                      {'Key': TAG_KEY, 'Value': TAG_VALUE}
                              ]
                       )
                       print(f"Added tag: {TAG_KEY} = {TAG_VALUE} to VPC {VPC_ID}")
               else:
                       print(f"Tag: {TAG_KEY} = {TAG_VALUE} already exists on VPC {VPC_ID}")

               # Add additional tags for VPC
               for key, value in ADDITIONAL_TAGS.items():
                       if not vpc_tag_exists(VPC_ID, key, value, session):
                              ec2_client.create_tags(
                                      Resources=[VPC_ID],
                                      Tags=[
                                             {'Key': key, 'Value': value}
                                      ]
                              )
                              print(f"Added additional tag: {key} = {value} to VPC {VPC_ID}")
                       else:
                              print(f"Additional tag: {key} = {value} already exists on VPC {VPC_ID}")

               # CloudWatch Logs client
               cloudwatch_logs = session.client('logs')

               # Add primary tag for CloudWatch Log Group if not exists
               if not cloudwatch_log_group_tag_exists(LOG_GROUP_NAME, TAG_KEY, TAG_VALUE, session):
                       cloudwatch_logs.tag_log_group(
                              logGroupName=LOG_GROUP_NAME,
                              tags={
                                      TAG_KEY: TAG_VALUE
                              }
                       )
                       print(f"Added tag: {TAG_KEY} = {TAG_VALUE} to CloudWatch Log Group {LOG_GROUP_NAME}")
               else:
                       print(f"Tag: {TAG_KEY} = {TAG_VALUE} already exists on CloudWatch Log Group {LOG_GROUP_NAME}")

               # Add additional tags for CloudWatch Log Group
               for key, value in ADDITIONAL_TAGS.items():
                       if not cloudwatch_log_group_tag_exists(LOG_GROUP_NAME, key, value, session):
                              cloudwatch_logs.tag_log_group(
                                      logGroupName=LOG_GROUP_NAME,
                                      tags={
                                             key: value
                                      }
                              )
                              print(f"Added additional tag: {key} = {value} to CloudWatch Log Group {LOG_GROUP_NAME}")
                       else:
                              print(f"Additional tag: {key} = {value} already exists on CloudWatch Log Group {LOG_GROUP_NAME}")

               # Secrets Manager client
               secrets_client = session.client('secretsmanager')

               # Get the ARN of the Secrets Manager secret
               secret_arn = secrets_client.describe_secret(SecretId=SECRET_NAME)['ARN']

               # Add primary tag for Secrets Manager secret if not exists
               if not secrets_manager_tag_exists(secret_arn, TAG_KEY, TAG_VALUE, session):
                       secrets_client.tag_resource(
                              SecretId=secret_arn,
                              Tags=[
                                      {'Key': TAG_KEY, 'Value': TAG_VALUE}
                              ]
                       )
                       print(f"Added tag: {TAG_KEY} = {TAG_VALUE} to Secrets Manager secret {SECRET_NAME}")
               else:
                       print(f"Tag: {TAG_KEY} = {TAG_VALUE} already exists on Secrets Manager secret {SECRET_NAME}")

               # Add additional tags for Secrets Manager secret
               for key, value in ADDITIONAL_TAGS.items():
                       if not secrets_manager_tag_exists(secret_arn, key, value, session):
                              secrets_client.tag_resource(
                                      SecretId=secret_arn,
                                      Tags=[
                                             {'Key': key, 'Value': value}
                                      ]
                              )
                              print(f"Added additional tag: {key} = {value} to Secrets Manager secret {SECRET_NAME}")
                       else:
                              print(f"Additional tag: {key} = {value} already exists on Secrets Manager secret {SECRET_NAME}")

                # S3 client
               s3_client = session.client('s3')

               # Add primary tag for S3 bucket if not exists
               if not s3_tag_exists(S3_BUCKET_NAME, TAG_KEY, TAG_VALUE, session):
                       s3_client.put_bucket_tagging(
                              Bucket=S3_BUCKET_NAME,
                              Tagging={
                                      'TagSet': [
                                             {'Key': TAG_KEY, 'Value': TAG_VALUE}
                                      ]
                              }
                       )
                       print(f"Added tag: {TAG_KEY} = {TAG_VALUE} to S3 bucket {S3_BUCKET_NAME}")
               else:
                       print(f"Tag: {TAG_KEY} = {TAG_VALUE} already exists on S3 bucket {S3_BUCKET_NAME}")

               # Add additional tags for S3 bucket
               for key, value in ADDITIONAL_TAGS.items():
                       if not s3_tag_exists(S3_BUCKET_NAME, key, value, session):
                              existing_tags = s3_client.get_bucket_tagging(Bucket=S3_BUCKET_NAME).get('TagSet', [])
                              existing_tags.append({'Key': key, 'Value': value})
                              s3_client.put_bucket_tagging(
                                      Bucket=S3_BUCKET_NAME,
                                      Tagging={
                                             'TagSet': existing_tags
                                      }
                              )
                              print(f"Added additional tag: {key} = {value} to S3 bucket {S3_BUCKET_NAME}")
                       else:
                              print(f"Additional tag: {key} = {value} already exists on S3 bucket {S3_BUCKET_NAME}")
                              
                       # ALB client
               elbv2_client = session.client('elbv2')
               
               # Get the ARN of the ALB
               alb_arn = elbv2_client.describe_load_balancers(Names=[ALB_NAME])['LoadBalancers'][0]['LoadBalancerArn']
               
               # Add primary tag for ALB if not exists
               if not alb_tag_exists(alb_arn, TAG_KEY, TAG_VALUE, session):
                       elbv2_client.add_tags(
                              ResourceArns=[alb_arn],
                              Tags=[
                                      {'Key': TAG_KEY, 'Value': TAG_VALUE}
                              ]
                       )
                       print(f"Added tag: {TAG_KEY} = {TAG_VALUE} to ALB {ALB_NAME}")
               else:
                       print(f"Tag: {TAG_KEY} = {TAG_VALUE} already exists on ALB {ALB_NAME}")
               
               # Add additional tags for ALB
               for key, value in ADDITIONAL_TAGS.items():
                       if not alb_tag_exists(alb_arn, key, value, session):
                              elbv2_client.add_tags(
                                      ResourceArns=[alb_arn],
                                      Tags=[
                                             {'Key': key, 'Value': value}
                                      ]
                              )
                              print(f"Added additional tag: {key} = {value} to ALB {ALB_NAME}")
                       else:
                              print(f"Additional tag: {key} = {value} already exists on ALB {ALB_NAME}")
                              
                       # Tag ECS Cluster
               ecs_arn = f'arn:aws:ecs:{session.region_name}:{session.client("sts").get_caller_identity()["Account"]}:cluster/{ECS_CLUSTER_NAME}'
               
               if not ecs_tag_exists(ECS_CLUSTER_NAME, TAG_KEY, TAG_VALUE, session):
                       ecs_client.tag_resource(
                              resourceArn=ecs_arn,
                              tags=[
                                      {'key': TAG_KEY, 'value': TAG_VALUE}
                              ]
                       )
                       print(f"Added tag: {TAG_KEY} = {TAG_VALUE} to ECS cluster {ECS_CLUSTER_NAME}")
               else:
                       print(f"Tag: {TAG_KEY} = {TAG_VALUE} already exists on ECS cluster {ECS_CLUSTER_NAME}")

               for key, value in ADDITIONAL_TAGS.items():
                       if not ecs_tag_exists(ECS_CLUSTER_NAME, key, value, session):
                              ecs_client.tag_resource(
                                      resourceArn=ecs_arn,
                                      tags=[
                                             {'key': key, 'value': value}
                                      ]
                              )
                              print(f"Added additional tag: {key} = {value} to ECS cluster {ECS_CLUSTER_NAME}")
                       else:
                              print(f"Additional tag: {key} = {value} already exists on ECS cluster {ECS_CLUSTER_NAME}")
                              
                       
                # Cloud Map client
               cloudmap_client = session.client('servicediscovery')

               # Process Cloud Map Namespace
               namespace_arn = f'arn:aws:servicediscovery:{session.region_name}:{session.client("sts").get_caller_identity()["Account"]}:namespace/{CLOUDMAP_NAMESPACE_ID}'
               
               # Add primary tag for Cloud Map Namespace if not exists
               if not cloudmap_tag_exists(namespace_arn, TAG_KEY, TAG_VALUE, session):
                       cloudmap_client.tag_resource(
                              ResourceARN=namespace_arn,
                              Tags=[
                                      {'Key': TAG_KEY, 'Value': TAG_VALUE}
                              ]
                       )
                       print(f"Added tag: {TAG_KEY} = {TAG_VALUE} to Cloud Map Namespace {CLOUDMAP_NAMESPACE_ID}")
               else:
                       print(f"Tag: {TAG_KEY} = {TAG_VALUE} already exists on Cloud Map Namespace {CLOUDMAP_NAMESPACE_ID}")

               # Add additional tags for Cloud Map Namespace
               for key, value in ADDITIONAL_TAGS.items():
                       if not cloudmap_tag_exists(namespace_arn, key, value, session):
                              cloudmap_client.tag_resource(
                                      ResourceARN=namespace_arn,
                                      Tags=[
                                             {'Key': key, 'Value': value}
                                      ]
                              )
                              print(f"Added additional tag: {key} = {value} to Cloud Map Namespace {CLOUDMAP_NAMESPACE_ID}")
                       else:
                              print(f"Additional tag: {key} = {value} already exists on Cloud Map Namespace {CLOUDMAP_NAMESPACE_ID}")
                              
         # Check if DynamoDB table exists before tagging
               if not dynamodb_tag_exists(DYNAMODB_TABLE_NAME, TAG_KEY, TAG_VALUE, session):
                       dynamodb_client = session.client('dynamodb')
                       dynamodb_client.tag_resource(
                              ResourceArn=f'arn:aws:dynamodb:{session.region_name}:{session.client("sts").get_caller_identity()["Account"]}:table/{DYNAMODB_TABLE_NAME}',
                              Tags=[{'Key': TAG_KEY, 'Value': TAG_VALUE}] + [{'Key': k, 'Value': v} for k, v in ADDITIONAL_TAGS.items()]
                       )

               # Return success response
               return {
                       'statusCode': 200,
                       'body': 'All resources have been tagged successfully'
               }
        
        except Exception as e:
               print(f"Error in lambda_handler: {str(e)}")
               return {
                       'statusCode': 500,
                       'body': str(e)
               }
