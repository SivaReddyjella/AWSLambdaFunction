import boto3
import os

# Set environment variables or set these directly
CLUSTER_NAME = 'Tags'
TAG_KEY = 'Environment'
TAG_VALUE = 'prod'
ADDITIONAL_TAG_KEY = os.getenv('ADDITIONAL_TAG_KEY', 'your-ADDITIONAL_TAG_KEY')
ADDITIONAL_TAG_VALUE = os.getenv('ADDITIONAL_TAG_VALUE', 'your-ADDITIONAL_TAG_VALUE')
TASK_DEFINITION_NAME = 'tagstaskdefinition'
EC2_INSTANCE_IDS = ['i-04e22fb8ba2c22885', 'i-06331246688f2a290']  # Add your EC2 instance IDs here

def tag_exists(resource_arn, key, value, session):
    try:
        ecs_client = session.client('ecs')
        existing_tags = ecs_client.list_tags_for_resource(
            resourceArn=resource_arn
        ).get('tags', [])

        for tag in existing_tags:
            if tag['key'] == key and tag['value'] == value:
                return True
        return False
    except Exception as e:
        print(f"Error checking tags for {resource_arn}: {str(e)}")
        raise e

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

def lambda_handler(event, context):
    try:
        session = boto3.Session(
            aws_access_key_id=os.getenv('your-aws_access_key_id'),
            aws_secret_access_key=os.getenv('your-aws_secret_access_key'),
            region_name='us-east-1'
        )

        ecs_client = session.client('ecs')

        # List all services in the cluster
        paginator = ecs_client.get_paginator('list_services')
        service_arns = []
        for page in paginator.paginate(cluster=CLUSTER_NAME):
            service_arns.extend(page['serviceArns'])

        if not service_arns:
            print("No services found in the cluster.")
            return {
                'statusCode': 404,
                'body': 'No services found in the cluster'
            }

        for service_arn in service_arns:
            # Check and add the primary tag
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

            # Check and add the additional tag if provided
            if ADDITIONAL_TAG_KEY and ADDITIONAL_TAG_VALUE:
                if not tag_exists(service_arn, ADDITIONAL_TAG_KEY, ADDITIONAL_TAG_VALUE, session):
                    ecs_client.tag_resource(
                        resourceArn=service_arn,
                        tags=[
                            {'key': ADDITIONAL_TAG_KEY, 'value': ADDITIONAL_TAG_VALUE}
                        ]
                    )
                    print(f"Added additional tag: {ADDITIONAL_TAG_KEY} = {ADDITIONAL_TAG_VALUE} to {service_arn}")
                else:
                    print(f"Additional tag: {ADDITIONAL_TAG_KEY} = {ADDITIONAL_TAG_VALUE} already exists on {service_arn}")
            else:
                print("No additional tags provided.")

        # Tag the task definition
        task_definition_arn = ecs_client.describe_task_definition(taskDefinition=TASK_DEFINITION_NAME)['taskDefinition']['taskDefinitionArn']

        # Check and add the primary tag for task definition
        if not tag_exists(task_definition_arn, TAG_KEY, TAG_VALUE, session):
            ecs_client.tag_resource(
                resourceArn=task_definition_arn,
                tags=[
                    {'key': TAG_KEY, 'value': TAG_VALUE}
                ]
            )
            print(f"Added tag: {TAG_KEY} = {TAG_VALUE} to {task_definition_arn}")
        else:
            print(f"Tag: {TAG_KEY} = {TAG_VALUE} already exists on {task_definition_arn}")

        # Check and add the additional tag for task definition if provided
        if ADDITIONAL_TAG_KEY and ADDITIONAL_TAG_VALUE:
            if not tag_exists(task_definition_arn, ADDITIONAL_TAG_KEY, ADDITIONAL_TAG_VALUE, session):
                ecs_client.tag_resource(
                    resourceArn=task_definition_arn,
                    tags=[
                        {'key': ADDITIONAL_TAG_KEY, 'value': ADDITIONAL_TAG_VALUE}
                    ]
                )
                print(f"Added additional tag: {ADDITIONAL_TAG_KEY} = {ADDITIONAL_TAG_VALUE} to {task_definition_arn}")
            else:
                print(f"Additional tag: {ADDITIONAL_TAG_KEY} = {ADDITIONAL_TAG_VALUE} already exists on {task_definition_arn}")
        else:
            print("No additional tags provided for task definition.")

        ec2_client = session.client('ec2')

        for instance_id in EC2_INSTANCE_IDS:
            # Check and add the primary tag for EC2 instance
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

            # Check and add the additional tag for EC2 instance if provided
            if ADDITIONAL_TAG_KEY and ADDITIONAL_TAG_VALUE:
                if not ec2_tag_exists(instance_id, ADDITIONAL_TAG_KEY, ADDITIONAL_TAG_VALUE, session):
                    ec2_client.create_tags(
                        Resources=[instance_id],
                        Tags=[
                            {'Key': ADDITIONAL_TAG_KEY, 'Value': ADDITIONAL_TAG_VALUE}
                        ]
                    )
                    print(f"Added additional tag: {ADDITIONAL_TAG_KEY} = {ADDITIONAL_TAG_VALUE} to EC2 instance {instance_id}")
                else:
                    print(f"Additional tag: {ADDITIONAL_TAG_KEY} = {ADDITIONAL_TAG_VALUE} already exists on EC2 instance {instance_id}")
            else:
                print("No additional tags provided for EC2 instance.")

        return {
            'statusCode': 200,
            'body': 'Tags updated successfully'
        }
    except Exception as e:
        print(f"Error in lambda_handler: {str(e)}")
        return {
            'statusCode': 500,
            'body': str(e)
        }
