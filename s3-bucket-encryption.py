import boto3
from botocore.client import ClientError
from config import *

def main ():
    checkMetadata("s3-bucket-encryption")
    try:
        for bucket in s3.list_buckets()['Buckets']:
            if s3.get_bucket_location(Bucket=bucket['Name'])['LocationConstraint'] == aws_region:
                try:
                    response = s3.get_bucket_encryption(Bucket = bucket["Name"])["ServerSideEncryptionConfiguration"]
                    if response:
                        textPass ('Bucket '+bucket['Name']+' has Server Side Encryption enabled.', bucket['Name'])
                    else:
                        textFail ('Server Side Encryption configuration is not configured for '+bucket["Name"], bucket['Name'])
                except ClientError as error:
                    if 'ServerSideEncryptionConfigurationNotFoundError' in str(error):
                        textFail ('Server Side Encryption configuration is not configured for '+bucket["Name"], bucket['Name'])
                    else:
                        textInfo(str(error))
    except ClientError as error:
        textInfo(str(error))
if __name__ == "__main__":
	main()
