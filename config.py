from pydoc import doc
import sys
import boto3
import subprocess
import os
import json

# Environment variables
aws_region = sys.argv[1]
aws_profile = sys.argv[2]
aws_account = sys.argv[3]
modes = sys.argv[4]
output_file = sys.argv[5]
start_time = sys.argv[6]

# boto3 session
session = boto3.Session(region_name=aws_region, profile_name=aws_profile)
# boto3 s3 session
s3 = session.client('s3')

# colors
os.environ["NORMAL"]="[0;39m"
os.environ["WARNING"]="[0;33m"          # Warning (brown)
os.environ["NOTICE"]="[1;33m"           # Notice (yellow)
os.environ["OK"]="[1;32m"               # Ok (green)
os.environ["BAD"]="[1;31m"              # Bad (red)

# Prowler Env vars
os.environ["SEP"] = ','
os.environ["PROFILE"] = aws_profile
os.environ["ACCOUNT_NUM"] = aws_account
os.environ["MODES"] = modes
os.environ["OUTPUT_FILE_NAME"] = output_file
os.environ["PROWLER_START_TIME"] = start_time


# read check metadata
def checkMetadata(check_name):
    metadata = json.load(open(check_name+".json"))
    os.environ["CHECK_SEVERITY"] = metadata['Severity']
    os.environ["CHECK_ASFF_COMPLIANCE_TYPE"] =  metadata['Compliance'][0]['Framework']
    os.environ["CHECK_SERVICENAME"] = metadata['Severity']
    os.environ["TITLE_ID"] = metadata['CheckAlias']
    os.environ["TITLE_TEXT"] = metadata['CheckTitle']
    os.environ["CHECK_RISK"] = metadata['Risk']
    os.environ["CHECK_REMEDIATION"] = metadata['Remediation']['Recommendation']['Text']
    os.environ["CHECK_DOC"] = metadata['RelatedUrl']
    os.environ["CHECK_CAF_EPIC"] = metadata['CheckType']
    os.environ["ITEM_CIS_LEVEL"] = "Extra"

# include bash functions
def textPass (result, resource):
    subprocess.Popen(['bash', '-c', "for lib in include/*;do . $lib; done; general_output PASS '"+aws_region+": "+ result +"' "+ resource+ " "+aws_region])

def textFail (result, resource):
    subprocess.Popen(['bash', '-c', "for lib in include/*;do . $lib; done; general_output FAIL '"+aws_region+": "+ result +"' "+ resource+ " "+aws_region])

def textInfo (result):
    subprocess.Popen(['bash', '-c', "for lib in include/*;do . $lib; done; general_output INFO '"+aws_region+": "+ result +"' "+aws_region])