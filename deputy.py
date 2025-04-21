def print_deputy_barney_banner():
    print("""
    -----------------------------------------------------
     _____                     _         ______                      
    |  __ \                   | |       |  ____|                     
    | |  | | ___ _ __  _   _| |_ _   _| |__   __ _ _ __ _ __   ___ _   _ 
    | |  | |/ _ \ '_ \| | | | __| | | |  __| / _` | '__| '_ \ / _ \ | | |
    | |__| |  __/ |_) | |_| | |_| |_| | |___| (_| | |  | | | |  __/ |_| |
    |_____/ \___| .__/ \__,_|\__|\__, |______\__,_|_|  |_| |_|\___|\__, |
                | |               __/ |                              __/ |
                |_|              |___/                              |___/ 
    -----------------------------------------------------
          "Nip it in the bud!" - AWS Security Edition
    -----------------------------------------------------
    
    A tool to find confused deputy cases in AWS
    
    -----------------------------------------------------
*+***==+**+=++==+=++==+++*=+=++*=+*++====****+====-=----:::::::::::-:-------::--------:::::::::::: 
 ====++=============-=--:::=-::::. ..+=%=:.    :.:-:-:-:::::::::::::::::::::::::::::::::::::::::::: 
 =======================--=::---===%     ==*+++==--:        ::-:::::::::::::::::::::::::::::::::::: 
 ==-====-====------==-=-----=:===  .-+**+===-:-----===+++++==   ::::::::::::::::::::::::::::::::::: 
 ==:--==----==---=-----:::::=.*  %*====.-..:*+--::--:-:::::::-=#. :-::::::::::::::::::::::::::::::: 
 =======-=====-----====---=+: *%=-::==-*-=@ ...:#=:==-::-::::::-=*.  .::::::::::::::::::::::::::::: 
 ====+========---=------+:= :%-:-  = :.:*  ...*   ...:==****=:.::--=*. :::::::::::::::::::::::::::: 
 =------:-:-=----=:-=:--=  @*==-::@@=%=:.::.%..*@%:===::...:=*#*:::-+=+..:::::::::::::::::::::::::: 
 =======-=========--=--: %+-=::-:=. -=..:::...-+ @ .::=*%+=:....%*:..-=:.:::::::::::::::::::::::::: 
 -----==------:-----== :%=-:::==.==%@ .::::===..=%%:-=:.:-::=%#=  :%.:==:.::::::::::::::::::::::::: 
 =====-::::---::::-:: +++::.-=..=*: -%.::::::::.=*:.:=-====::::=+@@==-:-%.::::::::::::::::::::::::: 
 :::--:-:--:--:-:-:..@=-::-==.-+*:.@  ..:.*:::=.-@+*.:::-::==:+=- @@-:-=*:::::::::::::::::::::::::: 
 ==--------------: =#=:-::=:::*=::  @@ .%.::::=                    -%+-:=.::::::::::::::::::::::::: 
 =--=-==-=----::: %*==:-:=-::=.--:-  @           @@@@@@@@@@@@@@@@@*@  .**.::::::::::::::::::::::::: 
 :-----:------=- +*-:--::::-.==-:--     *@@@%+@@@@%%%%@@@@@@@@@@@@ @@@:*..::::::::::::::::::::::::: 
 =--=-:-::::::: %*=----::..=+=::    @@@@@@@@-=   =%#%@@@%*****+==%@*  -..:::::::::::::::::::::::::: 
 =-:::::-----  @=::--:..=**+    #@@@@@%%%#+@@@@@@@@%*+-===-:==*%#===@@ .::::::::::::::::::::::::::: 
 =-:--::----.=@.-:::: .#:    @@@@@%%%%%%@@@%%**%+@@@@@@@@@@@@@@=#@@@%  :::::::::::::::::::::::::::: 
 -:--=-:::-: %@%---  =*  @@@@@@@%#%%%@@%*%%@@@@@@@@%%%@%         *@@- ::::::::::::::::::::::::::::: 
 ==---=::=: @:#:.:: @@ @@@@=:.=*%%%%@###@%@@@@@@@:       ::--==:.%@@@  :::::::::::::::::::::::::::: 
 -=-==--:=  @*-:==:-@=%@@@@@@@@@%%%@%@@@@@@*      .-:.......-=:::*@%@@ .::::::::::::::::::::::::::: 
 =======-+ @@: -:= =@@@@@  %%%%%@@@@@%       .::::::.+%%%%%#..-.::@@@@ .::::::::::::::::::::::::::: 
 ===---==- @#* -=% =@  @ @@@@@@@@@- =+*##=..:::::::::-....:-%#*=. %@@# .::::::::::::::::::::::::::: 
 +==++====.=@: -.. @@@ * @%%**@   :    ..:--.::::::....--.....:#: @@-  .::::::::::::::::::::::::::: 
 ====+*===-: @@: . %@@@@@@%@*@@    .--=%#=-== ::::=-=#+. =*#-.:+= @@ %%.::::::::::::::::::::::::::: 
 =+-==-=====. #@%%:  @@@ @@@=**.:@% =@@ .##:@ ...++++= @@@ .%-:.- @  .=.::::::::::::::::::::::::::: 
 =+--::---:-+:. *+ .*@%=  *@#=- :@- :@@ .-= %=:-.*..:=  @= -+*..::  ==..::::::::::::::::::::::::::: 
 +=+=-===-=====::.: .:  %@#@@:  .%%#-:: :..:%=:-:===.=- .:++::..-*:.*:-:::::::::::::::::::::::::::: 
 ===+===========-=:::.:  %@@@@::. .:.::-=-:%%::=:==-:::::...:.-=-+..:+.:::::::::::::::::::::::::::: 
 ====+*=======-=--::----  %@@@-=:.::-:-:-..@#:-=--=::.-:::::::::=%...#.:::::::::::::::::::::::::::: 
 ++=+=+=========--::-:: + @%#@@:-:-:-:==: %@.:.:::=#-.:::-::::::++=+-=.:::::::::::::::::::::::::::: 
 ========-=-=-:-:::--:::  %-%@@:-:::-+=..%%=+  ...===.:::--:::::#:::*.::::::::::::::::::::::::::::: 
 ===+=-========--:--::::: @:-@@%: -.*=:.. =*@@%#%#-%:.:::-::=-:-#::%..::::::::::::::::::::::::::::: 
 +===+======---=::::::::: @% @@@=.:-%:..-=:.   ..:=::-:.::-:-:.=%....:::::::::::::::::::::::::::::: 
 +=+=---=:-:.::=:::::--:::    @@#  =* .*#==::=.:..:-=-=::.::--:**.::::::::::::::::::::::::::::::::: 
 +==-:-====-==--:--::::::::::  @@= *% %=::............:=+.:---=%..::::::::::::::::::::::::::::::::: 
 +=======--:---::::-:::::::::. @@@ %* %-==%%*##%%*+-*=:.=::=:-#:.:::::::::::::::::::::::::::::::::: 
 +==========-=-=-----:::::::::. @@-%% =:.--.%%...*#@=+.--::=:-% ::::::::::::::::::::::::::::::::::: 
 =+==-=====--=-=--:::::::::-:::  @@:@ -::*@-..::-. =+=.--.-=-:@ ::::::::::::::::::::::::::::::::::: 
 =======+==--=-::::::-::::::::::  @:@ -+.::#%%#*%*%=.:-:=-=--=@ ::::::::::::::::::::::::::::::::::: 
 ++======-==-=-:::::::::::::::::: @@=%::-:::.:.::..:-=::::--==% ::::::::::::::::::::::::::::::::::: 
 ++=====-:-::-:::::::::::--+=-=-: *@=**---::-:....:.:::==*+**=%.::::.:....::::::::::::::::::::::::: 
 ==-=-==-=====--:-=++++=::.. ...   @@@#@+  ::-:.::::-:=*==*::#*..::::%.=#+::::::::::::::::::::::::: 
 +*====+===-++**%*       .  :+..+*=%=@@@@@%      .::=#+==*:-%%.:.:::..%..-::::::::::::::::::::::::: 
 ++====-+*%@*-   .-=*===%#@@*-+.=+@ @+ -+@@@@@@@@%%#*=:--:=%...:-=:::..+:::::::....:::::::::::::::: 
 +=:=*#@%     --:::....... :...: @** =@: +         ..:-=*##..::-::::::::::==---=**=:::::::::::::::: 
 =+%@@   :==-+:-:::.:...==.=.::. @@ + .@##%=-:...::::-=%=...:::::::::::::::::-:....:::::::::::::::: 
 @@%   :::+=.%%=-:====+*:-::---: =%% :. :#@***.  .-*%%:..::::::*.:::---::::::::::::=::::::::::::::: 
 = @ .:**.::::..:::::::::::::::.=. +#:::.     + : .+...::::::::.:-::::::::::::::::=:::::::::::::::: 
   .*%==--:::::::::::::-::::::- #.:-=*=.  @@@@@@@@%  :::::::::=::-::::::::::::::.=-:::::::::::::::: 
 .%.=...-:::::-::::::::-:::-:::.@.===::= @@@%%%%%@@@  :-::::.-:.=-::::::::::::::==::::::::::::::::: 
 .:.=-::=::-:::::-::::::::::::.:*.--::*  @@%%%#%@@@@=  :--:.=-:-=::::::::::::::-=:::::::::::::::::: 
 ::.:=.=:.:.-::::::::--:-:::::..* ==*==  @%%%@@@@   @: .:=::=.::::::::::::::::=-::::::::::::::::::: 
 .::-=:=:.:::-=::::::::::--=--  @ *-#.  @@%%%@@   :  @  .::-=.:::::::::::::::-=:::::::::::::::::::: 
 :.::-:-=::::-=::::::::::::=== *%.%=.  =@@%#%@@  :::  @  ::--::-::::::::::::==::::::::::::::::::::: 
 :::==-.--:::::+=::::::::::-:  @:%...  @@%%%%%@@  :::  @  .=.:-::::::::::::--:::::::::::::::::::::: 
 ---:.::==:::::-=-:::--::::::.@*  .:  @@%%%%#%@@@  ::: :@  :::::::::::::::--::::::::::::::::::::::: 
 -=:=-::-=-:::::-=-:::::::::.   :==:  @@%%%%%%#@@% :::  :@ ::::::::::::::--:::::::::::::::::::::::: 
 :==-::-:+-::::::-=-::::::::::::-==+ =@%%%%%%%%%@@  :::    :::::::::::::--::::::::::::::::::::::.+. 
 :--+=.=-=*::::::::=--::::::::::..== @@%%%%%%%%%%@: :::::-::::::::::::::-:::::::::::::::::::-::.=.. 
 ::#*:.-:-*:::::::.-==:.:::::::::.:  @@%%%%%%%%%%@% :::::::::::::::::-==:::::::::::::::::::.=:.-:.% 
                                     @-:-:-:-::::#:                                                 
    -----------------------------------------------------
    """)

# Call the function to display the banner
print_deputy_barney_banner()                                                                                                    
 
#!/usr/bin/env python3

import boto3
import json
import logging
import os
import configparser
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError, ProfileNotFound
from datetime import datetime

# --- Configuration ---
LOG_LEVEL = logging.INFO  # Change to logging.DEBUG for more verbose output
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
DEFAULT_OUTPUT_FILENAME = f"aws_confused_deputy_audit_{TIMESTAMP}.json"

# --- Logging Setup ---
# Format includes timestamp, level, and message
logging.basicConfig(level=LOG_LEVEL, format='%(asctime)s - %(levelname)s - %(message)s')

# --- AWS Profile Handling ---

def get_aws_profiles():
    """Finds available AWS profiles from credentials and config files."""
    profiles = set()
    # Standard locations for AWS config/credentials files
    credentials_path = os.path.expanduser("~/.aws/credentials")
    config_path = os.path.expanduser("~/.aws/config")

    # Parse credentials file
    if os.path.exists(credentials_path):
        credentials_parser = configparser.ConfigParser()
        try:
            credentials_parser.read(credentials_path)
            profiles.update(credentials_parser.sections())
            logging.debug(f"Found profiles in credentials file: {credentials_parser.sections()}")
        except configparser.Error as e:
            logging.warning(f"Could not parse credentials file at {credentials_path}: {e}")

    # Parse config file
    if os.path.exists(config_path):
        config_parser = configparser.ConfigParser()
        try:
            config_parser.read(config_path)
            config_profiles = [s.replace('profile ', '').strip() for s in config_parser.sections() if s.startswith('profile ')]
            profiles.update(config_profiles)
            logging.debug(f"Found profiles in config file: {config_profiles}")
            # Add default if it exists as a section without the 'profile ' prefix
            if 'default' in config_parser.sections():
                profiles.add('default')
        except configparser.Error as e:
            logging.warning(f"Could not parse config file at {config_path}: {e}")

    # Ensure 'default' is included if it might exist implicitly (e.g., env vars)
    # This is a basic check; a profile named 'default' might still fail if not configured
    if not profiles or 'default' not in profiles:
         profiles.add('default') # Add default as an option even if not explicitly found

    return sorted(list(profiles))

def select_aws_profile(profiles):
    """Prompts the user to select an AWS profile."""
    if not profiles:
        logging.error("No AWS profiles found or determined.")
        print("\nError: No AWS profiles found or identifiable. Please configure AWS credentials.")
        return None

    print("\nAvailable AWS Profiles:")
    for idx, profile in enumerate(profiles):
        print(f"  {idx + 1}. {profile}")

    while True:
        try:
            choice = input(f"Select a profile number (1-{len(profiles)}): ")
            profile_index = int(choice) - 1
            if 0 <= profile_index < len(profiles):
                selected_profile = profiles[profile_index]
                print(f"Attempting to use profile: {selected_profile}")
                return selected_profile
            else:
                print("Invalid choice. Please enter a number from the list.")
        except ValueError:
            print("Invalid input. Please enter a number.")
        except KeyboardInterrupt:
            print("\nOperation cancelled by user.")
            return None

# --- Helper Function ---

def has_source_condition(condition_data):
    """Checks if a condition block contains aws:SourceAccount or aws:SourceArn."""
    if not condition_data or not isinstance(condition_data, dict):
        return False
    for cond_operator, cond_pairs in condition_data.items():
        # Check if cond_pairs is a dict (standard structure)
        if isinstance(cond_pairs, dict):
            # Normalize keys (lower case) for comparison flexibility
            condition_keys_lower = {k.lower(): v for k, v in cond_pairs.items()}
            if 'aws:sourceaccount' in condition_keys_lower:
                return True
            if 'aws:sourcearn' in condition_keys_lower:
                return True
    # If loop finishes without finding the keys, return False
    return False

# --- IAM Role Checks ---

def check_iam_roles(session, current_account_id):
    """
    Checks IAM role trust policies for potential Confused Deputy issues
    related to missing sts:ExternalId in cross-account trust.
    """
    iam_client = session.client('iam')
    findings = []
    logging.info("Starting IAM Role trust policy check...")
    role_counter = 0

    try:
        paginator = iam_client.get_paginator('list_roles')
        for page in paginator.paginate(MaxItems=1000): # Adjust MaxItems if needed
            for role in page.get('Roles', []):
                role_counter += 1
                role_name = role['RoleName']
                role_arn = role['Arn']
                logging.debug(f"Checking role: {role_name}")

                # Get the trust policy document
                try:
                    # Get policy directly if available, otherwise make extra call
                    if 'AssumeRolePolicyDocument' in role:
                        assume_role_policy_doc = role.get('AssumeRolePolicyDocument')
                    else:
                         # Fallback to get_role if policy wasn't in list_roles output
                         role_details = iam_client.get_role(RoleName=role_name)
                         assume_role_policy_doc = role_details['Role'].get('AssumeRolePolicyDocument')

                    if not assume_role_policy_doc:
                        logging.warning(f"Could not retrieve AssumeRolePolicyDocument for role '{role_name}'. Skipping.")
                        continue

                    statements = assume_role_policy_doc.get('Statement', [])
                    for stmt_idx, stmt in enumerate(statements):
                        effect = stmt.get('Effect', 'Allow')
                        principal_data = stmt.get('Principal', {})
                        condition_data = stmt.get('Condition', {})

                        if effect == 'Allow' and 'AWS' in principal_data:
                            aws_principals = principal_data['AWS']
                            if not isinstance(aws_principals, list):
                                aws_principals = [aws_principals]

                            for principal_arn_str in aws_principals:
                                # Extract account ID from ARN strings
                                parts = principal_arn_str.split(':')
                                trusted_account_id = None
                                if len(parts) >= 5 and parts[0] == 'arn' and parts[4].isdigit():
                                    trusted_account_id = parts[4]
                                elif principal_arn_str.isdigit() and len(principal_arn_str) == 12: # Handle plain account ID principal
                                    trusted_account_id = principal_arn_str

                                # --- VULNERABILITY CHECK ---
                                # Check if it trusts an external account without ExternalId
                                if trusted_account_id and trusted_account_id != current_account_id:
                                    has_external_id = False
                                    if condition_data: # Check if Condition block exists
                                        for cond_operator, cond_pairs in condition_data.items():
                                            # Check variations like StringEquals, StringLike etc.
                                            if isinstance(cond_pairs, dict) and 'sts:ExternalId' in cond_pairs:
                                                has_external_id = True
                                                break
                                    if not has_external_id:
                                        finding = {
                                            "type": "IAM Role Trust - Missing ExternalId",
                                            "resource_arn": role_arn,
                                            "details": f"Role trusts external account '{trusted_account_id}' without 'sts:ExternalId' condition.",
                                            "trusted_principal": principal_arn_str,
                                            "policy_statement": stmt,
                                            "poc_guidance": generate_role_poc_guidance(role_arn, trusted_account_id)
                                        }
                                        findings.append(finding)
                                        logging.warning(f"Potential Finding: {finding['details']} (Role: {role_name})")

                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchEntity':
                        logging.warning(f"Role '{role_name}' not found during detailed check (possibly deleted recently). Skipping.")
                    elif e.response['Error']['Code'] == 'AccessDenied':
                         logging.error(f"Access Denied getting details for role '{role_name}'. Check permissions. Skipping.")
                    else:
                        logging.error(f"Error getting details for role '{role_name}': {e}")
                except Exception as e:
                     logging.error(f"Unexpected error processing role '{role_name}': {e}")

        logging.info(f"Finished IAM Role check. Processed {role_counter} roles.")

    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            logging.error("Access Denied listing IAM roles. Please ensure the profile has 'iam:ListRoles' and potentially 'iam:GetRole' permissions.")
            print("\nError: Access Denied listing IAM roles. Check permissions.")
        else:
            logging.error(f"An AWS error occurred during IAM check: {e}")
            print(f"\nAn AWS error occurred: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during IAM check: {e}")
        print(f"\nAn unexpected error occurred: {e}")

    return findings

def generate_role_poc_guidance(role_arn, trusted_account_id):
    """Generates manual PoC steps for a role missing ExternalId."""
    guidance = [
        f"Risk: Role '{role_arn}' trusts account '{trusted_account_id}' without 'sts:ExternalId'.",
        "  Any IAM principal (user or role) within that trusted account might be able to assume this role if they know its ARN and have 'sts:AssumeRole' permission.",
        "Manual PoC Steps:",
        f"1. Obtain AWS credentials (access key/secret key or assume a role) for an IAM principal *within* the trusted account ({trusted_account_id}). Ensure this principal has 'sts:AssumeRole' permission.",
        "2. Configure the AWS CLI or SDK to use these credentials from the trusted account.",
        "3. Execute the following AWS CLI command:",
        f"   aws sts assume-role --role-arn \"{role_arn}\" --role-session-name ConfusedDeputyPoC_Audit",
        "4. If the command SUCCEEDS:",
        "   - It will return temporary credentials (AccessKeyId, SecretAccessKey, SessionToken).",
        "   - This demonstrates that the role can be assumed from the external account without an ExternalId check.",
        "   - (Optional) Configure a new temporary AWS profile with these credentials and run a command like 'aws s3 ls --profile <temp_profile_name>' or 'aws iam get-user --profile <temp_profile_name>' to verify access level.",
        "5. If the command FAILS:",
        "   - Check the error message. It might be due to other conditions in the trust policy, permissions boundaries, Service Control Policies (SCPs), or the specific principal used lacking 'sts:AssumeRole' permission in the trusted account.",
        "   - However, the lack of 'sts:ExternalId' itself remains a potential weakness that should generally be addressed for third-party trust.",
        "Recommendation: Add a Condition block with a unique 'sts:ExternalId' (provided by the trusted entity) to the role's trust policy statement for account " + trusted_account_id + "."
    ]
    return "\n".join(guidance)


# --- S3 Bucket Checks ---

def check_s3_buckets(session):
    """
    Checks S3 bucket policies for potential Confused Deputy issues
    related to service principals lacking source checks.
    """
    s3_client = session.client('s3')
    findings = []
    logging.info("Starting S3 Bucket policy check...")
    bucket_counter = 0

    try:
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])

        for bucket in buckets:
            bucket_counter += 1
            bucket_name = bucket['Name']
            logging.debug(f"Checking bucket: {bucket_name}")

            try:
                policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                policy_str = policy_response.get('Policy')

                if policy_str:
                    policy_doc = json.loads(policy_str)
                    statements = policy_doc.get('Statement', [])

                    for stmt_idx, stmt in enumerate(statements):
                        effect = stmt.get('Effect', 'Allow')
                        principal_data = stmt.get('Principal', {})
                        condition_data = stmt.get('Condition', {})
                        action_data = stmt.get('Action', '')

                        # Check if principal is a service
                        if effect == 'Allow' and 'Service' in principal_data:
                            service_principals = principal_data['Service']
                            if not isinstance(service_principals, list):
                                service_principals = [service_principals]

                            # --- VULNERABILITY CHECK ---
                            if not has_source_condition(condition_data):
                                finding = {
                                    "type": "S3 Bucket Policy - Service Principal Missing Source Check",
                                    "resource_arn": f"arn:aws:s3:::{bucket_name}",
                                    "details": f"Bucket policy allows service principal(s) '{', '.join(service_principals)}' actions without 'aws:SourceAccount' or 'aws:SourceArn' condition.",
                                    "service_principal": service_principals,
                                    "policy_statement": stmt,
                                    "poc_guidance": generate_s3_poc_guidance(bucket_name, service_principals, action_data)
                                }
                                findings.append(finding)
                                logging.warning(f"Potential Finding: {finding['details']} (Bucket: {bucket_name})")
                else:
                    logging.debug(f"Bucket '{bucket_name}' policy string is empty.")


            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    logging.debug(f"Bucket '{bucket_name}' has no policy.")
                elif e.response['Error']['Code'] == 'AccessDenied':
                    logging.warning(f"Access Denied getting policy for bucket '{bucket_name}'. Check permissions (s3:GetBucketPolicy). Skipping.")
                else:
                    # Handle potential region redirection errors if client is not region-aware for get_bucket_policy
                    logging.error(f"Error getting policy for bucket '{bucket_name}': {e}")
            except json.JSONDecodeError as e:
                logging.error(f"Error decoding policy JSON for bucket '{bucket_name}': {e}")
            except Exception as e:
                 logging.error(f"Unexpected error processing bucket '{bucket_name}': {e}")

        logging.info(f"Finished S3 Bucket check. Processed {bucket_counter} buckets.")

    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            logging.error("Access Denied listing S3 buckets. Please ensure the profile has 's3:ListAllMyBuckets' permission.")
            print("\nError: Access Denied listing S3 buckets. Check permissions.")
        else:
            logging.error(f"An AWS error occurred during S3 check: {e}")
            print(f"\nAn AWS error occurred: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during S3 check: {e}")
        print(f"\nAn unexpected error occurred: {e}")

    return findings

def generate_s3_poc_guidance(bucket_name, service_principals, actions):
    """Generates manual PoC steps for S3 policy missing source checks."""
    # Make actions easier to check
    action_list = actions if isinstance(actions, list) else [actions]
    action_str_lower = ",".join(action_list).lower() # Combine and lower-case for easier checking

    guidance = [
        f"Risk: Bucket 's3://{bucket_name}' allows service principal(s) '{', '.join(service_principals)}' actions ({actions}) without 'aws:SourceAccount' or 'aws:SourceArn' conditions.",
        "  Any AWS account might be able to configure that AWS service to perform the allowed actions on *this* bucket if they know its name.",
        "Manual PoC Steps (Example - adapt based on service and actions):",
        "  Scenario Assumption: Service is 'cloudtrail.amazonaws.com' and 's3:PutObject' is allowed.",
        "  1. Obtain AWS credentials for a *different*, potentially unauthorized AWS account (Account B).",
        "  2. Configure the AWS CLI or SDK to use Account B's credentials.",
        "  3. In Account B, create a new CloudTrail trail.",
        "  4. During setup (or by modifying the trail settings using 'aws cloudtrail update-trail --name <trail_name_in_B> --s3-bucket-name <bucket_name_in_A>'), configure the trail's S3 bucket destination.",
        f"     Specify *this* bucket name in Account A: '{bucket_name}'",
        "  5. Wait a few minutes and perform some actions in Account B that generate CloudTrail events (e.g., list S3 buckets: `aws s3 ls`).",
        f"  6. Check the target bucket ('s3://{bucket_name}') in Account A, looking under the prefix `AWSLogs/ACCOUNT_B_ID/CloudTrail/`.",
        "  7. If you see CloudTrail log files appearing from Account B's trail inside your Account A bucket, this proves the vulnerability.",
        "  Scenario Assumption 2: Service is 'serverlessrepo.amazonaws.com' and 's3:GetObject' allowed.",
        "  1. In a *different* AWS account (Account B), create a dummy Serverless Application Repository application.",
        "  2. Use the AWS CLI from Account B to update the application's README URL to point to a known object in the vulnerable bucket:",
        f"     `aws serverlessrepo update-application --application-id <app-id-in-B> --readme-url s3://{bucket_name}/<some-known-object-key>`",
        "  3. If the update succeeds without error, navigate to the SAR application in the AWS Console in Account B.",
        "  4. If the README section attempts to load and potentially displays content (or shows an error clearly indicating access to the object was attempted), this can indicate the vulnerability.",
        "Recommendation: Add a Condition block to the bucket policy statement.",
        "  - Use 'aws:SourceAccount': { 'StringEquals': { 'aws:SourceAccount': 'ACCOUNT_ID_USING_THE_SERVICE' } }",
        "  - Or, more specifically, use 'aws:SourceArn': { 'ArnEquals': { 'aws:SourceArn': 'ARN_OF_RESOURCE_USING_THE_SERVICE' } } (e.g., CloudTrail Trail ARN, SAR Application ARN)"
    ]
    return "\n".join(guidance)

# --- SQS Queue Checks ---

def check_sqs_queues(session):
    """
    Checks SQS queue policies for potential Confused Deputy issues
    related to service principals lacking source checks.
    """
    sqs_client = session.client('sqs')
    findings = []
    logging.info("Starting SQS Queue policy check...")
    queue_counter = 0

    try:
        paginator = sqs_client.get_paginator('list_queues')
        for page in paginator.paginate():
            queue_urls = page.get('QueueUrls', [])
            for queue_url in queue_urls:
                queue_counter += 1
                logging.debug(f"Checking queue: {queue_url}")
                try:
                    # Get policy and ARN together
                    attributes = sqs_client.get_queue_attributes(
                        QueueUrl=queue_url,
                        AttributeNames=['Policy', 'QueueArn']
                    )
                    policy_str = attributes.get('Attributes', {}).get('Policy')
                    # Use ARN if available, otherwise fallback to URL for identification
                    queue_arn = attributes.get('Attributes', {}).get('QueueArn', queue_url)

                    if policy_str:
                        policy_doc = json.loads(policy_str)
                        statements = policy_doc.get('Statement', [])

                        for stmt_idx, stmt in enumerate(statements):
                            effect = stmt.get('Effect', 'Allow')
                            principal_data = stmt.get('Principal', {})
                            condition_data = stmt.get('Condition', {})
                            action_data = stmt.get('Action', '')

                            if effect == 'Allow' and 'Service' in principal_data:
                                service_principals = principal_data['Service']
                                if not isinstance(service_principals, list):
                                    service_principals = [service_principals]

                                # --- VULNERABILITY CHECK ---
                                if not has_source_condition(condition_data):
                                    finding = {
                                        "type": "SQS Queue Policy - Service Principal Missing Source Check",
                                        "resource_arn": queue_arn,
                                        "details": f"Queue policy allows service principal(s) '{', '.join(service_principals)}' without 'aws:SourceAccount' or 'aws:SourceArn' condition.",
                                        "service_principal": service_principals,
                                        "policy_statement": stmt,
                                        "poc_guidance": generate_sqs_poc_guidance(queue_url, queue_arn, service_principals, action_data)
                                    }
                                    findings.append(finding)
                                    logging.warning(f"Potential Finding: {finding['details']} (Queue URL: {queue_url})")
                    else:
                        logging.debug(f"Queue '{queue_url}' has no policy.")

                except ClientError as e:
                    if e.response['Error']['Code'] == 'AccessDenied':
                         logging.warning(f"Access Denied getting attributes for queue '{queue_url}'. Skipping.")
                    # Add handling for queues that might have been deleted between list and get_attributes
                    elif 'NonExistentQueue' in e.response['Error']['Code']:
                         logging.warning(f"Queue '{queue_url}' non-existent. Skipping.")
                    else:
                         logging.error(f"Error getting attributes for queue '{queue_url}': {e}")
                except json.JSONDecodeError as e:
                    logging.error(f"Error decoding policy JSON for queue '{queue_url}': {e}")
                except Exception as e:
                    logging.error(f"Unexpected error processing queue '{queue_url}': {e}")

        logging.info(f"Finished SQS Queue check. Processed {queue_counter} queues.")

    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            logging.error("Access Denied listing SQS queues. Check 'sqs:ListQueues' permission.")
            print("\nError: Access Denied listing SQS queues.")
        else:
            logging.error(f"An AWS error occurred during SQS check: {e}")
            print(f"\nAn AWS error occurred: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during SQS check: {e}")
        print(f"\nAn unexpected error occurred: {e}")

    return findings

def generate_sqs_poc_guidance(queue_url, queue_arn, service_principals, actions):
    """Generates manual PoC steps for SQS policy missing source checks."""
    action_list = actions if isinstance(actions, list) else [actions]
    action_str_lower = ",".join(action_list).lower()

    guidance = [
        f"Risk: Queue '{queue_arn}' allows service principal(s) '{', '.join(service_principals)}' actions ({actions}) without 'aws:SourceAccount' or 'aws:SourceArn' conditions.",
        "  Any AWS account might be able to configure that service to perform the allowed actions on *this* queue if they know its URL/ARN.",
        "Manual PoC Steps (Example - adapt based on service and action):",
        "  Scenario Assumption: Service is 'sns.amazonaws.com' and 'sqs:SendMessage' is allowed.",
        "  1. Obtain AWS credentials for a *different* AWS account (Account B).",
        "  2. In Account B, create an SNS topic.",
        "  3. Create an SNS subscription from the topic in Account B, targeting *this* SQS queue in Account A.",
        f"     Protocol: SQS, Endpoint: {queue_arn}",
        "     Use AWS CLI: `aws sns subscribe --topic-arn <topic_arn_in_B> --protocol sqs --notification-endpoint <queue_arn_in_A>`",
        "  4. IMPORTANT: By default, SQS requires confirmation. Check the target queue in Account A for a subscription confirmation message. Copy the 'SubscribeURL' from the message body and visit it in a browser (or use curl/wget) to confirm.",
        "     (If the queue policy is extremely permissive, confirmation might not be strictly needed, but it's standard).",
        "  5. Once confirmed, publish a test message to the SNS topic in Account B:",
        "     `aws sns publish --topic-arn <topic_arn_in_B> --message 'Confused Deputy PoC Test'`",
        f"  6. Check the SQS queue ('{queue_url}') in Account A using:",
        "     `aws sqs receive-message --queue-url <queue_url_in_A>`",
        "  7. If the test message published from Account B's SNS topic arrives in Account A's SQS queue, this proves the vulnerability (SNS could send messages without source checks).",
        "Recommendation: Add a Condition block to the queue policy statement.",
        "  - Use 'aws:SourceAccount': { 'StringEquals': { 'aws:SourceAccount': 'ACCOUNT_ID_OWNING_SNS_TOPIC_ETC' } }",
        "  - Or, more specifically, use 'aws:SourceArn': { 'ArnEquals': { 'aws:SourceArn': 'ARN_OF_SNS_TOPIC_OR_S3_BUCKET_ETC' } }"
    ]
    return "\n".join(guidance)

# --- SNS Topic Checks ---

def check_sns_topics(session):
    """
    Checks SNS topic policies for potential Confused Deputy issues
    related to service principals lacking source checks.
    """
    sns_client = session.client('sns')
    findings = []
    logging.info("Starting SNS Topic policy check...")
    topic_counter = 0

    try:
        paginator = sns_client.get_paginator('list_topics')
        for page in paginator.paginate():
            topics = page.get('Topics', [])
            for topic in topics:
                topic_counter += 1
                topic_arn = topic['TopicArn']
                logging.debug(f"Checking topic: {topic_arn}")
                try:
                    attributes = sns_client.get_topic_attributes(TopicArn=topic_arn)
                    policy_str = attributes.get('Attributes', {}).get('Policy')

                    if policy_str:
                        policy_doc = json.loads(policy_str)
                        statements = policy_doc.get('Statement', [])

                        for stmt_idx, stmt in enumerate(statements):
                            effect = stmt.get('Effect', 'Allow')
                            principal_data = stmt.get('Principal', {})
                            condition_data = stmt.get('Condition', {})
                            action_data = stmt.get('Action', '')

                            if effect == 'Allow' and 'Service' in principal_data:
                                service_principals = principal_data['Service']
                                if not isinstance(service_principals, list):
                                    service_principals = [service_principals]

                                # --- VULNERABILITY CHECK ---
                                if not has_source_condition(condition_data):
                                    finding = {
                                        "type": "SNS Topic Policy - Service Principal Missing Source Check",
                                        "resource_arn": topic_arn,
                                        "details": f"Topic policy allows service principal(s) '{', '.join(service_principals)}' without 'aws:SourceAccount' or 'aws:SourceArn' condition.",
                                        "service_principal": service_principals,
                                        "policy_statement": stmt,
                                        "poc_guidance": generate_sns_poc_guidance(topic_arn, service_principals, action_data)
                                    }
                                    findings.append(finding)
                                    logging.warning(f"Potential Finding: {finding['details']} (Topic: {topic_arn})")
                    else:
                        # SNS GetTopicAttributes might not return 'Policy' if it's the default (owner only)
                        logging.debug(f"Topic '{topic_arn}' has no explicit policy (or policy not retrieved).")

                except ClientError as e:
                    if e.response['Error']['Code'] == 'AccessDenied':
                         logging.warning(f"Access Denied getting attributes for topic '{topic_arn}'. Skipping.")
                    elif e.response['Error']['Code'] == 'NotFoundException': # Topic might have been deleted
                         logging.warning(f"Topic '{topic_arn}' not found. Skipping.")
                    elif e.response['Error']['Code'] == 'AuthorizationError': # Can happen sometimes
                         logging.warning(f"Authorization error getting attributes for topic '{topic_arn}'. Skipping.")
                    else:
                         logging.error(f"Error getting attributes for topic '{topic_arn}': {e}")
                except json.JSONDecodeError as e:
                    logging.error(f"Error decoding policy JSON for topic '{topic_arn}': {e}")
                except Exception as e:
                    logging.error(f"Unexpected error processing topic '{topic_arn}': {e}")

        logging.info(f"Finished SNS Topic check. Processed {topic_counter} topics.")

    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            logging.error("Access Denied listing SNS topics. Check 'sns:ListTopics' permission.")
            print("\nError: Access Denied listing SNS topics.")
        elif e.response['Error']['Code'] == 'AuthorizationError':
             logging.error("Authorization error listing SNS topics. Check credentials/permissions.")
             print("\nError: Authorization error listing SNS topics.")
        else:
            logging.error(f"An AWS error occurred during SNS check: {e}")
            print(f"\nAn AWS error occurred: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during SNS check: {e}")
        print(f"\nAn unexpected error occurred: {e}")

    return findings

def generate_sns_poc_guidance(topic_arn, service_principals, actions):
    """Generates manual PoC steps for SNS policy missing source checks."""
    action_list = actions if isinstance(actions, list) else [actions]
    action_str_lower = ",".join(action_list).lower()

    guidance = [
        f"Risk: Topic '{topic_arn}' allows service principal(s) '{', '.join(service_principals)}' actions ({actions}) without 'aws:SourceAccount' or 'aws:SourceArn' conditions.",
        "  Any AWS account might configure that service to perform the allowed actions (like 'sns:Publish') on *this* topic if they know its ARN.",
        "Manual PoC Steps (Example - adapt based on service and action):",
        "  Scenario Assumption: Service is 's3.amazonaws.com' and 'sns:Publish' is allowed.",
        "  1. Obtain AWS credentials for a *different* AWS account (Account B).",
        "  2. In Account B, create an S3 bucket.",
        "  3. Configure 'Event Notifications' for the S3 bucket in Account B (via Console or CLI `put-bucket-notification-configuration`).",
        "  4. Set up a notification to send events (e.g., 's3:ObjectCreated:*') to an SNS Topic.",
        f"     For the SNS Topic destination, specify the ARN of *this* topic in Account A: '{topic_arn}'",
        "  5. Upload a test file to the S3 bucket in Account B.",
        f"  6. Monitor the SNS topic ('{topic_arn}') in Account A. Subscribe an SQS queue or email address to the topic for easy verification.",
        "     `aws sns subscribe --topic-arn <topic_arn_in_A> --protocol email --notification-endpoint <your_email>` (Confirm subscription via email link).",
        "  7. If a notification message triggered by the S3 event from Account B arrives at your subscription (email/SQS), this proves the vulnerability.",
        "Recommendation: Add a Condition block to the topic policy statement.",
        "  - Use 'aws:SourceAccount': { 'StringEquals': { 'aws:SourceAccount': 'ACCOUNT_ID_CONFIGURING_S3_ETC' } }",
        "  - Or, more specifically, use 'aws:SourceArn': { 'ArnEquals': { 'aws:SourceArn': 'ARN_OF_S3_BUCKET_OR_EVENT_RULE_ETC' } }"
    ]
    return "\n".join(guidance)

# --- KMS Key Checks ---

def check_kms_keys(session):
    """
    Checks KMS key policies for potential Confused Deputy issues
    related to service principals lacking source checks.
    """
    kms_client = session.client('kms')
    findings = []
    logging.info("Starting KMS Key policy check...")
    key_counter = 0

    try:
        paginator = kms_client.get_paginator('list_keys')
        for page in paginator.paginate():
            keys = page.get('Keys', [])
            for key_info in keys:
                key_counter += 1
                key_id = key_info['KeyId']
                key_arn = key_info['KeyArn'] # Use ARN for finding resource identifier
                logging.debug(f"Checking key: {key_id} ({key_arn})")

                try:
                    # Only check Customer Managed Keys (CMKs) as AWS Managed Keys have policies controlled by AWS
                    # We need describe_key to check KeyManager == 'CUSTOMER'
                    key_metadata = kms_client.describe_key(KeyId=key_id)
                    if key_metadata['KeyMetadata']['KeyManager'] != 'CUSTOMER':
                        logging.debug(f"Skipping non-customer managed key: {key_id}")
                        continue

                    policy_response = kms_client.get_key_policy(KeyId=key_id, PolicyName='default')
                    policy_str = policy_response.get('Policy')

                    if policy_str:
                        policy_doc = json.loads(policy_str)
                        statements = policy_doc.get('Statement', [])

                        for stmt_idx, stmt in enumerate(statements):
                            effect = stmt.get('Effect', 'Allow')
                            principal_data = stmt.get('Principal', {})
                            condition_data = stmt.get('Condition', {})
                            action_data = stmt.get('Action', '')

                            # Focus on explicit Service principals first
                            if effect == 'Allow' and 'Service' in principal_data:
                                service_principals = principal_data['Service']
                                if not isinstance(service_principals, list):
                                    service_principals = [service_principals]

                                # --- VULNERABILITY CHECK ---
                                if not has_source_condition(condition_data):
                                    finding = {
                                        "type": "KMS Key Policy - Service Principal Missing Source Check",
                                        "resource_arn": key_arn,
                                        "details": f"Key policy allows service principal(s) '{', '.join(service_principals)}' without 'aws:SourceAccount' or 'aws:SourceArn' condition.",
                                        "service_principal": service_principals,
                                        "policy_statement": stmt,
                                        "poc_guidance": generate_kms_poc_guidance(key_arn, service_principals, action_data)
                                    }
                                    findings.append(finding)
                                    logging.warning(f"Potential Finding: {finding['details']} (Key: {key_id})")

                except ClientError as e:
                    # Keys pending deletion or otherwise inaccessible might raise errors
                    if e.response['Error']['Code'] == 'AccessDeniedException':
                         logging.warning(f"Access Denied describing/getting policy for key '{key_id}'. Skipping.")
                    elif e.response['Error']['Code'] in ['NotFoundException', 'KMSInvalidStateException', 'InvalidArnException']:
                         logging.warning(f"Key '{key_id}' not found, in invalid state, or ARN invalid. Skipping ({e.response['Error']['Code']}).")
                    elif e.response['Error']['Code'] == 'KeyUnavailableException':
                         logging.warning(f"Key '{key_id}' is currently unavailable (e.g., pending import/deletion). Skipping.")
                    else:
                         logging.error(f"Error processing key '{key_id}': {e}")
                except json.JSONDecodeError as e:
                    logging.error(f"Error decoding policy JSON for key '{key_id}': {e}")
                except Exception as e:
                    logging.error(f"Unexpected error processing key '{key_id}': {e}")

        logging.info(f"Finished KMS Key check. Processed {key_counter} keys (attempted checks on Customer Managed Keys).")

    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            logging.error("Access Denied listing/describing KMS keys. Check 'kms:ListKeys', 'kms:DescribeKey', 'kms:GetKeyPolicy' permissions.")
            print("\nError: Access Denied listing/describing KMS keys.")
        else:
            logging.error(f"An AWS error occurred during KMS check: {e}")
            print(f"\nAn AWS error occurred: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during KMS check: {e}")
        print(f"\nAn unexpected error occurred: {e}")

    return findings

def generate_kms_poc_guidance(key_arn, service_principals, actions):
    """Generates manual PoC steps for KMS policy missing source checks."""
    action_list = actions if isinstance(actions, list) else [actions]
    action_str_lower = ",".join(action_list).lower()
    guidance = [
        f"Risk: KMS Key '{key_arn}' policy allows service principal(s) '{', '.join(service_principals)}' actions ({actions}) without 'aws:SourceAccount' or 'aws:SourceArn' conditions.",
        "  Any AWS account might configure that service (if it assumes a role allowed by the policy or uses the service principal directly) to use *this* key for the allowed actions.",
        "Manual PoC Steps (Example - adapt based on service and action):",
        "  Scenario Assumption: Service is 'logs.<region>.amazonaws.com' and actions like 'kms:Encrypt', 'kms:Decrypt', 'kms:GenerateDataKey*' are allowed.",
        "  1. Obtain AWS credentials for a *different* AWS account (Account B).",
        "  2. In Account B, create a CloudWatch Log Group.",
        "  3. Attempt to associate *this* KMS key from Account A with the Log Group in Account B for encryption:",
        f"     `aws logs associate-kms-key --log-group-name <log_group_in_B> --kms-key-id \"{key_arn}\"`",
        "  4. If the association SUCCEEDS (without errors related to KMS access denied):",
        "     - This indicates CloudWatch Logs service principal from Account B's region could potentially use the key based on the vulnerable policy.",
        "     - Further test by ensuring logs written to the group in Account B are actually encrypted using the key from Account A (may be harder to verify directly).",
        "  5. If the command FAILS:",
        "     - Check the error. KMS key policies are evaluated alongside IAM permissions. The service principal needs access via the key policy, AND the entity *configuring* the service (e.g., your user/role in Account B) needs `kms:CreateGrant` or relevant permissions, potentially allowed via the key policy too.",
        "Recommendation: Add a Condition block to the key policy statement allowing the service principal.",
        "  - Use 'aws:SourceAccount': { 'StringEquals': { 'aws:SourceAccount': 'ACCOUNT_ID_WHERE_LOG_GROUP_EXISTS_ETC' } }",
        "  - Or, more specifically, use 'aws:SourceArn': { 'ArnLike': { 'aws:SourceArn': 'arn:aws:logs:REGION:ACCOUNT_ID:log-group:LOG_GROUP_NAME:*' } }",
        "  - Consider using KMS Encryption Context conditions ('kms:EncryptionContext:*') for cryptographic operations."
    ]
    return "\n".join(guidance)

# --- Lambda Function Checks ---

def check_lambda_functions(session):
    """
    Checks Lambda function resource-based policies for potential Confused Deputy issues
    related to service principals lacking source checks for invocation.
    """
    lambda_client = session.client('lambda')
    findings = []
    logging.info("Starting Lambda Function resource policy check...")
    func_counter = 0

    try:
        paginator = lambda_client.get_paginator('list_functions')
        for page in paginator.paginate():
            functions = page.get('Functions', [])
            for function in functions:
                func_counter += 1
                function_name = function['FunctionName']
                function_arn = function['FunctionArn']
                logging.debug(f"Checking function: {function_name}")

                try:
                    # Lambda GetPolicy throws ResourceNotFoundException if no policy exists
                    policy_response = lambda_client.get_policy(FunctionName=function_name)
                    policy_str = policy_response.get('Policy')

                    if policy_str:
                        policy_doc = json.loads(policy_str)
                        statements = policy_doc.get('Statement', [])

                        for stmt_idx, stmt in enumerate(statements):
                            effect = stmt.get('Effect', 'Allow')
                            principal_data = stmt.get('Principal', {})
                            condition_data = stmt.get('Condition', {})
                            action_data = stmt.get('Action', '')

                            # Check if principal is a service and action allows invocation
                            action_list = action_data if isinstance(action_data, list) else [action_data]
                            allows_invoke = any(a.lower() == 'lambda:invokefunction' or a.lower() == 'lambda:*' or a == '*' for a in action_list)

                            if effect == 'Allow' and 'Service' in principal_data and allows_invoke:
                                service_principals = principal_data['Service']
                                if not isinstance(service_principals, list):
                                    service_principals = [service_principals]

                                # --- VULNERABILITY CHECK ---
                                if not has_source_condition(condition_data):
                                    finding = {
                                        "type": "Lambda Policy - Service Principal Missing Source Check",
                                        "resource_arn": function_arn,
                                        "details": f"Function policy allows service principal(s) '{', '.join(service_principals)}' invoke access without 'aws:SourceAccount' or 'aws:SourceArn' condition.",
                                        "service_principal": service_principals,
                                        "policy_statement": stmt,
                                        "poc_guidance": generate_lambda_poc_guidance(function_arn, service_principals, action_data)
                                    }
                                    findings.append(finding)
                                    logging.warning(f"Potential Finding: {finding['details']} (Function: {function_name})")

                except ClientError as e:
                    if e.response['Error']['Code'] == 'ResourceNotFoundException':
                         logging.debug(f"Function '{function_name}' has no resource-based policy.")
                    elif e.response['Error']['Code'] == 'AccessDeniedException':
                         logging.warning(f"Access Denied getting policy for function '{function_name}'. Skipping.")
                    else:
                         logging.error(f"Error getting policy for function '{function_name}': {e}")
                except json.JSONDecodeError as e:
                    logging.error(f"Error decoding policy JSON for function '{function_name}': {e}")
                except Exception as e:
                    logging.error(f"Unexpected error processing function '{function_name}': {e}")

        logging.info(f"Finished Lambda Function check. Processed {func_counter} functions.")

    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            logging.error("Access Denied listing Lambda functions. Check 'lambda:ListFunctions' permission.")
            print("\nError: Access Denied listing Lambda functions.")
        else:
            logging.error(f"An AWS error occurred during Lambda check: {e}")
            print(f"\nAn AWS error occurred: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during Lambda check: {e}")
        print(f"\nAn unexpected error occurred: {e}")

    return findings

def generate_lambda_poc_guidance(function_arn, service_principals, actions):
    """Generates manual PoC steps for Lambda policy missing source checks."""
    action_list = actions if isinstance(actions, list) else [actions]
    guidance = [
        f"Risk: Lambda function '{function_arn}' policy allows service principal(s) '{', '.join(service_principals)}' to invoke ({action_list}) without 'aws:SourceAccount' or 'aws:SourceArn' conditions.",
        "  Any AWS account might configure that service to invoke *this* function if they know its ARN.",
        "Manual PoC Steps (Example - adapt based on service):",
        "  Scenario Assumption: Service is 'apigateway.amazonaws.com' and 'lambda:InvokeFunction' is allowed.",
        "  1. Obtain AWS credentials for a *different* AWS account (Account B).",
        "  2. In Account B, create an API Gateway REST API.",
        "  3. Configure a method (e.g., GET on the root resource '/') within the API in Account B.",
        "  4. Set the 'Integration type' for this method to 'AWS Service', Service='Lambda', Action='Invoke'.",
        f"  5. Specify the function ARN from Account A as the target: '{function_arn}'",
        "  6. Set up an Execution Role in Account B that API Gateway can assume. This role needs permissions to invoke Lambda functions (`lambda:InvokeFunction`).",
        "     NOTE: Depending on Account A's Lambda policy, this execution role ARN from Account B might ALSO need to be explicitly allowed in the function policy's 'Principal' section, in addition to the service principal check we are discussing.",
        "  7. Deploy the API in Account B.",
        "  8. Call the deployed API endpoint from Account B (e.g., using curl or Postman).",
        f"  9. Check the logs (e.g., CloudWatch Logs) for the Lambda function ('{function_arn}') in Account A.",
        "  10. If the function executes successfully triggered by the API Gateway call from Account B, this suggests the lack of source condition check is exploitable (assuming step 6 permissions are met).",
        "Recommendation: Add a Condition block to the function policy statement.",
        "  - Use 'aws:SourceAccount': { 'StringEquals': { 'aws:SourceAccount': 'ACCOUNT_ID_OF_API_GATEWAY_OWNER' } }",
        "  - Or, more specifically, use 'aws:SourceArn': { 'ArnLike': { 'aws:SourceArn': 'arn:aws:execute-api:REGION:ACCOUNT_ID:API_ID/*' } } (adjust ARN pattern for the triggering service, e.g., S3 bucket ARN, SQS queue ARN)"
    ]
    return "\n".join(guidance)

# --- Secrets Manager Secret Checks ---

def check_secrets_manager_secrets(session):
    """
    Checks Secrets Manager secret policies for potential Confused Deputy issues
    related to service principals lacking source checks.
    """
    secrets_client = session.client('secretsmanager')
    findings = []
    logging.info("Starting Secrets Manager Secret policy check...")
    secret_counter = 0

    try:
        # Filter for only Active secrets to reduce noise? Or check all? Checking all for now.
        paginator = secrets_client.get_paginator('list_secrets')
        for page in paginator.paginate(): # Add Filters=[{'Key': 'state', 'Values': ['Active']}] if desired
            secrets = page.get('SecretList', [])
            for secret_info in secrets:
                secret_counter += 1
                secret_id = secret_info['Name'] # Can use Name or ARN
                secret_arn = secret_info['ARN']
                logging.debug(f"Checking secret: {secret_id}")

                try:
                    # Throws ResourceNotFoundException if no policy exists
                    policy_response = secrets_client.get_resource_policy(SecretId=secret_id)
                    policy_str = policy_response.get('ResourcePolicy')

                    if policy_str:
                        policy_doc = json.loads(policy_str)
                        statements = policy_doc.get('Statement', [])

                        for stmt_idx, stmt in enumerate(statements):
                            effect = stmt.get('Effect', 'Allow')
                            principal_data = stmt.get('Principal', {})
                            condition_data = stmt.get('Condition', {})
                            action_data = stmt.get('Action', '')

                            # Check if principal is a service and action allows read
                            action_list = action_data if isinstance(action_data, list) else [action_data]
                            allows_read = any(a.lower() == 'secretsmanager:getsecretvalue' or a.lower() == 'secretsmanager:*' or a == '*' for a in action_list)

                            if effect == 'Allow' and 'Service' in principal_data and allows_read:
                                service_principals = principal_data['Service']
                                if not isinstance(service_principals, list):
                                    service_principals = [service_principals]

                                # --- VULNERABILITY CHECK ---
                                if not has_source_condition(condition_data):
                                    finding = {
                                        "type": "Secrets Manager Policy - Service Principal Missing Source Check",
                                        "resource_arn": secret_arn,
                                        "details": f"Secret policy allows service principal(s) '{', '.join(service_principals)}' GetSecretValue access without 'aws:SourceAccount' or 'aws:SourceArn' condition.",
                                        "service_principal": service_principals,
                                        "policy_statement": stmt,
                                        "poc_guidance": generate_secrets_poc_guidance(secret_arn, service_principals, action_data)
                                    }
                                    findings.append(finding)
                                    logging.warning(f"Potential Finding: {finding['details']} (Secret: {secret_id})")

                except ClientError as e:
                    if e.response['Error']['Code'] == 'ResourceNotFoundException':
                         logging.debug(f"Secret '{secret_id}' has no resource-based policy.")
                    elif e.response['Error']['Code'] == 'AccessDeniedException':
                         logging.warning(f"Access Denied getting policy for secret '{secret_id}'. Skipping.")
                    elif e.response['Error']['Code'] == 'InvalidRequestException' and 'marked for deletion' in e.response['Error']['Message']:
                         logging.warning(f"Secret '{secret_id}' is marked for deletion. Skipping policy check.")
                    else:
                         logging.error(f"Error getting policy for secret '{secret_id}': {e}")
                except json.JSONDecodeError as e:
                    logging.error(f"Error decoding policy JSON for secret '{secret_id}': {e}")
                except Exception as e:
                    logging.error(f"Unexpected error processing secret '{secret_id}': {e}")

        logging.info(f"Finished Secrets Manager Secret check. Processed {secret_counter} secrets.")

    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            logging.error("Access Denied listing Secrets Manager secrets. Check 'secretsmanager:ListSecrets' permission.")
            print("\nError: Access Denied listing Secrets Manager secrets.")
        else:
            logging.error(f"An AWS error occurred during Secrets Manager check: {e}")
            print(f"\nAn AWS error occurred: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during Secrets Manager check: {e}")
        print(f"\nAn unexpected error occurred: {e}")

    return findings

def generate_secrets_poc_guidance(secret_arn, service_principals, actions):
    """Generates manual PoC steps for Secrets Manager policy missing source checks."""
    action_list = actions if isinstance(actions, list) else [actions]
    guidance = [
        f"Risk: Secret '{secret_arn}' policy allows service principal(s) '{', '.join(service_principals)}' to potentially get its value ({action_list}) without 'aws:SourceAccount' or 'aws:SourceArn' conditions.",
        "  Any AWS account might configure that service (if it assumes a role allowed by the policy or uses the service principal directly) to retrieve *this* secret.",
        "Manual PoC Steps (Example - adapt based on service):",
        "  Scenario Assumption: Service is 'lambda.amazonaws.com' and 'secretsmanager:GetSecretValue' is allowed.",
        "  1. Obtain AWS credentials for a *different* AWS account (Account B).",
        "  2. In Account B, create a Lambda function.",
        "  3. Grant the Lambda function's execution role in Account B permission to call 'secretsmanager:GetSecretValue'.",
        "     IMPORTANT: The secret policy in Account A must ALSO allow Account B's Lambda execution role ARN as an 'AWS' principal (or allow Account B root `arn:aws:iam::ACCOUNT_B_ID:root`) for this specific PoC to work directly via the role.",
        "     However, the vulnerability regarding the *service principal* still exists if *another* service (like CodeBuild in Account B) could be configured to fetch the secret using its own service identity, assuming the policy allows the CodeBuild service principal without source checks.",
        "  4. Write Lambda code in Account B that attempts to call `secretsmanager_client.get_secret_value(SecretId='{secret_arn}')` using Boto3.",
        "  5. Invoke the Lambda function in Account B.",
        "  6. Check the Lambda function's execution logs in Account B.",
        "  7. If the Lambda function successfully retrieves the secret value from Account A, this proves the vulnerability (potentially via the execution role OR the service principal depending on the exact policy).",
        "Recommendation: Add a Condition block to the secret policy statement allowing the service principal.",
        "  - Use 'aws:SourceAccount': { 'StringEquals': { 'aws:SourceAccount': 'ACCOUNT_ID_WHERE_LAMBDA_RUNS_ETC' } }",
        "  - Or, more specifically, use 'aws:SourceArn': { 'ArnEquals': { 'aws:SourceArn': 'ARN_OF_LAMBDA_FUNCTION_OR_CODEBUILD_PROJECT_ETC' } }"
    ]
    return "\n".join(guidance)

# --- Output Handling ---

def display_findings(findings):
    """Prints findings to the console."""
    if not findings:
        print("\n[+] No potential Confused Deputy findings detected based on the checks run.")
        return

    print(f"\n--- Potential Confused Deputy Findings ({len(findings)}) ---")
    for idx, finding in enumerate(findings):
        print(f"\nFinding {idx + 1}: {finding['type']}")
        print(f"  Resource: {finding['resource_arn']}")
        print(f"  Details: {finding['details']}")
        # Optional: Print the specific policy statement for context
        # try:
        #     print(f"  Problematic Statement: {json.dumps(finding.get('policy_statement', ''), indent=2)}")
        # except TypeError:
        #     print(f"  Problematic Statement: {finding.get('policy_statement', '')}")

        print("\n  Manual PoC Guidance:")
        # Indent guidance for readability
        poc_lines = finding.get('poc_guidance', 'No specific guidance generated.').split('\n')
        for line in poc_lines:
            print(f"    {line}")
        print("-" * 60) # Separator line
    print("--- End of Findings ---")
    print("\nDisclaimer: These findings indicate potential misconfigurations based on policy analysis.")
    print("Manual verification is required to confirm actual exploitability and impact in your environment.")

def save_findings_json(findings, filename):
    """Saves findings to a JSON file."""
    if not findings:
        logging.info("No findings to save.")
        return

    try:
        with open(filename, 'w') as f:
            json.dump(findings, f, indent=4, default=str) # Use default=str for non-serializable types
        print(f"\n[+] Findings successfully saved to '{filename}'")
        logging.info(f"Findings saved to {filename}")
    except IOError as e:
        logging.error(f"Error saving findings to JSON file '{filename}': {e}")
        print(f"\nError: Could not write findings to '{filename}'. Check permissions or path.")
    except Exception as e:
        logging.error(f"Unexpected error saving findings to JSON: {e}")
        print(f"\nAn unexpected error occurred while saving to JSON.")


# --- Main Application Logic ---

def run_checks(session, current_account_id, check_choice):
    """Runs the selected checks based on the menu choice."""
    all_findings = []
    run_all = (check_choice == '9') # Assuming '9' is Run All

    if check_choice == '1' or run_all:
        print("\n[*] Running IAM Role Checks...")
        iam_findings = check_iam_roles(session, current_account_id)
        all_findings.extend(iam_findings)
        print("[*] IAM Role Checks Complete.")
    if check_choice == '2' or run_all:
        print("\n[*] Running S3 Bucket Checks...")
        s3_findings = check_s3_buckets(session)
        all_findings.extend(s3_findings)
        print("[*] S3 Bucket Checks Complete.")
    if check_choice == '3' or run_all:
        print("\n[*] Running SQS Queue Checks...")
        sqs_findings = check_sqs_queues(session)
        all_findings.extend(sqs_findings)
        print("[*] SQS Queue Checks Complete.")
    if check_choice == '4' or run_all:
        print("\n[*] Running SNS Topic Checks...")
        sns_findings = check_sns_topics(session)
        all_findings.extend(sns_findings)
        print("[*] SNS Topic Checks Complete.")
    if check_choice == '5' or run_all:
        print("\n[*] Running KMS Key Checks...")
        kms_findings = check_kms_keys(session)
        all_findings.extend(kms_findings)
        print("[*] KMS Key Checks Complete.")
    if check_choice == '6' or run_all:
        print("\n[*] Running Lambda Function Policy Checks...")
        lambda_findings = check_lambda_functions(session)
        all_findings.extend(lambda_findings)
        print("[*] Lambda Function Policy Checks Complete.")
    if check_choice == '7' or run_all:
        print("\n[*] Running Secrets Manager Secret Policy Checks...")
        secrets_findings = check_secrets_manager_secrets(session)
        all_findings.extend(secrets_findings)
        print("[*] Secrets Manager Secret Policy Checks Complete.")
    # Add calls for other services here if check_choice matches

    return all_findings

def main():
    """Main function to run the auditor tool."""
    print("-" * 60)
    print("--- AWS Confused Deputy Potential Vulnerability Detector ---")
    print("-" * 60)
    print("Disclaimer: This tool performs passive checks for common policy")
    print("misconfigurations. Findings require manual validation.")
    print("-" * 60)


    # 1. Select Profile
    profiles = get_aws_profiles()
    selected_profile = select_aws_profile(profiles)
    if not selected_profile:
        return # User cancelled or no profiles found

    # 2. Initialize Boto3 Session
    session = None
    current_account_id = None
    try:
        session = boto3.Session(profile_name=selected_profile)
        # Verify credentials and get account ID early
        sts_client = session.client('sts')
        identity = sts_client.get_caller_identity()
        current_account_id = identity['Account']
        caller_arn = identity['Arn']
        print(f"\nSuccessfully connected using profile '{selected_profile}'.")
        print(f"  Account ID: {current_account_id}")
        print(f"  Caller ARN: {caller_arn}")
        print("-" * 60)
        logging.info(f"Initialized Boto3 session for profile '{selected_profile}', Account ID: {current_account_id}, Caller: {caller_arn}")
    except ProfileNotFound:
         logging.error(f"AWS profile '{selected_profile}' not found.")
         print(f"\nError: Profile '{selected_profile}' not found. Check your AWS configuration (~/.aws/credentials and ~/.aws/config).")
         return
    except (NoCredentialsError, PartialCredentialsError) as e:
        logging.error(f"Credentials error for profile '{selected_profile}': {e}")
        print(f"\nError: Could not find valid credentials for profile '{selected_profile}'. {e}")
        return
    except ClientError as e:
         # Handle common STS errors during initial connection
        error_code = e.response.get('Error', {}).get('Code')
        if error_code == 'ExpiredToken':
             logging.error(f"AWS token for profile '{selected_profile}' is expired.")
             print(f"\nError: Credentials for profile '{selected_profile}' have expired.")
        elif error_code == 'InvalidClientTokenId':
             logging.error(f"Invalid AWS credentials for profile '{selected_profile}'.")
             print(f"\nError: Invalid credentials for profile '{selected_profile}'. Check access keys.")
        elif error_code == 'AccessDenied':
             logging.error(f"Access Denied calling sts:GetCallerIdentity for profile '{selected_profile}'.")
             print(f"\nError: Access Denied verifying identity for profile '{selected_profile}'. Ensure 'sts:GetCallerIdentity' permission.")
        else:
             logging.error(f"AWS ClientError connecting with profile '{selected_profile}': {e}")
             print(f"\nError: An AWS connection error occurred: {e}")
        return
    except Exception as e: # Catch other potential exceptions during session init
        logging.error(f"Failed to initialize Boto3 session for profile '{selected_profile}': {e}", exc_info=True)
        print(f"\nError: Failed to initialize AWS session for profile '{selected_profile}': {e}")
        return

    # 3. Main Menu Loop
    output_mode = 'console' # 'console' or 'file'
    output_filename = DEFAULT_OUTPUT_FILENAME.replace(TIMESTAMP, datetime.now().strftime("%Y%m%d_%H%M%S")) # Update timestamp

    while True:
        # Update default filename timestamp each time menu is shown
        output_filename = DEFAULT_OUTPUT_FILENAME.replace(f"audit_{TIMESTAMP}", f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

        print("\n--- Main Menu ---")
        print("1. Check IAM Roles (Trust Policy - ExternalId)")
        print("2. Check S3 Buckets (Resource Policy - Service Source)")
        print("3. Check SQS Queues (Resource Policy - Service Source)")
        print("4. Check SNS Topics (Resource Policy - Service Source)")
        print("5. Check KMS Keys (Resource Policy - Service Source)")
        print("6. Check Lambda Functions (Resource Policy - Service Source)")
        print("7. Check Secrets Manager Secrets (Resource Policy - Service Source)")
        # Add other service checks here as menu items 8, etc.
        print("8. ---")
        print("9. Run All Checks Listed Above")
        print("10. Configure Output [Current: {}]".format(
            f"Console & File ({output_filename})" if output_mode == 'file' else "Console Only"
        ))
        print("11. Exit")

        choice = input("Enter your choice: ")

        # Map choices to run_checks function (handle single and 'Run All')
        check_map = {'1', '2', '3', '4', '5', '6', '7', '9'}

        if choice in check_map:
            findings = run_checks(session, current_account_id, choice)
            display_findings(findings)
            if output_mode == 'file' and findings:
                save_findings_json(findings, output_filename)
        elif choice == '10': # Configure Output
            print("\n--- Configure Output ---")
            print("1. Console Output Only")
            # Refresh filename in prompt
            current_default_filename = DEFAULT_OUTPUT_FILENAME.replace(f"audit_{TIMESTAMP}", f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            print(f"2. Console and Save to JSON File (Default: {current_default_filename})")
            out_choice = input("Select output mode (1-2): ")
            if out_choice == '1':
                output_mode = 'console'
                print("Output set to Console Only.")
            elif out_choice == '2':
                output_mode = 'file'
                new_filename_input = input(f"Enter filename (leave blank for default with current timestamp): ").strip()
                if new_filename_input:
                     # Basic validation - ensure it ends with .json
                    if not new_filename_input.lower().endswith('.json'):
                         new_filename_input += '.json'
                    output_filename = new_filename_input
                else:
                    # Use the refreshed default if blank
                    output_filename = current_default_filename
                print(f"Output set to Console & File ('{output_filename}')")
            else:
                print("Invalid choice. Output mode unchanged.")
        elif choice == '11': # Exit
            print("\nExiting AWS Confused Deputy Detection Tool.")
            break
        else:
            print("Invalid choice. Please enter a number from the menu.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user. Exiting.")
    except Exception as e:
        # Catch any unexpected errors in the main loop
        logging.error("An unexpected error occurred in the main loop.", exc_info=True)
        print(f"\nAn unexpected critical error occurred: {e}")
