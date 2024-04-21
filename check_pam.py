""" Retrieve current users and group membership from Azure Entra and check for """
""" changes to membership of administrator groups as defined in config """

import argparse
import json
import subprocess
import shlex

# check CLI input flags
# --ouputdir=<dir> (default '.')
# --inputdir=<dir> (default '.')
# --config=<filename> (default ./check_pam_config.json)
# --outputfile=<filename> (default ddmmyy_ss_pam.json)
# --debug (default False by omission)
# --report=<filename> (report on either last review or based on given filename)
def get_args(): 
    parser = argparse.ArgumentParser(
        description="Check privileged access accounts in Entra for changes"
    )
    parser.add_argument("--outputdir", 
                        required=False, 
                        default=".",
                        help="output directory for saving current report")
    parser.add_argument("--inputdir", 
                        required=False, 
                        default=".",
                        help="input directory for reading previous report")
    parser.add_argument("--outputfile", 
                        required=False, 
                        default=".",
                        help="output file for saving current output report")
    parser.add_argument("--config", 
                        required=False, 
                        default="./check_pam_config.json",
                        help="config file path and name")
    parser.add_argument(
        "--debug", action="store_true", help="Enable debug mode (very verbose)"
    )
    parser.add_argument(
        "--report", action="store_true", help="Don't do live check, report on previous check"
    )
    return parser.parse_args()

def dump_args(args):
    print(f"args are {args}")

# read config file and parse for admin group names
def read_config(args): 
    if args.debug:
       print(f"Reading from config {args.config}")
    try:
        with open(args.config) as config_file:
            config = json.load(config_file)
    except FileNotFoundError as e:
        print(f"No config file found {args.config} {e}")
        exit()
    except json.JSONDecodeError as e:
        print(f"Config file {args.config} doesn't appear to be JSON")
        exit()

    if args.debug:
        print(f"Config is {config} and admingroups is {config['admingroups']}")

    return config

# need to be able to execute a command at the shell as this will be how we
# interact with the Azure CLI. Will be careful of command injection
    
# start with a command sanitisation function
def sanitize(s: str) -> str:
    replace_map = {
        ';': 'wasSemicolon',
        "\'": 'wasApostrophe',
        '"': 'wasQuote',
        '$': 'wasQuestion',
        '!': 'wasPling',
        '&': 'wasAmpersand'}
    sanitized = s
    for to_replace in replace_map:
        sanitized = sanitized.replace(to_replace, replace_map[to_replace])
    return sanitized

def ex_az_command(c: str) -> None:
    to_execute = sanitize(c)
    if not to_execute.startswith("az"):
        print("Command injection attempt? Command must start with 'az' was {to_execute} (after sanitization)")
        exit()
    try:
        if args.debug:
            print(f"executing command {to_execute}")
        result = subprocess.Popen(shlex.split(to_execute), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        std_out, std_err = result.communicate()
        if len(std_err):
            if std_err.find(b"az login") != -1:
                print(f"You do not appear to have a current Azure login session ({std_err}), terminating....")
                exit()
    except subprocess.CalledProcessError as e:
        print(f"unable to execute command {to_execute} exception is {e}")
    return std_out


# check for removals and additions (we will flag new admin groups as non-alerts)

# write new status to dated file 

# report changes and overall status


def banner():
    print(
        """
          
  _____        __  __        _               _    
 |  __ \ /\   |  \/  |      | |             | |   
 | |__) /  \  | \  / |   ___| |__   ___  ___| | __
 |  ___/ /\ \ | |\/| |  / __| '_ \ / _ \/ __| |/ /
 | |  / ____ \| |  | | | (__| | | |  __/ (__|   < 
 |_| /_/    \_\_|  |_|  \___|_| |_|\___|\___|_|\_\
                                                  
                                                  
 ++ D Scholefield. Ver 1.0 ++
          """
    )

if __name__ == "__main__":
    banner()

    # we'll record all useful events in the log and record them in the
    # record for this run
    log_lines = []

    args = get_args()
    if args.debug:  
        dump_args(args) 
    
    if args.report:
        report_last_check(args)
        exit()
    
    config = read_config(args)
    
    # confirm that there is a current login session to Azure for the
    # user running this script - this first execute will exit if there is no session
    print("Checking for live Azure session...")
    command_result = ex_az_command("az ad signed-in-user show")
    print("Session found, continuing")

    # now to get the user list
    print("Attempting to read the users from Entra")
    try:
        command_result = ex_az_command("az ad user list")
        users = json.loads(command_result.decode('utf-8'))
        count = 0
        for user in users:
            if args.debug:
                print(f"found user {user['userPrincipalName']}")
            count = count + 1
    except json.JSONDecodeError as e:
        print("Could not parse az output as valid JSON (or no users!): exception is {e}")
    
    print(f"Found {count} users in Entra for current subscription")
    print("Checking group membership, this will take some time")
    
    admin_groups={}
    user_check_count = 0
    for user in users:
        if args.debug:
            print(f"\tchecking user {user}")
        name = user['userPrincipalName']
        # for testing purposes let's cut out the platform accounts
        if name.startswith("A"):
            continue
        command_result = ex_az_command(f"az ad user get-member-groups --id {name}")
        try:
            record = json.loads(command_result)
        except:
            print(f"problem parsing json in {command_result}")
            continue
        for group in record:
            group_name = group['displayName']
            if args.debug:
                print(f"\t\t\tin group {group_name}")
            if group_name in config['admingroups']:
                # this is an admin group according to the config file
                # so we need to record it
                if args.debug:
                    print("this is an admin group according to the config file")
                if not group_name in admin_groups.keys():
                    admin_groups[group_name] = []
                admin_groups[group_name].append(name)
        user_check_count = user_check_count + 1
        if user_check_count > 10000:
            break
    
    # now to dump out the admin groups and their users
    print(f"{user_check_count} users checked")
    for group in admin_groups:
        print(f"Admin group: {group}")
        for user in admin_groups[group]:
            print(f"\t{user}")
    




        

