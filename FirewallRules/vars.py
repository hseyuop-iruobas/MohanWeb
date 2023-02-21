###############################

from pathlib import Path
#from urllib.parse import quote

THISISPROD = False #i mean set it to True when its prod



relativePath = str(Path.cwd()) #init RelativePath
FirewallFolder = relativePath + "/FirewallRules/FirewallRules/"
####################
#### here we have our file locations where all of ansible stuff runs or saves or plays from:

firewall_backup_file = 'backups/firewalls.backup.txt'
security_zone_backup_file = 'backups/secZones.backup.txt'
locations_backup_file = 'backups/Locations.backup.txt'
mysecretsfile_location = 'ansible-plays/inventory/firewall-secrets.yml'


vpn_ike_result_file = "results/vpnsettings.yml"
resultFolderPath = 'results/'
resultFileName = 'results/firewall_rules.yml'

location_file_path = 'vars/locations_file.yml'
location_root = 'locations'

object_file_path = 'vars/objects.yml'
object_root = 'objects'
newObject_Location = 'results/objects.yml'

object_group_file_path = 'vars/object_groups.yml'
object_group_root = 'object_groups'

service_path = 'vars/services.yml'
service_root = 'services'
services_play_var_file = 'results/services.yml'

rule_path = 'vars/firewall_rules.yml'
rule_root = 'firewall_rules'

#panorama /paloalto allows firewall rules to be 64chars. I use up a few myself so 60 set to max
max_rule_name_lenght = 60

###############################


'''
section below is used for configuration of basic variables/ models.
'''

interface_management_profile_choices = (('https-ssh-ping-snmp', 'https-ssh-ping-snmp'), ('ping', 'ping'))
service_protocol_choices = (('TCP', 'TCP'), ('UDP', 'UDP'),)
object_type_choices = (
    ('ip-netmask', 'ip-netmask'), ('address-group', 'address-group'), ('fqdn', 'fqdn'), ('special', 'special'),)
scheduleChoice = (
    ('5', '5 Days'), ('15', '15 Days'), ('30', '30 Days'), ('60', '60 Days'), ('90', '90 Days'), ('180', '6 Months'),
    ('0', 'Permanent'),)
change_status_choices = (('Not Started', 'Not Started'), ('Complete', 'Complete'), ('Started', 'Started'), ('ERROR', 'ERROR'))
rule_location_Choice = (('pre-rulebase', 'pre-rulebase'),('post-rulebase', 'post-rulebase'),)


####here we have Panorama settings:
panorama_server = ''
pano_readonly_username = ''
pano_readonly_password = ''
####################################
#####################################


#############HERE we have logging, and profile settings

Firewall_Settings = {
    'state': 'present',
    'log_setting': 'SOMELOGGINGPROFILE',
    'log_at_session_start': '0',
    'log_at_session_end': '1',
    'profile_type': 'Group',

}
#############END OF HERE we have logging, and profile settings
###########SNOW vars go here:
SERVICE_NOW_IS_SETUP = False
def getSNOW_baseURL():
    SNOW_baseURL = ''
    if THISISPROD:
        SNOW_baseURL = 'https://xxx.service-now.com/'
    else:
        SNOW_baseURL = 'https://xxx.service-now.com/'
    return SNOW_baseURL


def getSNOW_STD_Table_Location():
    SNOW_STD_Table_Location = ''
    if THISISPROD:
        SNOW_STD_Table_Location = 'api/now/table/change_request?sysparm_fields=number'
    else:
        SNOW_STD_Table_Location = 'api/now/table/change_request?sysparm_fields=number'
    return SNOW_STD_Table_Location


def getSNOW_Username():
    SNOW_Username = ''
    if THISISPROD:
        SNOW_Username = 'APIENABLEDUSERNAME@'
    else:
        SNOW_Username = 'APIENABLEDUSERNAME@'
    return SNOW_Username


def getSNOW_Password():
    SNOW_Password = ''
    if THISISPROD:
        SNOW_Password = ''
    else:
        SNOW_Password = ''
    return SNOW_Password

#####################################

#######Arista CONFIG HERE######

#Arista Switch Configuration
Arista_Switch_eAPI_transport="https"
