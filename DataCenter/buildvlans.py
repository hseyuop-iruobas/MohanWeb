DEBUG = False


#need sys and os to find path and set path 
from FirewallRules.vars import relativePath
from FirewallRules.models import Firewall_Interface
import os
from FirewallRules.tools import writeYamltoFile,writePanoSecretsFile #, getList, writetoFile, write_eos_yml_file
import yaml
#need time
from datetime import date
import time
#need ansible_runer to run plays
import ansible_runner
#set today
today = date.today()


#these things are used somewhere
varsFolderPath = relativePath + '/DataCenter/ansible-plays/vars/'
playsFolderPath = relativePath + '/DataCenter/ansible-plays/'
inventoryFolderPath = relativePath + '/DataCenter/ansible-plays/inventory/'
vrf_result_location_file = varsFolderPath+"vrf_data.yml"
vlan_add_location_file = varsFolderPath+"vlan_add.yml"
vlan_remove_location_file = varsFolderPath+"vlan_removed.yml"
eos_yaml_file_location = varsFolderPath + 'eos.yml'
interface_result_location_file = varsFolderPath+"build_this_interface.yml"
mysecretsfile_location = varsFolderPath+"mysecrets.yml"
panoInventoryFile_location = relativePath + '/FirewallRules/FirewallRules/ansible-plays/inventory/PALO-inventory.ini'



#need models
from .models import Tenant, Vlan, DataCenter
from FirewallRules.models import secZone,Firewall

#need some tools from tools

def removefile(filename):
   #assumes its a .yml file this is to get around some other issues at calling this crap
    newfilename = filename[:filename.find('.yml')] + "-" + today.strftime("%b-%d-%Y") + ".yml"
    print(f"going to move to { newfilename } ")
    stream = os.popen('mv ' + filename + ' ' + newfilename)  # move the Service play var file
def run_play_add_vlans():
    runner = ansible_runner.run(private_data_dir='',
                                playbook=playsFolderPath + 'addVLAN-leaf.yml',
                                inventory=inventoryFolderPath + 'DC2-inventory.ini')
    print("{}: {}".format(runner.status, runner.rc))
def run_play_add_vlans_edge():
    runner = ansible_runner.run(private_data_dir='',
                                playbook=playsFolderPath + 'addVLAN-edge.yml',
                                inventory=inventoryFolderPath + 'DC2-inventory.ini')
    print("{}: {}".format(runner.status, runner.rc))
def run_play_del_vlans():
    runner = ansible_runner.run(private_data_dir='',
                                playbook=playsFolderPath + 'delVLAN-leaf.yml',
                                inventory=inventoryFolderPath + 'DC2-inventory.ini')
    newfilename = vlan_remove_location_file[:vlan_remove_location_file.find('.yml')] + "-" + today.strftime("%b-%d-%Y") + ".yml"
    print(f"going to move to { newfilename } ")
    stream = os.popen('mv ' + vlan_remove_location_file + ' ' + newfilename)  # move the Service play var file
    print("{}: {}".format(runner.status, runner.rc))
def run_play_update_vrf():
    runner = ansible_runner.run(private_data_dir='',
                                playbook=playsFolderPath + 'fixBGP-vlan-leaf.yml',
                                inventory=inventoryFolderPath + 'DC2-inventory.ini')
    
    print("{}: {}".format(runner.status, runner.rc))
def run_play_update_vrf_edge():
    runner = ansible_runner.run(private_data_dir='',
                                playbook=playsFolderPath + 'fixBGP-vlan-edge.yml',
                                inventory=inventoryFolderPath + 'DC2-inventory.ini')
    print("{}: {}".format(runner.status, runner.rc))
def run_play_add_interface():

    runner = ansible_runner.run(private_data_dir='',
                                playbook= playsFolderPath + 'addInterfacetoFW.yml',
                                inventory= panoInventoryFile_location)

    print("{}: {}".format(runner.status, runner.rc))
def getInterfaceType(interfacename):
    #looks at the name and returns a type ethernet, tunnel, loopback
    if ('loopback' in interfacename):
        return 'loopback'
    elif ('tunnel' in interfacename):
        return 'tunnel'
    elif ('ethernet' in interfacename) or ('ae' in interfacename):
         return 'subinterface'



def deleteFile(secret_file_location):
    #delets a file in the path 
    stream = os.popen('rm -f ' + secret_file_location)


####supposed to create an interface and security zone stuff

def createsubInterfaceonFirewall(username,password, Firewall_Interface_id):
    playvarList = []
    playvardictionary = {}
    print(f'received {username}, *******, { Firewall_Interface_id }')
    #this function is called when we want to build a new interface. Surely the interface exists right?
    myInterface = Firewall_Interface.objects.get(Firewall_Interface_id = Firewall_Interface_id)
    myfirewall = myInterface.Firewall_Interface_virtual_router.virtual_router_firewall
    print(f'My Interface is: {myInterface}')
    print(f"myfirewall is: {myfirewall}")
    playvardictionary['enable_dhcp'] = 'no' #we dont run DHCP ...
    playvardictionary['name'] = myInterface.Firewall_Interface_name
    playvardictionary['vlan'] = myInterface.Firewall_Interface_vlan.vlan_number if myInterface.Firewall_Interface_vlan else ''
    playvardictionary['vr_name'] = myInterface.Firewall_Interface_virtual_router.virtual_router_name
    #forcing PING at minimum
    playvardictionary['management_profile'] = myInterface.Firewall_Interface_management_profile if myInterface.Firewall_Interface_management_profile else 'ping'
    playvardictionary['vsys'] = myfirewall.firewall_vsys
    playvardictionary['zone_name'] = myInterface.Firewall_Interface_security_zone.security_zone_name
    playvardictionary['ip'] = myInterface.Firewall_Interface_value
    playvardictionary['template'] = myfirewall.firewall_template_name.firewall_template_name
    playvardictionary['interface_type'] = getInterfaceType(playvardictionary['name'])
    print(f'this would be our play dictionary: { playvardictionary }')
    playvarList.append(playvardictionary)
#convert the list to yaml and write to file
    #location : interface_result_location_file
    writeYamltoFile('interfaces', yaml.dump(playvarList), interface_result_location_file)
    secret_file_location = writePanoSecretsFile(username,password,mysecretsfile_location)
    time.sleep(5)
    run_play_add_interface()
    time.sleep(5)
    deleteFile(secret_file_location)
    return True

