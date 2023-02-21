from celery import shared_task
from FirewallRules.models import IKE_VPN
from FirewallRules.tools import writeYamltoFile,writePanoSecretsFile
from FirewallRules.vars import FirewallFolder,vpn_ike_result_file, mysecretsfile_location
import yaml
import os
import ansible_runner


def buildVPNdictionary(vpn_id):
    myIKEVPN = IKE_VPN.objects.get(id=vpn_id)

    vpnsettings = {}  # placeholder to dump to yaml
    # Tunnel interface information:
    tunnel_interface = myIKEVPN.tunnel_interface
    tunnel_front_door = myIKEVPN.tunnel_front_door
    tunnel_virtual_router = tunnel_interface.Firewall_Interface_virtual_router
    tunnel_firewall = tunnel_virtual_router.virtual_router_firewall
    vpnsettings['tunnel_number'] = tunnel_interface.Firewall_Interface_name  # copy tunnel number
    vpnsettings['tunnel_address'] = tunnel_interface.Firewall_Interface_value  # copy tunnel number
    vpnsettings['zone_name'] = tunnel_interface.Firewall_Interface_security_zone.security_zone_name  # get tunnels' security zone name
    vpnsettings['tunnel_virtual_router'] = tunnel_interface.Firewall_Interface_virtual_router.virtual_router_name  # get the VR for the tunnel
    vpnsettings['targettemplate'] = tunnel_firewall.firewall_template_name.firewall_template_name  # get target template
    vpnsettings['management_profile'] = tunnel_interface.Firewall_Interface_management_profile  # copy tunnel number
    # frontdoor interface information

    vpnsettings['front_door_interface'] = tunnel_front_door.Firewall_Interface_name  # copy tunnel number
    vpnsettings['front_door_interface_value'] = tunnel_front_door.Firewall_Interface_value[:tunnel_front_door.Firewall_Interface_value.find("/")]  # copy tunnel number
    # IKE_Gateway info
    vpnsettings['peer_outside_address'] = myIKEVPN.peer_outside_address  # copy set outside interface IP
    vpnsettings['crypto_profile'] = myIKEVPN.crypto_profile  # copy set outside interface IP
    vpnsettings['ike_gateway_name'] = myIKEVPN.ike_gateway_name  # copy set outside interface IP
    # IPSEC_info
    vpnsettings['ipsec_profile'] = myIKEVPN.ipsec_profile  # copy set outside interface IP
    return vpnsettings

def runansibleplays():
    runner = ansible_runner.run(private_data_dir='',
                                playbook=FirewallFolder + 'ansible-plays/buildIKEVPN.yml',
                                inventory=FirewallFolder + 'ansible-plays/inventory/PALO-inventory.ini')
    print("{}: {}".format(runner.status, runner.rc))
    pass


@shared_task
def buildikeVPN(vpn_id_list, pano_username, pano_password, pre_shared_key):
    mylist = []
    for vpn_id in vpn_id_list:
        vpnsettings = buildVPNdictionary(vpn_id)
        mylist.append(vpnsettings)

    myresultfilelocation = writeYamltoFile('vpnsettings', yaml.dump(mylist), FirewallFolder + vpn_ike_result_file)
    print(f'wrong to {myresultfilelocation} going to run plays')
    writePanoSecretsFile(pano_username, pano_password, FirewallFolder + mysecretsfile_location)
    runansibleplays()

    stream = os.popen('rm ' + FirewallFolder + mysecretsfile_location)  # nuke the file
    print(f'I built yer VPN - with VPN ID {vpn_id} and stuff')