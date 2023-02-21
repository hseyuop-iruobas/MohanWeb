from DataCenter.models import Vlan, Tenant
import pyeapi
'''

define global variables
'''

def sendAPIRequeststoAristaSwitch(host,username,password):
    '''Establish API connection and return it'''
    device = pyeapi.connect(host=host, username=username,password=password,transport="https")
    #output = device.execute(command)
    return device

def getVlansFromSwitch(device):
    '''Connect to device using EAPI and fire commands to get vlan and apend it to a dictionary'''
    #results = sendAPIRequeststoAristaSwitch(host,username,password)
    command = device.execute('show vlan')
    #print(command,"commoo")
    vlan_dictionary = command.get('result',[{}])[0].get('vlans')
    vlan_list = []
    for key in vlan_dictionary.keys():
        mynew_dict = {}
        mynew_dict['vlan_id'] = key
        mynew_dict['vlan_name'] = vlan_dictionary[key].get('name')
        vlan_list.append(mynew_dict)
    #print(vlan_list,"liii")
    return vlan_list

def getTenantsfromSWitch(connection):
    # takes node (device??)
    #       return list of dictionaries where key: tenant name, value: [list of vlan objects (DataCenter.models.Vlan)]
    # 305-306,1200-1299,2299
    #[{'core_routing': [<DataCenter.models.Vlan(305), <DataCenter.models.Vlan(306), <DataCenter.models.Vlan(1200), <DataCenter.models.Vlan(1201), <DataCenter.models.Vlan(1202), ...<DataCenter.models.Vlan(1299), <DataCenter.models.Vlan(2299)]}, {'banking': [xxxxx,xxxx,xxxx,x]})
    device = pyeapi.client.Node(connection)
    data1 = device.enable(u'show running-config')
    result_list = []
    for key in data1[0].get('result').get('cmds').keys():
        if data1[0].get('result').get('cmds', {}).get(key, {}) != None:
            for item in data1[0].get('result').get('cmds', {}).get(key, {}).get('cmds', {}).keys():
                if 'vlan-aware-bundle' in item:
                    vlan_list_string = ""
                    tenant_name = item
                    tenant_name = item.replace("vlan-aware-bundle ", "")
                    #print(data1[0].get('result').get('cmds', {}).get(key, {}).get('cmds', {}).get(item),"lii")
                    for key2 in list(data1[0].get('result').get('cmds', {}).get(key, {}).get('cmds', {}).get(item, {}).get('cmds', {}).keys()):
                        if 'vlan' in key2:
                     #       print(key2,"kk")
                       #      print(f"{key2} && value : {data1[0].get('result').get('cmds', {}).get(item, {})}")
                            vlan_list_string = key2
                        #    print(vlan_list_string,"after")
                    #After the for loop is done, you need to strip the world vlan from the vlan_list_string. Ideally we should just get
                    #ex 305,306-310,1200-1299
                    #AFter for loop tenant_name please strip everything except the actual name. So 'Banking' , 'core_routing', etc
                            vlan1 = key2.replace("vlan ","")
                            mydictionary = {tenant_name:vlan1}
                            #print(mydictionary,"di")
                            result_list.append(mydictionary)
                    #print(vlan1, "vlan")
    #print(f'returning from dummy1.getTenantsfromSWitch with: {result_list}')
    return result_list

def getTenantandVlans(result_list):
    '''
    we are expecting [[tenant_name:vlan_list_string]]
    we parse the vlan_list_string (use string.split(",")) --> list
    iterate through list and adjust ranges to become indiv items:
    example: 305-310 --> 305, 306, 307, etc...

    iterate through list and get actual vlans by :
    Vlan.objects.get(vlan_name = list[x])


    pull tenant using tenant_name
    Tenants.objects.get(teannt_name = dictionary key)

    returns: [{teantnt_object: [vlan_instances],..]

    '''
    level = result_list
    end_result_list = []
    end_dict = {}
    for val1 in level:
        mykeys = [*val1]
        #print(mykeys,"mmim")
        for s in val1.values():# if the value of the  vlan is in range format the inbetween values are obrained and appended using the range function.else the vlan value is directly appended to vlan_list
            s=s.split(",")
            vlan_list = []
            for each in s:
                if "-" in each:
                    v1 = each.split('-')
                    start = v1[0]
                    if (len(v1)>1):
                        end = v1[1]
                        values = range(int(start),int(end)+1)
                        for v2 in values:
                            vlan_list.append(v2)
                else:
                    vlan_list.append(int(each))
            #print(vlan_list,"last vlan")
            #end_dict[frozenset(val1.keys())] = vlan_list
        end_dict = dict.fromkeys(mykeys,vlan_list)
        end_result_list.append(end_dict)
    return end_result_list

def addTenantInfotoDatabase(tenant_vlan_dictionary_list,vlan_data_center):
    '''[{'Banking': [520, 534, 535, 536, 538, 539, 584, 585, 586, 587, 588, 589, 629, 645, 651, 652, 653, 654, 655, 656, 657, 658, 659, 660, 668, 672, 673, 679, 1300, 1301, 1302, 1303, 1304, 1305, 1306, 1307, 1308]}]
    the output of the previous function which is something like the above example is taken.the tenant name is filtered.If the tenant is not there it is created.vrf rd value is yet t be determined'''
    for items in tenant_vlan_dictionary_list:
        l = list(items.keys())
        print(items,"items")
        print(f'Tenant is: {l}')
        tenants =Tenant.objects.filter(vrf_bgp_bundle_name=l[0])
        if len(tenants) > 0:
            tenants = Tenant.objects.get(vrf_bgp_bundle_name=l[0])
            print(tenants,"tenn")
        else:
            tenants= Tenant()
            tenants.vrf_rd_value == 10
            tenants.vrf_name = l[0]
            #print(tenants.vrf_name,"vrff")
            tenants.vrf_bgp_bundle_name = l[0]
            #print(tenants.vrf_bgp_bundle_name,"bundlee")
            tenants.save()
        print(f'values are: {items.values()}')
        v = list(items.values())[0]

        print(v)
        for vlan in v:
            print(f'looking for vlan {vlan}')
            myvlan = Vlan.objects.filter(vlan_number=vlan).filter(vlan_datacenter=vlan_data_center)
            myvlan = myvlan[0]
            #print(myvlan,"mi")
            tenants.vrf_vlans.add(myvlan)
        tenants.save()

def addVlansToDatabase(list_vlans_dictionary, vlan_data_center):
    '''
    takes a list of vlan dictionaries expected keys:
    [{'vlan_number':1, 'vlan_name':'something'}],

      - vlan_name
      - vlan_number
    checks to see if it's in the database already, if not it adds it

    '''
    for new_vlan in list_vlans_dictionary:
        # query the database for vlan id
        #print(new_vlan,"new")
        myDBVlanQuery = Vlan.objects.filter(vlan_number=new_vlan.get('vlan_id')).filter(vlan_datacenter=vlan_data_center)
        #print(myDBVlanQuery,"QUERY")
        #print(len(myDBVlanQuery),"LEN")
        myDBVlan = None  # set value now
        if len(myDBVlanQuery) > 0:  # if the vlan was in the DB
            myDBVlan = myDBVlanQuery[0]  # assign it to myDBVlan value
            #print(myDBVlan,"mine1")
        if myDBVlan:
            # clearly we hadme data in DB
            # update the DB instance
            myDBVlan.vlan_name = new_vlan.get('vlan_name')
            myDBVlan.vlan_datacenter = vlan_data_center
            myDBVlan.vlan_number = new_vlan.get('vlan_id') #set the number, ID is not the same anymore
            #print(myDBVlan.vlan_name,"1st if")
        else:
            # no instance in DB add one
            myDBVlan = Vlan()
            myDBVlan.vlan_number = new_vlan.get('vlan_id')
            myDBVlan.vlan_name = new_vlan.get('vlan_name')
            #print(myDBVlan.vlan_name,"else")
            myDBVlan.vlan_datacenter = vlan_data_center
        #print(myDBVlan.getDictionary())
        myDBVlan.save()  # save Vlan
        #print(f'saved Vlan: {myDBVlan.vlan_name}')

#
def synchronizeTenantDBFromAristaSwitch(host,username,password):
    hostname = host.switch_name
    device = sendAPIRequeststoAristaSwitch(hostname, username, password)
    result = getTenantandVlans(getTenantsfromSWitch(device))
    print(f'phase1 {result}')
    addTenantInfotoDatabase(result, host.switch_datacenter)

def synchronizeVLanDBFromAristaSwitch(host, username, password):
    #get a device
    hostname = host.switch_name
    device = sendAPIRequeststoAristaSwitch(hostname, username, password)
    vlan_list = getVlansFromSwitch(device)
    addVlansToDatabase(vlan_list, host.switch_datacenter)