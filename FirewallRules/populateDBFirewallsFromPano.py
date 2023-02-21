from FirewallRules.models import (Firewall,
                                  VirtualRouter,
                                  secZone,
                                  Object,
                                  Duplicates, FirewallRules,
                                  RuleInstance)
from FirewallRules.models import Firewall_Interface, Location, Service, tag
from FirewallRules.tools import findObjectLocation
import socket
import requests
from django.db.models import Q

import json
from django.db import transaction
from FirewallRules.vars import panorama_server
from DataCenter.models import Vlan


def getPreRuleFirewallRulesPerDeviceGroupFromPanorama(apikey, device_group_name,rule_location):
    '''
        takes apikey, template name and vsysname
        makes a query to panoarama server and returns the result as json object
    '''
    if rule_location == 'pre-rulebase':
        rule_base = 'SecurityPreRules'
    else:
        rule_base = 'SecurityPostRules'
    print(f'getPreRuleFirewallRulesPerDeviceGroupFromPanorama')
    print(f'making a call to {rule_location} / {rule_base} to obtain rules')
    url = f"https://{panorama_server}/restapi/v10.0/Policies/{rule_base}?location=device-group&device-group={device_group_name}"
    headers = {
        'X-PAN-KEY': apikey,
    }
    response = requests.request("get", url, headers=headers, verify=False)

    answer = json.loads(response.text)
    return answer

def getsecurityzonefromName(zone_name,myfirewall):

    return secZone.objects.get(security_zone_name = zone_name,security_zone_firewall=myfirewall)


def getOrMakeTag(mytag):
    tagQuery = tag.objects.filter(tag_name = mytag)
    if len(tagQuery) > 0:
        return tagQuery[0]
    else:
        myDBtag = tag()
        myDBtag.tag_name = mytag
        myDBtag.save()
        return myDBtag

def recievePanoObjectNameGetDBObjectValue(object_name):
    #print(f'received {object_name} going to try and find it now in the DBs')
    #try our real DB!
    db_object_value_query = Object.objects.filter(object_name = object_name)
    if len(db_object_value_query)>0:
        return db_object_value_query[0].object_id
    else:
        #try the duplicates table?
        db_object_value_query = Duplicates.objects.filter(object_name = object_name)
        if len(db_object_value_query)>0:
            return db_object_value_query[0].current_db_value.object_id #return the real object in DB
        else:
            print(f"****WTHeck I can't find {object_name}")
            print(f"going to check the name against value")
            db_object_value_query = Object.objects.filter(object_value = object_name)
            if len(db_object_value_query) > 0:
                return db_object_value_query[0].object_id
            else:
                return None

def recievePanoServiceNameGetDBServiceValue(service_name):
    #assumes we have all services boarded otherwise get an excetion error RIGHT here
    #or i just changed my mind and saved the fake service with just a name .. and you figure it out later?
    print(f'I received the following service: {service_name}')
    db_service_query = Service.objects.filter(service_name = service_name)
    if len(db_service_query)> 0 :
        return db_service_query[0].service_id
    else:
        print(f"***WTHeck I can't find {service_name}")
        print(f'Going to fakone:')
        myService = Service(service_name = service_name)
        myService.save()
        return myService.service_id

def getURLCatDataFromPanoRama(myPanoRestAPIInstance, urls_name):
    '''
            takes apikey, template name and vsysname
            makes a query to panoarama server and returns the result as json object
    '''
    #our api keys expire after 5 min. so get a new one if you have to get URLS
    apikey = myPanoRestAPIInstance.getapikey(myPanoRestAPIInstance.ip,
                                             myPanoRestAPIInstance.username,
                                             myPanoRestAPIInstance.password)
    url = f"https://{panorama_server}/restapi/v10.0/Objects/CustomURLCategories?location=shared&name={urls_name}"
    headers = {
        'X-PAN-KEY': apikey,
    }
    response = requests.request("get", url, headers=headers, verify=False)
    answer = json.loads(response.text)
    if answer.get('@status') == 'success':
        returned_data = answer.get('result',{}).get('entry',[{}])[0].get('list',{}).get('member',[])
        print(f'sending back : {returned_data}')
        return returned_data
    else:
        print(f"Could not Find: {urls_name}")
        print(f"answer was: {answer}")
        if answer.get('code',0) == 5:
            #object not found it seems from panorama
            return [f'{answer.get("message")}']
        return None


def processurls(myPanoRestAPIInstance, urls):
    '''
        panorama sends the url cat back as either ['any']
        or a list of possible cats used.
        we will have to write a different function to get them in armat we CARE about
        so for now we will store the pure value which is the NAMES of the URL cat
        or an empty string to represent nothing
    '''
    print(f'entering processurls:')
    if urls == ['any']:
        return '' #send an empty string
    else:
        print(f'obtaining the following urls : {urls} from Panorama now...')
        mydata = ""
        for url in urls:
            mydata += ",".join(getURLCatDataFromPanoRama(myPanoRestAPIInstance, url))
        return mydata




def create_or_find_ruleinstance_to_attach_firewall_Rule(rule_name, source_values, destination_values,
                                                        service_values, source_user,rule_duration, urls,
                                                        application, catagory_name,rule_location,profile_group_name):

    '''
        in theory this takesa  source, dest and service value obtained from panorama!
        finds the matching rules for it hopefully
        or makes one if there is none
    '''
    #build a true source, destination list. remember we have duplicates to deal with
    real_source_values_db = [recievePanoObjectNameGetDBObjectValue(x) for x in source_values]
    real_destination_values_db = [recievePanoObjectNameGetDBObjectValue(x) for x in destination_values]
    real_service_values_db = [recievePanoServiceNameGetDBServiceValue(x) for x in service_values]
    myRuleInstanceQ = RuleInstance.objects.filter(source__object_id__in=real_source_values_db,
                                                  dest__object_id__in=real_destination_values_db,
                                                  service__service_id__in=real_service_values_db).distinct()
    print(f'Query after first filter:\r\n {myRuleInstanceQ}')
    myquery = Q()
    myquery &= Q(source_user = source_user, rule_duration = rule_duration)
    #change application to string:
    #add it to the Q query
    print(f'Query after source_user/schedule user filter:\r\n {myRuleInstanceQ}')
    myquery = Q()
    myquery &= Q(application__iexact= application)
    print(f'Query after application user filter:\r\n {myRuleInstanceQ}')
    myquery = Q()
    myquery &= Q(urls__iexact=urls)

    print(f'Query after urls user filter:\r\n {myRuleInstanceQ}')
    myRuleInstanceQ = myRuleInstanceQ.filter(myquery).distinct()

    if len(myRuleInstanceQ) > 0:
        print(f'****found {len(myRuleInstanceQ)} for rules matching FW {rule_name}')
        print(f'returning only one of the {myRuleInstanceQ}')
        return myRuleInstanceQ[0]
    else:
        print(f'****did not find any rules matching FW {rule_name} Going to make one')
        myruleInstance = RuleInstance()
        rule_id = rule_name.replace(" ", "-") #so we have rule names with spaces WTF
        myruleInstance.id = rule_id #working on increasing ID size to 100 so i dont have to clip
        myruleInstance.rule_name = rule_name
        myruleInstance.rule_description= rule_name
        myruleInstance.source_user = source_user
        myruleInstance.created_by = 'System Export Function'
        myruleInstance.rule_duration = 15 if rule_duration else 0
        myruleInstance.urls = urls #needs to get fixed
        myruleInstance.catagory_name = catagory_name
        myruleInstance.application = application
        myruleInstance.location = rule_location
        myruleInstance.location = profile_group_name
        myruleInstance.save()
        for source in real_source_values_db:
            myruleInstance.source.add(source)
        for destination in real_destination_values_db:
            myruleInstance.dest.add(destination)
        for service in real_service_values_db:
            myruleInstance.service.add(service)
        myruleInstance.save()
        return myruleInstance

def processRulesFromPano(myPanoRestAPIInstance,
                         firewall_name,
                         myfirewall,
                         rule_dictionary_list,
                         rule_location):
    '''
        does the heavy lifting of the actual rule process.
        it takes a list of dictionaries received from panorama / api request
        goes through it one by one.
        it creates a new firewall rule for it, adds the security zones, log settings, etc
        it then takes the source/dest/services/users/urls, etc (all the things a Rule Instance needs to know)
        and send its over to create_or_find_ruleinstance_to_attach_firewall_rule
        once it receives in theory either a new RuleInstance or an existing one it will attach it to the FirewallRule
        as a foreignkey to keep track of it all.
    '''
    errored_out_rules = []
    for rule in rule_dictionary_list:
        if rule.get('disabled', 'no') != 'yes':
            with transaction.atomic():
                try:
                    #check to see if FW Rule needs to be built maybe already imported!
                    if FirewallRules.objects.filter(name_on_the_firewall=rule.get('@name'), devicegroup = myfirewall).count() < 1 :
                        newRule = FirewallRules()
                        newRule.name_on_the_firewall = rule.get('@name')
                        newRule.save()  # get an ID so we can set FK relations
                        destination_zone_list = rule.get('to', {}).get('member', [])
                        print(f'processing destination zones: {destination_zone_list}')
                        for zone in destination_zone_list:
                            newRule.destination_zone.add(getsecurityzonefromName(zone, myfirewall))
                        source_zone_list = rule.get('from', {}).get('member', [])
                        print(f'processing source zone: {source_zone_list}')
                        for zone in source_zone_list:
                            newRule.source_zone.add(getsecurityzonefromName(zone, myfirewall))
                        newRule.save()
                        print(f"log_setting: {rule.get('log-setting')}")
                        newRule.log_setting = rule.get('log-setting')
                        profile_group_name_list = rule.get('profile-setting', {}).get('group', {}).get('member', [])
                        print(f"profile_group_name: {rule.get('profile-setting', {}).get('group', {})}")
                        newRule.profile_group_name = profile_group_name_list[0] if len(
                            profile_group_name_list) > 0 else 'None'
                        tag_list = rule.get('tag', {}).get('member', [])
                        for mytag in tag_list:
                            # makes or gets a tag object and returns that so we can add it here
                            newRule.tags.add(getOrMakeTag(mytag))
                        newRule.save()
                        newRule.log_at_session_end = '1' if rule.get('log-end') == 'yes' else '0'
                        newRule.log_at_session_start = '1' if rule.get('log-start') == 'yes' else '0'
                        newRule.action = rule.get('action')
                        newRule.devicegroup = myfirewall  # set the device group
                        newRule.save()
                        source_address_list = rule.get('source', {}).get('member', [])
                        destination_address_list = rule.get('destination', {}).get('member', [])
                        service_list = rule.get('service', {}).get('member')
                        source_user = ",".join(rule.get('source-user', {}).get('member', []))
                        rule_duration = rule.get('schedule', 0)
                        urls = processurls(myPanoRestAPIInstance,
                                           rule.get('category', {}).get('member'))  # getting all or nothing
                        catagory_name = rule.get('category', {}).get('member', [''])[0]
                        print(f'catagory name: {catagory_name} for rule {newRule.name_on_the_firewall}')
                        application = ",".join(rule.get('application', {}).get('member', []))
                        profile_group_name = newRule.profile_group_name #storing in RuleInstance for reasons!
                        # FIGURE OUT how to do this .. we need a Rule Instance here now to relate this to
                        myRule_Instance = create_or_find_ruleinstance_to_attach_firewall_Rule(
                            rule_name=newRule.name_on_the_firewall,
                            source_values=source_address_list,
                            destination_values=destination_address_list,
                            service_values=service_list,
                            source_user=source_user,
                            rule_duration=rule_duration,
                            urls=urls,
                            application=application,
                            catagory_name=catagory_name,
                            rule_location = rule_location,
                            profile_group_name = profile_group_name)
                        newRule.rule_instance = myRule_Instance
                        newRule.isShared = False
                        newRule.pushed_to_firewall = True
                        newRule.save()
                        print(f"saved rule {rule.get('@name')} from {firewall_name}")
                    else:
                        print(f"we already have this rule {rule.get('@name')} from {firewall_name}")

                except Exception as e:
                    print('^' * 17)
                    print(f'\r\nencrounted exception: {e}')
                    print('^' * 17)
                    errored_out_rules.append(rule)

    print("$" * 18)
    print("following rules errored out for some reason or another")
    f = open(f'badrules-{firewall_name}.txt', 'w')
    for rule in errored_out_rules:
        print(rule)
        print('$' * 7)
        f.write(str(rule))
        f.write('$' * 7 + '\r\n')
    f.close()


def getRulesAndSaveToDatabaseperDeviceGroupFromPanorama(myPanoRestAPIInstance, firewall_name,rule_location):
    '''
        takes an api instance and a firewall name
        queries panorama for the device group firewall rules in prerules database
        sends it over to the processRulesFromPano to get processed.
    '''
    apikey = myPanoRestAPIInstance.getapikey(myPanoRestAPIInstance.ip,
                                             myPanoRestAPIInstance.username,
                                             myPanoRestAPIInstance.password)
    myfirewall = Firewall.objects.get(firewall_Name = firewall_name)
    device_group_name = myfirewall.firewall_device_group_name.device_group_name
    myjson_response = getPreRuleFirewallRulesPerDeviceGroupFromPanorama(apikey, device_group_name,rule_location)
    total_rule_count = myjson_response.get('result',{}).get('@count')
    rule_dictionary_list = myjson_response.get('result', {}).get('entry',[]) #need a list
    print(f'Processing total {total_rule_count} from {device_group_name}')
    processRulesFromPano(myPanoRestAPIInstance=myPanoRestAPIInstance,
                         firewall_name=firewall_name,
                         myfirewall=myfirewall,
                         rule_dictionary_list=rule_dictionary_list,
                         rule_location=rule_location)








def getVirtualRoutersFromPano(apikey, template_name, vsys_name):
    '''
    takes apikey, template name and vsysname
    makes a query to panoarama server and returns the result
    '''
    url = f"https://{panorama_server}/restapi/v10.0/Network/VirtualRouters?location=template&template={template_name}&vsys={vsys_name}"
    headers = {
        'X-PAN-KEY': apikey,
    }
    response = requests.request("get", url, headers=headers, verify=False)

    answer = json.loads(response.text)
    return answer


def getSecurityZonesFromPano(apikey, template_name, vsys_name):
    '''
    takes apikey, template name and vsysname
    makes a query to panoarama server and returns the result
    '''
    url = f"https://{panorama_server}/restapi/v10.0/Network/Zones?location=template&template={template_name}&vsys={vsys_name}"
    headers = {
        'X-PAN-KEY': apikey,
    }
    response = requests.request("get", url, headers=headers, verify=False)

    answer = json.loads(response.text)
    return answer

def getEthernetInterfacesFromPano(apikey, template_name, vsys_name):
    '''
    takes apikey, template name and vsysname
    makes a query to panoarama server and returns the result
    '''
    url = f"https://{panorama_server}/restapi/v10.0/Network/EthernetInterfaces?location=template&template={template_name}"
    headers = {
        'X-PAN-KEY': apikey,
    }
    response = requests.request("get", url, headers=headers, verify=False)

    answer = json.loads(response.text)
    return answer


def getAggregateInterfacesFromPano(apikey, template_name, vsys_name):
    '''
    takes apikey, template name and vsysname
    makes a query to panoarama server and returns the result
    '''
    url = f"https://{panorama_server}/restapi/v10.0/Network/AggregateEthernetInterfaces?location=template&template={template_name}"
    headers = {
        'X-PAN-KEY': apikey,
    }
    response = requests.request("get", url, headers=headers, verify=False)

    answer = json.loads(response.text)
    return answer



def getTunnelInterfacesFromPano(apikey, template_name, vsys_name):
    '''
    takes apikey, template name and vsysname
    makes a query to panoarama server and returns the result
    '''
    url = f"https://{panorama_server}/restapi/v10.0/Network/TunnelInterfaces?location=template&template={template_name}"
    headers = {
        'X-PAN-KEY': apikey,
    }
    response = requests.request("get", url, headers=headers, verify=False)

    answer = json.loads(response.text)
    return answer



def getallobjectswithtagNonShared(apikey, ip,device_group_name):



    url = 'https://{ip}/restapi/v10.0/Objects/Addresses?location=device-group&device-group={device_group_name}'.format(ip = ip,
                                                                                                                       device_group_name = device_group_name)

    payload = {}
    headers = {
    'X-PAN-KEY': apikey,
    }

    response = requests.request("GET", url, headers=headers, data=payload, verify=False)

    addressobjectsdictionary = json.loads(response.text)
    return addressobjectsdictionary

def getallobjectGroupswithtagNonShared(apikey, ip,device_group_name):
    matchlist = []
    url = 'https://{ip}/restapi/v10.0/Objects/AddressGroups?location=device-group&device-group={device_group_name}'.format(ip = ip,
                                                                                                                       device_group_name = device_group_name)
    payload = {}
    headers = {
    'X-PAN-KEY': apikey,
    }
    response = requests.request("GET", url, headers=headers, data=payload, verify=False)
    addressobjectsdictionary = json.loads(response.text)
    return addressobjectsdictionary




def getallobjectswithtag(apikey, ip):



    url = 'https://{ip}/restapi/v10.0/Objects/Addresses?location=shared'.format(ip = ip)

    payload = {}
    headers = {
    'X-PAN-KEY': apikey,
    }

    response = requests.request("GET", url, headers=headers, data=payload, verify=False)

    addressobjectsdictionary = json.loads(response.text)
    return addressobjectsdictionary


def getSingleobjectswithtag(apikey, ip,object_name):



    url = 'https://{ip}/restapi/v10.0/Objects/Addresses?location=shared&name={object_name}'.format(ip = ip,
                                                                                                   object_name=object_name)

    payload = {}
    headers = {
    'X-PAN-KEY': apikey,
    }

    response = requests.request("GET", url, headers=headers, data=payload, verify=False)

    addressobjectsdictionary = json.loads(response.text)
    return addressobjectsdictionary



def getallservices(apikey, ip):



    url = 'https://{ip}/restapi/v10.0/Objects/Services?location=shared'.format(ip = ip)

    payload = {}
    headers = {
    'X-PAN-KEY': apikey,
    }

    response = requests.request("GET", url, headers=headers, data=payload, verify=False)

    addressobjectsdictionary = json.loads(response.text)
    return addressobjectsdictionary


def getallobjectGroupswithtag(apikey, ip):

    matchlist = []

    url = 'https://{ip}/restapi/v10.0/Objects/AddressGroups?location=shared'.format(ip = ip)

    payload = {}
    headers = {
    'X-PAN-KEY': apikey,
    }

    response = requests.request("GET", url, headers=headers, data=payload, verify=False)

    addressobjectsdictionary = json.loads(response.text)
    return addressobjectsdictionary

def getSingleobjectGroupswithtag(apikey, ip,object_name):

    matchlist = []

    url = 'https://{ip}/restapi/v10.0/Objects/AddressGroups?location=shared&name={object_name}'.format(ip = ip,
                                                                                                       object_name=object_name)

    payload = {}
    headers = {
    'X-PAN-KEY': apikey,
    }

    response = requests.request("GET", url, headers=headers, data=payload, verify=False)

    addressobjectsdictionary = json.loads(response.text)
    return addressobjectsdictionary


def getVirtualRouter(myVRName, firewall):
    vrQuery = VirtualRouter.objects.filter(virtual_router_firewall = firewall)
    for vr in vrQuery:
        if vr.virtual_router_name == myVRName:
             return vr
    return None

@transaction.atomic
def consolidatetags():
    #get a list of all objects
    object_list = Object.objects.all()
    for myobject in object_list:
        #get a queryset of duplicates that have this object as their thing
        duplicate_list = Duplicates.objects.filter(current_db_value = myobject)
        current_tag = myobject.object_tag #get current tag list we dont want to miss that ..
        tag_list = []
        if current_tag:
            tag_list = current_tag.split(",")
        if len(duplicate_list)>0 : #we have some stuff here?
            for myduplicate in duplicate_list:
                if myduplicate.object_tag:
                    for tag in myduplicate.object_tag.split(","):
                       tag_list.append(tag)
        #remove dups by making a dictionary and then making it a list again

        tag_list_dup_removed = []
        if len(tag_list)>0:
           tag_list_dup_removed = list(dict.fromkeys(tag_list))
        #join the list
        print(f'foundtags for {myobject} that are {tag_list_dup_removed}')
        myobject.object_tag = ",".join(tag_list_dup_removed)
        myobject.save()

@transaction.atomic
def consolidatetagsDB():
    tag_dictionary = {}
    for object in Object.objects.all() :
        if object.object_tag:
            tag_list = object.object_tag.split(",")
            for mytag in tag_list :
                if (mytag): #do we have a tag?
                    print(f'{mytag}')
                    if mytag not in tag_dictionary.keys(): #we already have the tag loaded
                        tagquery = tag.objects.filter(tag_name=mytag)
                        if len(tagquery)<1:
                            newtag = tag()
                            newtag.tag_name = mytag
                            newtag.save()
                        tagquery = tag.objects.filter(tag_name=mytag)
                        tag_dictionary[mytag] = tagquery[0]
                        print(f'tag is {tag_dictionary}')
                    object.tags.add(tag_dictionary.get(mytag))  # add the tag to object
                    print(f'added {mytag} to {object}')


@transaction.atomic
def synchronizeDBServices(service_json_data):
    services_list = service_json_data.get('result',{}).get('entry')
    for service in services_list:
        print(f'working with: s{service}')
        myService_queryset = Service.objects.filter(service_name = service.get('@name'))
        if len(myService_queryset)>0:
            myservice = myService_queryset[0]
            #update the service
            if service.get('protocol',{}).get('udp'):
                myservice.service_protocol = 'UDP'
                myservice.service_dest_port = service.get('protocol',{}).get('udp',{}).get('port')
            else:
                myservice.service_protocol = 'TCP'
                myservice.service_dest_port = service.get('protocol', {}).get('tcp', {}).get('port')
            myservice.save()
        else:
            myservice = Service()
            myservice.service_name = service.get('@name')
            if service.get('protocol',{}).get('udp'):
                myservice.service_protocol = 'UDP'
                myservice.service_dest_port = service.get('protocol',{}).get('udp',{}).get('port')
            else:
                myservice.service_protocol = 'TCP'
                myservice.service_dest_port = service.get('protocol', {}).get('tcp', {}).get('port')
            myservice.save()



def synchronizeDBObjectGroup(object_json_data):
    my_object_dictionary = object_json_data.get('result', {}).get('entry',
                                                                  [])  # getme the entry dictionary stuff or return empty LIST
    nextID = Object.objects.latest('object_id').object_id

    list_of_objects_not_in_mohan = []
    my_object_dictionary.reverse()
    if len(my_object_dictionary) > 0:
        with transaction.atomic():
            for pano_object in my_object_dictionary:
                # if this works i either get the ip-netmask if it exists or the 'fqdn' value or None
                object_group_name = pano_object.get('@name') #get the name
                group_member_list = pano_object.get('static', {}).get('member') #get the member list
                if group_member_list:
                    # we have a static object group - no fancy DAGs
                    my_object_group = None  # declare so it lives outside of try/except
                    try:
                        my_object_group = Object.objects.get(object_name = object_group_name)
                        my_object_group.object_group_members.clear()
                        my_object_group.save()
                        my_object_group.object_description = pano_object.get('description') #set description if any
                    except Object.DoesNotExist:
                        object_value = hash(",".join(group_member_list))#some hash here would be cool (?) and maybe give us unique?
                        #look up for duplicates in table
                        if len(Object.objects.filter(object_value = object_value))>0:
                            nextID = nextID + 1
                            object_value = object_value + (nextID)

                        my_object_group = Object(object_name = object_group_name, object_type = 'address-group',
                                                 object_value =object_value, object_description = pano_object.get('description'))

                    my_object_group.save()
                    from FirewallRules.models import AddressGroup
                    myaddressgroup_query = AddressGroup.objects.filter(Object_in_DB = my_object_group)
                    myaddressgroup = None
                    if len(myaddressgroup_query) < 1 :
                        myaddressgroup = AddressGroup()
                        myaddressgroup.save()
                        myaddressgroup.Object_in_DB = my_object_group
                        myaddressgroup.save()
                    else:
                        myaddressgroup = myaddressgroup_query[0]
                    for member in group_member_list:
                        myobjectquery = Object.objects.filter(object_name=member)
                        myobject = None
                        if len(myobjectquery) > 0:
                            myobject = myobjectquery[0]
                        else:
                            mydupobjectquery = Duplicates.objects.filter(object_name=member)
                            if len(mydupobjectquery)>0:
                                myobject = mydupobjectquery[0].current_db_value
                            else:
                                list_of_objects_not_in_mohan.append(pano_object)
                        if myobject:
                            print(f'adding {myobject} to {my_object_group} and I might have replaced org {member}')
                            myaddressgroup.object_group_members.add(myobject)
                    myaddressgroup.save()
                    my_object_group.save()
                else:
                    list_of_objects_not_in_mohan.append(pano_object)
    return list_of_objects_not_in_mohan



#function below synchronizes OBJECTS
@transaction.atomic
def synchronizeDB(object_json_data):
    '''
    synch's objects from panorama 
    '''
    my_object_dictionary = object_json_data.get('result',{}).get('entry', []) #getme the entry dictionary stuff or return empty LIST
    list_of_objects_not_in_mohan = [] #storing for later
    location_dictionary_parent = Location.objects.filter(location_type='Parent') #get parent locations
    location_dictionary_child = Location.objects.filter(location_type='Child') #get child locations
    if len(my_object_dictionary)>0:
        for pano_object in my_object_dictionary:
            #if this works i either get the ip-netmask if it exists or the 'fqdn' value or None
            object_value = pano_object.get('ip-netmask', pano_object.get('fqdn'))
            if pano_object.get('ip-netmask') and ("/" not in pano_object.get('ip-netmask')):
                #enforcing subnetmask for obviously HOST objects. hopefully we now catch the duplicates that have no mask vs mask
                #ex. 1.1.1.1 and 1.1.1.1/32 ..
                object_value = object_value +"/32"
            if (object_value):
                django_object_queryset = Object.objects.filter(object_value=object_value)
                #if we have a result
                if len(django_object_queryset) > 0:
                    #we have a result check the names
                    django_object = django_object_queryset[0] #take our result
                    print(f'%%%%comparing {django_object} to {pano_object}')
                    if django_object.object_name.lower() == pano_object.get('@name').lower():
                        #we have a match lets update tags?
                        print(f"setting tag on {django_object} to {pano_object.get('tag',{}).get('member',[])}")
                        django_object.object_tag = ",".join(pano_object.get('tag',{}).get('member',[])) #i love python
                        django_object.save()
                    else:
                        print(f'going to update a duplicate hopefully {pano_object}')
                        #we have a value match but not a name match so we are dealing with dups
                        try:
                           django_duplicate = Duplicates.objects.get(object_name =pano_object.get('@name'))
                           django_duplicate.current_db_value = django_object
                           django_duplicate.object_tag = ",".join(pano_object.get('tag',{}).get('member',[]))
                           django_duplicate.save()
                        except Duplicates.DoesNotExist:
                           mynewdup = Duplicates(object_name = pano_object.get('@name'),
                                                 current_db_value = django_object,
                                                 object_value = pano_object.get('ip-netmask', pano_object.get('fqdn')),
                                                 object_tag =",".join(pano_object.get('tag',{}).get('member',[])))
                           mynewdup.save()
                else:
                    #we dont have this object in mohan WTF?
                    print(f'didnt find the following : {pano_object}')
                    newObject = Object()
                    newObject.object_name = pano_object.get('@name')
                    newObject.object_description = pano_object.get('@name')
                    #set type and value below
                    if pano_object.get('ip-netmask'):
                        newObject.object_type = 'ip-netmask'
                        response = findObjectLocation(object_value, location_dictionary_parent, location_dictionary_child)
                        if response.get('interface_id'):
                            newObject.object_firewall_interface = \
                                Firewall_Interface.objects.get(Firewall_Interface_id= response.get('interface_id'))
                            print(f"Setting interface: {Firewall_Interface.objects.get(Firewall_Interface_id= response.get('interface_id'))}")
                        newObject.object_location = response.get('location')
                        newObject.object_tag = ",".join(pano_object.get('tag', {}).get('member', []))  # i love python
                        newObject.object_value = object_value
                        newObject.save()
                    else:
                        newObject.object_type = 'fqdn'
                        try:
                            response = findObjectLocation(socket.gethostbyname(object_value), location_dictionary_parent,
                                                      location_dictionary_child)
                            if response.get('interface_id'):
                                newObject.object_firewall_interface = \
                                    Firewall_Interface.objects.get(Firewall_Interface_id=response.get('interface_id'))
                                print(
                                    f"FQDN - Setting interface: {Firewall_Interface.objects.get(Firewall_Interface_id=response.get('interface_id'))}")
                            newObject.object_location = response.get('location')
                            newObject.object_tag = ",".join(
                                pano_object.get('tag', {}).get('member', []))  # i love python
                            newObject.object_value = object_value
                            newObject.save()
                        except socket.gaierror:
                            print(f'Unable to resolve {object_value} skipping invalid FQDN')
                            #leave the loop before save
                            #setting it by doing nothing that is!
                            list_of_objects_not_in_mohan.append(pano_object)  # i promise to something with this ?
    print("****** found following objects I didn't know what todo with*****")
    print(list_of_objects_not_in_mohan)
    return list_of_objects_not_in_mohan


@transaction.atomic
def getMyVlan(vlan_number, vlan_datacenter):

    myVL = Vlan.objects.filter(Q(vlan_number=vlan_number) & Q(vlan_datacenter=vlan_datacenter))
    if len(myVL)>0 :
        return myVL[0]
    else:
        myVL = Vlan(vlan_number = vlan_number, vlan_datacenter=vlan_datacenter, vlan_name=f'VL-{vlan_number}')
        myVL.save()
        return myVL

@transaction.atomic
def addSecurityZones(apikey, myFirewall_list):
    #myFirewall_list = Firewall.objects.all()
    for firewall in myFirewall_list:
        final_interface_dictionary = {} # key: interface name (unique per FW!) , value: dictionary (VR, value, security zone, description, tag)
        print(f'doing firewall: {firewall}')
        security_zone_list = getSecurityZonesFromPano(apikey, firewall.firewall_template_name.getName(),
                                                      firewall.firewall_vsys)
        ethernet_Interface_List = getEthernetInterfacesFromPano(apikey, firewall.firewall_template_name.getName(),
                                                      firewall.firewall_vsys)
        aggregate_Interface_List = getAggregateInterfacesFromPano(apikey, firewall.firewall_template_name.getName(),
                                                                firewall.firewall_vsys)
        Tunnel_Interface_List = getTunnelInterfacesFromPano(apikey, firewall.firewall_template_name.getName(),
                                                                  firewall.firewall_vsys)
        virtual_router_list = getVirtualRoutersFromPano(apikey, firewall.firewall_template_name.getName(),
                                                        firewall.firewall_vsys)
        #first letbuilda n interface list
        for interface in ethernet_Interface_List.get("result",{}).get('entry',[]):
            if interface.get('layer3') or interface.get('ip'):
                final_interface_dictionary[interface.get('@name')] = {}
                final_interface_dictionary[interface.get('@name')]['Firewall_Interface_name'] = interface.get('@name')
                #below we try tet the ip address in the final value, however if none exists we can take 0 as STRING!

                if interface.get('layer3'):
                    final_interface_dictionary[interface.get('@name')]['Firewall_Interface_value'] = \
                        interface.get('layer3',{}).get("ip",{}).get("entry",[{"@name":'0'}])[0].get("@name")
                elif interface.get("ip"):
                    final_interface_dictionary[interface.get('@name')]['Firewall_Interface_value'] = \
                        interface.get("ip", {}).get("entry", [{"@name": '0'}])[0].get("@name")
                else:
                    final_interface_dictionary[interface.get('@name')]['Firewall_Interface_value'] = 0


                final_interface_dictionary[interface.get('@name')]['Firewall_Interface_management_profile'] = \
                    interface.get('layer3', {}).get("interface-management-profile","ping")

                if ("." in interface.get('@name')):
                    vlan_number = int(interface.get('@name')[interface.get('@name').find(".") + 1:])
                    print(f'found Vlan Number: {vlan_number}')
                    myvlan = getMyVlan(vlan_number, firewall.firewall_datacenter)
                    final_interface_dictionary[interface.get('@name')]['Firewall_Interface_vlan'] = myvlan.id

        #build aggregate interfaces list
        for aggregate in aggregate_Interface_List.get("result", {}).get('entry', []):
            for interface in aggregate.get("layer3",{}).get("units",{}).get("entry",[]):
                final_interface_dictionary[interface.get('@name')] = {}
                final_interface_dictionary[interface.get('@name')]['Firewall_Interface_name'] = interface.get('@name')
                # below we try tet the ip address in the final value, however if none exists we can take 0 as STRING!
                final_interface_dictionary[interface.get('@name')]['Firewall_Interface_value'] = \
                    interface.get("ip", {}).get("entry", [{"@name": '0'}])[0].get("@name")
                final_interface_dictionary[interface.get('@name')]['Firewall_Interface_management_profile'] = \
                    interface.get("interface-management-profile", "ping")
                vlan_number = int(interface.get('@name')[interface.get('@name').find(".")+1:])
                print(f'found Vlan Number: {vlan_number}')
                myvlan = getMyVlan(vlan_number, firewall.firewall_datacenter)
                final_interface_dictionary[interface.get('@name')]['Firewall_Interface_vlan'] = myvlan.id

        #build tunnel interfce list
        for interface in Tunnel_Interface_List.get("result",{}).get('entry',[]):
            if interface.get('@name'):
                final_interface_dictionary[interface.get('@name')] = {}
                final_interface_dictionary[interface.get('@name')]['Firewall_Interface_name'] = interface.get('@name')
                #below we try tet the ip address in the final value, however if none exists we can take 0 as STRING!
                final_interface_dictionary[interface.get('@name')]['Firewall_Interface_value'] = \
                    interface.get("ip",{}).get("entry",[{"@name":'0'}])[0].get("@name")
                final_interface_dictionary[interface.get('@name')]['Firewall_Interface_management_profile'] = \
                    interface.get('layer3', {}).get("interface-management-profile","ping")

        #SET VR
        for virtual_router in virtual_router_list.get("result", {}).get('entry', []):
            myVRName = virtual_router.get("@name")
            myVirtualRouter = getVirtualRouter(myVRName, firewall)
            for interface in virtual_router.get("interface",{}).get("member",[]):
                if interface in final_interface_dictionary.keys():
                    print(f'found {interface} in VR {myVRName}')
                    final_interface_dictionary[interface]['Firewall_Interface_virtual_router'] = \
                        myVirtualRouter.id if myVirtualRouter else None
                else:
                    print(f'could not find {interface} in VR {myVRName}')

        #set SecurityZone
        for securityZone in security_zone_list.get("result", {}).get('entry', []):
            mySecurityZone = list(filter(lambda n: n.security_zone_name==securityZone.get("@name"),
                                         secZone.objects.filter(security_zone_firewall = firewall)))
            if mySecurityZone == []:
                mySecurityZone = secZone(security_zone_name =securityZone.get("@name"),security_zone_firewall = firewall)
                mySecurityZone.save()
            else:
                mySecurityZone = mySecurityZone[0]
            for interface in securityZone.get("network",{}).get("layer3",{}).get("member",[]):
                if interface in final_interface_dictionary.keys():
                    final_interface_dictionary[interface]['Firewall_Interface_security_zone'] = mySecurityZone.id

        for key in final_interface_dictionary:
            print(f'adding {final_interface_dictionary[key]}')
            if final_interface_dictionary[key].get('Firewall_Interface_virtual_router') and final_interface_dictionary[key].get('Firewall_Interface_security_zone'):
                securityzoneID = secZone.objects.get(id=final_interface_dictionary[key]['Firewall_Interface_security_zone'])
                print(f'pulled SecZone {securityzoneID}')
                virtualrouterID = VirtualRouter.objects.get(id=final_interface_dictionary[key]['Firewall_Interface_virtual_router'])
                vlanNumberID = None
                if final_interface_dictionary[key].get('Firewall_Interface_vlan'):
                    vlanNumberID = Vlan.objects.get(id=final_interface_dictionary[key]['Firewall_Interface_vlan'])
                    del final_interface_dictionary[key]['Firewall_Interface_vlan']

                del final_interface_dictionary[key]['Firewall_Interface_security_zone']
                del final_interface_dictionary[key]['Firewall_Interface_virtual_router']

                myInterface = Firewall_Interface(**final_interface_dictionary[key])
                myInterface.save()
                #get our Interface now with an ID!
                # myInterface = Firewall_Interface.objects.get(Firewall_Interface_value =
                #                                              final_interface_dictionary[key]['Firewall_Interface_value'])
                myInterface.Firewall_Interface_virtual_router = virtualrouterID
                print(f'about to set {securityzoneID} to {myInterface} with {myInterface.Firewall_Interface_id} as id')
                myInterface.Firewall_Interface_security_zone = securityzoneID
                myInterface.Firewall_Interface_vlan = vlanNumberID
                myInterface.save()

@transaction.atomic
def addVirtualRouters(apikey):
    myFirewall_list = Firewall.objects.all()
    for firewall in myFirewall_list:
        print(f'doing firewall: {firewall}')
        result_dictionary = getVirtualRoutersFromPano(apikey, firewall.firewall_template_name.getName(), firewall.firewall_vsys)
        if result_dictionary.get("@status") == 'success':
            for virtual_router in result_dictionary.get('result',{}).get('entry', {}):
                virtual_router_name = virtual_router.get('@name')
                if virtual_router_name:
                    print(f'adding {virtual_router_name} -{firewall.firewall_Name} -- in {firewall.firewall_vsys}')
                    myvirt = VirtualRouter(virtual_router_name=virtual_router_name, virtual_router_firewall = firewall, virtual_router_description = f'{virtual_router_name}--{firewall}')
                    myvirt.save()
                else:
                    print(f'I skipped  {virtual_router_name} on {firewall.getName()} because {firewall.firewall_vsys}\
                    didnot match {virtual_router.get("@vsys")}')
    print('done')


@transaction.atomic
def addVirtualRoutersSpecifyFWList(apikey, myFirewall_list):

    for firewall in myFirewall_list:
        print(f'doing firewall: {firewall}')
        result_dictionary = getVirtualRoutersFromPano(apikey, firewall.firewall_template_name.getName(), firewall.firewall_vsys)
        if result_dictionary.get("@status") == 'success':
            for virtual_router in result_dictionary.get('result',{}).get('entry', {}):
                virtual_router_name = virtual_router.get('@name')
                if virtual_router_name:
                    print(f'adding {virtual_router_name} -{firewall.firewall_Name} -- in {firewall.firewall_vsys}')
                    myvirt = VirtualRouter(virtual_router_name=virtual_router_name, virtual_router_firewall = firewall, virtual_router_description = f'{virtual_router_name}--{firewall}')
                    myvirt.save()
                else:
                    print(f'I skipped  {virtual_router_name} on {firewall.getName()} because {firewall.firewall_vsys}\
                    didnot match {virtual_router.get("@vsys")}')
    print('done')

def pushObjectfromDBtoPano(apikey, object_id):
    myobject = Object.objects.get(object_id = object_id)
    url = f"https://{panorama_server}/restapi/v10.0/Objects/Addresses?location=shared&name={myobject.object_name}"
    data_dictionary = {}
    data_dictionary['entry'] = {}
    data_dictionary['entry']['@name'] =f"{myobject.object_name}"
    data_dictionary['entry'][f"{myobject.object_type}"] = f"{myobject.object_value}"
    if myobject.tags.all():
        data_dictionary['entry']['tag'] = {'member':[f"{mytag.tag_name}" for mytag in myobject.tags.all()]}
    payload = json.dumps(data_dictionary)
    print(f'payload is: {payload}')
    headers = {
        'X-PAN-KEY': apikey,
    }
    response = requests.request("POST", url, headers=headers, data=payload, verify=False)
    answer = json.loads(response.text)
    if answer.get('@status') != 'success':
        #try a PUT ? maybe the object wasn't unique and we are just updating?
        response = requests.request("put", url, headers=headers, data=payload, verify=False)
        answer = json.loads(response.text)
    print(answer)
    return answer

def pushStaticObjectGroupfromDBtoPano(apikey, object_id):
    myobject = Object.objects.get(object_id = object_id)
    url = f"https://{panorama_server}/restapi/v10.0/Objects/AddressGroups?location=shared&name={myobject.object_name}"
    data_dictionary = {}
    data_dictionary['entry'] = {}
    data_dictionary['entry']['@name'] =f"{myobject.object_name}"
    member_list = []
    from FirewallRules.models import AddressGroup
    myAddressGroup = AddressGroup.objects.get(Object_in_DB = myobject)
    #set the object group members
    for member_object in myAddressGroup.object_group_members.all():
        member_list.append(member_object.object_name)
    data_dictionary['entry']['static']={'member' : member_list}
    #set the tags if any
    if myobject.tags.all():
        data_dictionary['entry']['tags'] = {'member':[f"{mytag.tag_name}" for mytag in myobject.tags.all()]}
    payload = json.dumps(data_dictionary)
    #Ilove print
    print(f'payload is: {payload}')
    #set my authentication
    headers = {
        'X-PAN-KEY': apikey,
    }
    #go go go try and create?
    response = requests.request("POST", url, headers=headers, data=payload, verify=False)
    answer = json.loads(response.text)
    #if create didn't work try and update?
    if answer.get('@status') != 'success':
        #try a PUT ? maybe the object wasn't unique and we are just updating?
        response = requests.request("put", url, headers=headers, data=payload, verify=False)
        answer = json.loads(response.text)
    print(f'response for object_group update pushStaticObjectGroupfromDBtoPano \r\n {response}')
    #send the result back either way
    return answer


