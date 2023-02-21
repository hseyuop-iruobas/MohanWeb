#my giant work of bad things import in!
from FirewallRules.models import (Change,
                                  secZone,
                                  routingBubble,
                                  FirewallRules,
                                  RuleInstance,
                                  AddressGroup)
from FirewallRules.tools import (panorestapi,
                                 FWObject,
                                 FWRuleInstance,
                                 buildSchedule,
                                 send_XMLPanorequestv3,
                                 writeYamltoFile,
                                 writePanoSecretsFile)
from FirewallRules.vars import (panorama_server,
                                resultFolderPath,
                                Firewall_Settings,
                                FirewallFolder,
                                newObject_Location,
                                service_root,
                                services_play_var_file,
                                rule_root,
                                resultFileName,
                                mysecretsfile_location,
                                getSNOW_Username,
                                getSNOW_Password,
                                THISISPROD,SERVICE_NOW_IS_SETUP)
from DataCenter.SnowChange import SNOWChange
#real libraries not my sutff
from datetime import date
from urllib.parse import quote
import xmltodict
import yaml
import os
import ansible_runner
from celery import shared_task
from django.db import transaction



###############################################################
###############################################################




def isSpecialRule(rule):
    '''
        Takes an instance of FWRuleInstance and checks to see if it can be built on
        shared profile instead of per firewall.
        currently the only thing thats special is rules for RFC_1918
        this is really here, cause im getting tired of building 10 rules on 10 firewalls where a single shared policy
         works
    '''
    print(f'assessing rule for being special? {rule}')
    special_list = ('RFC_1918', 'RFC_1918_CORE')
    #if have RFC_1918 or RFC_1918_CORE in the rule its going to be special
    source_addr_list = list(rule.dbRuleInstance.source.all())  #get all the sources

    dest_addr_list = list(rule.dbRuleInstance.dest.all())  # get all the destinations
    source_addr_list.extend(dest_addr_list) #bang em together
    list_of_addresses_used_in_the_rule = [x.object_name for x in source_addr_list]
    myanswer= False
    for item in special_list:
        if item in list_of_addresses_used_in_the_rule:
            myanswer = True
    print(f'the rule was indeed Special: {myanswer}')
    return myanswer

def getSpecialRule(rule,rule_object_dictionary):
    myanyzone = secZone.objects.get(seczone_name='any')
    newRule = {}
    newRule['source_zone'] = myanyzone.getName()
    newRule['source_zone_id'] = myanyzone.seczone_id
    newRule['destination_zone'] = myanyzone.getName()
    newRule['destination_zone_id'] = myanyzone.seczone_id
    newRule['devicegroup'] = 'shared'  # put it in shared this will kick in post and bottom
    newRule['devicegroup_id'] = 0
    # #so i need everything in this to be a string! otherwise all our ansible playfail due to dates in the values
    for key in newRule.keys():
        newRule[key] = str(newRule[key])
    return newRule


@transaction.atomic
def updateCHGStatus(change_number, status):
        print('%%%%%%%Entering update CHG Status%%%%%%%%%%')
        mychange = Change.objects.filter(Change_Number=change_number)[0]
        print(f'loaded CHG { mychange } current status: { mychange.change_status }')
        mychange.change_status = status
        mychange.save()
        mychange = Change.objects.filter(Change_Number=change_number)[0]
        print(f'loaded CHG { mychange } current status: { mychange.change_status }')
        print('%%%%%%%Leaving update CHG Status%%%%%%%%%%')
        mychange.save()

@shared_task
def buildRulefromDBDirect(change_id, username, password):
    try:
        mychange = Change.objects.filter(id=change_id)[0]
        print(f'WELCOME TO MOHAN WE ARE ABOUT TO HAVE SOME FUN with {mychange}')
        change_number = mychange.Change_Number
        RuleList = []

        for request in mychange.Requests.all():
            rule = {}
            sources = []
            for source in request.source.all():
                # print(source.object_name)
                sources.append(source.object_name)
            destination_ip = []
            for destination in request.dest.all():
                destination_ip.append(destination.object_name)
            services = []
            for service in request.service.all():
                services.append(service.service_name)
            rule['id'] = request.id
            rule['rule_instance'] = request.id
            rule['source_ip'] = ",".join(sources)
            rule['destination_ip'] = ",".join(destination_ip)
            rule['service'] = ",".join(services)
            rule['application'] = request.application
            rule['rule_name'] = request.rule_name
            rule['rule_description'] = request.rule_description
            rule['source_user'] = request.source_user
            rule['urls'] = request.urls if request.urls else ''
            rule['ritm'] = request.catagory_name if request.urls else ''
            rule['creation_date'] = request.creation_date
            rule['rule_duration'] = request.rule_duration
            rule['start_date'] = request.start_date
            RuleList.append(rule)
            print(rule)
        # load the CHG to get the refresh ID
        updateCHGStatus(change_number, 'Started')
        firewall_rules = buildFirewallwebRules(RuleList, username, password, change_number)


    except Exception as e:
        print(e)
        print('Someting went wrong with your change')


def unpackObjectGroup(firewall_rule_object, loaded_object_list):
    '''
        function is used to load object groups, or unpack them
        due to how our relations are setup (many to many) and how Django shows them
        we have to make sure that we dont go into a loop loading object-groups that are nested
        a key of what is already loaded is needed to ensure that
    '''
    temp_rule_object_dictionary = {}
    object_group_list = [firewall_rule_object]
    while len(object_group_list) > 0:
        temp_object_group = object_group_list.pop()  # take one out, pass it around
        print(f'processing object-group : {temp_object_group}')
        temp_rule_object_dictionary[temp_object_group.object_name] = FWObject(temp_object_group)  # add it to rule_object_dictionary
        loaded_object_list.append(temp_object_group.object_name)
        real_object_group = AddressGroup.objects.get(Object_in_DB=temp_object_group)
        for member in real_object_group.object_group_members.all():
            if (member.object_name not in loaded_object_list) :
                if member.object_type != 'address-group':
                    print(f'unpacking is an object from {member}')
                    temp_rule_object_dictionary[member.object_name] = FWObject(member)
                    loaded_object_list.append(member.object_name)
                else:
                    # we have an object that is NOT rule_object_dictionary and address group
                    # note it can't be the object we are working on since we loaded that already
                    print(f'this is an object-group adding it to object_group_list')
                    object_group_list.append(member)
    return temp_rule_object_dictionary



def loadObjectsforAllRulesintoDictionary(Firewall_Rule_list):
    '''
    in theory this function receives a list of rule_instance
    it should load all objects and object groups in those instances into a single coherent dictionary
    the format will be:
        {'{object_name}':<tools.FWObject_instance>}
    this is so we can load things faster during rule building in theory
    '''
    print(f'starting FirewallRules.buildFirewallRulesWEb.loadObjectsforAllRulesintoDictionary')
    print(f'attempting to run first unpack against all rulesets')
    rule_object_dictionary = {}
    firewall_rule_list_converted = []
    for ruleInstance in Firewall_Rule_list:
        myFWRuleInstance = FWRuleInstance(ruleInstance)
        firewall_rule_list_converted.append(myFWRuleInstance)
        address_group_used = False
        for source in ruleInstance.source.all():
            if source.object_type !='address-group':
                rule_object_dictionary[source.object_name] = FWObject(source)
                # need a way to keep track of all source associated to rule
                myFWRuleInstance.addsource([source.getName()])
            else:
                temp_rule_object_dictionary = unpackObjectGroup(source,
                                                                list(rule_object_dictionary.keys()))
                rule_object_dictionary.update(temp_rule_object_dictionary) #update our dict
                myFWRuleInstance.addsource(list(temp_rule_object_dictionary.keys()))
        for destination in ruleInstance.dest.all():
            if destination.object_type !='address-group':
                rule_object_dictionary[destination.object_name] = FWObject(destination)
                # need a way to keep track of all destinations associated to rule
                myFWRuleInstance.adddest([destination.getName()])
            else:
                temp_rule_object_dictionary= unpackObjectGroup(destination,
                                                               list(rule_object_dictionary.keys()))
                rule_object_dictionary.update(temp_rule_object_dictionary) #update our dict
                myFWRuleInstance.adddest(list(temp_rule_object_dictionary.keys()))
    print(f'leaving FirewallRules.buildFirewallRulesWEb.loadObjectsforAllRulesintoDictionary')
    print(f'object_dictionary is: {rule_object_dictionary}')
    return rule_object_dictionary, firewall_rule_list_converted


def buildFirewallRule(myruleInstance,rule_object_dictionary ):
    '''
        This function will tak a single ruleinstance and run the buildsinglesource... function
        against all sources and destinations O(N^2) cause we gonna need one for every one

        Input: FirewallRules.tools.FWRuleInstance()
        Output: Nothing
    '''
    print(f'Entering FirewallRules.buildFirewallRuleWeb.buildFirewallRule')
    sourcelist = myruleInstance.getsourcelist()
    destlist = myruleInstance.getdestlist()
    for source_address in sourcelist:
        if rule_object_dictionary[source_address].getObjectType() != 'address-group':
            for destination_address in destlist:
                if rule_object_dictionary[destination_address].getObjectType() != 'address-group':
                    myrulelist =buildSingleSourceSingleDestinationRule(rule_object_dictionary[source_address],
                                                               rule_object_dictionary[destination_address])
                    myruleInstance.addrule(myrulelist)
    print(f'Leaving BuildFirewallRules')
    print(f'with: {myruleInstance.getFWRuleDictionary()}')


def checktoseeifruleisneeded(firewall_rule_dictionary,source_address,destination_address):
    #write your own logic here..
    #for example maybe your cloud location has internet access and you dont need to backhaul things(?)
    return True


def buildSingleSourceSingleDestinationRule(source_address, destination_address):
    '''
    In theory this rule will take to FWObject classes
    Input: source_address, destination_address : FWObject instance

    output:
        should in theory output a list of firewallRule dictionary that includes all necessary
        info to build firewall rules.
    '''
    print(f'Entering FirewallRules.buildFirewallRulesWeb.buildSingleSourceSingleDestinationRule')
    routinbBubble_checklist = []
    end_firewall_rule_list = []
    #below we are creating a set of differences in the dictionaries
    #and then extracting a list of keys we need to build our rules
    for routinbBubble_key,securityZone_value in \
            (source_address.zone_IDS.items() ^ destination_address.zone_IDS.items()):
        if routinbBubble_key not in routinbBubble_checklist:
            routinbBubble_checklist.append(routinbBubble_key)
    #routinbBubble_checklist now has the list of all routing bubbles where object 1 and 2 are different
    #with this information we can easily build a firewall rule without having to iterate through all of them
    for routingBubble_id in routinbBubble_checklist:
        firewall_rule_dictionary = {} #new dictionary
        source_zone_id = source_address.zone_IDS.get(routingBubble_id)
        destination_zone_id = destination_address.zone_IDS.get(routingBubble_id)
        firewall_rule_dictionary['source_zone_id'] = [source_zone_id]
        firewall_rule_dictionary['destination_zone_id'] = [destination_zone_id]
        firewall_rule_dictionary['source_zone'] = [secZone.objects.get(id=source_zone_id)]
        firewall_rule_dictionary['destination_zone'] = [secZone.objects.get(id=destination_zone_id)]
        myroutingBubble = routingBubble.objects.get(routingBubble_id=routingBubble_id)
        firewall_rule_dictionary[
            'devicegroup'] = myroutingBubble.routingBubble_firewall.firewall_device_group_name.device_group_name
        firewall_rule_dictionary[
            'firewall'] = [myroutingBubble.routingBubble_firewall]
        print(f"found: {firewall_rule_dictionary['source_zone']}, "
              f"{firewall_rule_dictionary['destination_zone']}, "
              f"{firewall_rule_dictionary['devicegroup']}")
        if checktoseeifruleisneeded(firewall_rule_dictionary,source_address,destination_address):
            end_firewall_rule_list.append(firewall_rule_dictionary)
    print(f'routinbBubble_checklist: {routinbBubble_checklist}')
    print(f'Leaving FirewallRules.buildFirewallRulesWeb.buildSingleSourceSingleDestinationRule')
    print(f'We found the following: {end_firewall_rule_list}')
    return end_firewall_rule_list




def save_unbuilt_rule_instances(firewall_rule_list_converted):
    for myFWRuleinstance in firewall_rule_list_converted:
        myDBruleinstance = myFWRuleinstance.dbRuleInstance
        #get existing list of firewalls
        firewall_rule_instance_query = FirewallRules.objects.filter(rule_instance=myDBruleinstance)
        #delete the rules not pushed we dont need them seems like we are redoing the work
        #keep the rules that are pushed to firewall we can't delete those with out change
        for rule in firewall_rule_instance_query:
            if rule.pushed_to_firewall == False:
                rule.delete()
        for key,rule in myFWRuleinstance.getFWRuleDictionary().items():
            firewall_rule = FirewallRules()
            firewall_rule.pushed_to_firewall = 'False'
            firewall_rule.name_on_the_firewall = myDBruleinstance.rule_name
            firewall_rule.action = 'allow'
            firewall_rule.isShared = (rule.get('devicegroup') == 'shared')
            firewall_rule.save()
            firewall_rule.rule_instance = myDBruleinstance
            for source in rule.get('source_zone'):
                firewall_rule.source_zone.add(source)
            for dest in rule.get('destination_zone'):
                firewall_rule.destination_zone.add(dest)
            device_group = rule.get('firewall',[])[0]
            if (rule.get('firewall',[])[0] != 'shared'):
                firewall_rule.devicegroup = rule.get('firewall',[])[0]
            else:
                firewall_rule.devicegroup = None
            firewall_rule.save()

def rebuildfrewallruledictionary(myFWRuleInstance):
    myDBruleinstance = myFWRuleInstance.dbRuleInstance
    firewall_rule_query_org = FirewallRules.objects.filter(rule_instance=myDBruleinstance)
    firewall_rule_query= firewall_rule_query_org.filter(pushed_to_firewall=False)
    firewall_rule_list = []
    for rule in firewall_rule_query:
        key = '' #init outside of if block
        firewall_rule_dictionary = {}
        if rule.devicegroup:
            key = rule.devicegroup.firewall_device_group_name.device_group_name
        else:
            key = 'shared'
        #key is set inside if block

        firewall_rule_dictionary['devicegroup'] = key
        firewall_rule_dictionary['action'] = 'allow'
        firewall_rule_dictionary['source_zone'] = ",".join([X.security_zone_name for X in
                                                        rule.source_zone.all()])
        firewall_rule_dictionary['destination_zone'] = ",".join([X.security_zone_name for X in
                                                             rule.destination_zone.all()])
        firewall_rule_dictionary['source_ip'] = ",".join([X.object_name for X in
                                                      myDBruleinstance.source.all()])
        firewall_rule_dictionary['destination_ip'] = ",".join([X.object_name for X in
                                                           myDBruleinstance.dest.all()])
        firewall_rule_dictionary['service'] = ",".join([X.service_name for X in
                                                           myDBruleinstance.service.all()])
        firewall_rule_dictionary['rule_description'] = myDBruleinstance.rule_description if myDBruleinstance.rule_description else myDBruleinstance.id
        firewall_rule_dictionary['rule_name'] = myDBruleinstance.rule_name if myDBruleinstance.rule_name else myDBruleinstance.id
        firewall_rule_dictionary['source_user'] = myDBruleinstance.source_user
        firewall_rule_dictionary['application'] = myDBruleinstance.application
        firewall_rule_dictionary['profile_group_name'] = myDBruleinstance.profile_group_name
        if myDBruleinstance.rule_duration !='0':
            firewall_rule_dictionary['rule_schedule'] = myDBruleinstance.id
        else:
            firewall_rule_dictionary['rule_schedule'] = 'NOSCHEDULE'
        firewall_rule_list.append(firewall_rule_dictionary)
    myFWRuleInstance.addrule(firewall_rule_list)
    return myFWRuleInstance


def processSpecialRule(myRuleInstance):
    '''
        this function tkaes in a rule that has either RFC_1918 as source or dest
        and returns the instance back with a single firewallRule that has any as source zone/dest zone
        and shared as its devicegroup / firewall
        in turn mohan will build a FW rule on shared postpolicies for this
    '''
    end_firewall_rule_list = []
    firewall_rule_dictionary = {}
    #everyfirewall has a any zone, because there are rules that are specific to that firewall
    #however any zone with no firewall meansed SHARED profile .. and is required to exist.
    #since we have lots of em and i dont want to pull the wrong one:
    any_zone = secZone.objects.get(security_zone_name='any', security_zone_firewall=None)

    firewall_rule_dictionary['source_zone_id'] = [any_zone.id]
    firewall_rule_dictionary['destination_zone_id'] = [any_zone.id]
    firewall_rule_dictionary['source_zone'] = [any_zone]
    firewall_rule_dictionary['destination_zone'] = [any_zone]
    firewall_rule_dictionary['devicegroup'] = 'shared' #shared device group and firewall
    firewall_rule_dictionary['firewall'] = ['shared'] #pushes to shared profile / post
    end_firewall_rule_list.append(firewall_rule_dictionary)
    myRuleInstance.addrule(end_firewall_rule_list)
    return myRuleInstance




@shared_task
def buildFirewallwebRules(Firewall_Rule_List_ids):
    '''
        takes in a list of RuleInstance
        processes them and makes firewall rules for them (not push just cacls the path, etc)
        saves it to the database and relates them to the RITM
    '''
    #we should get back a rule object dictionary that has all our objects
    #and a list of all rules that have groups in them
    print(f'Got {Firewall_Rule_List_ids}')
    Firewall_Rule_List = []
    for rule_id in Firewall_Rule_List_ids:
        myruleInstance = RuleInstance.objects.get(id = rule_id)
        myruleInstance.isInUse = True #lock the record in a way
        myruleInstance.save()
        Firewall_Rule_List.append(myruleInstance)
    rule_object_dictionary, firewall_rule_list_converted = loadObjectsforAllRulesintoDictionary(Firewall_Rule_List)
    print(f'and following are loaded: {rule_object_dictionary}')
    for myruleInstance in firewall_rule_list_converted:
        # builds and stores the data inside the FWRuleInstance Objects
        if not isSpecialRule(myruleInstance):
            buildFirewallRule(myruleInstance, rule_object_dictionary)
        else:
            processSpecialRule(myruleInstance)
    save_unbuilt_rule_instances(firewall_rule_list_converted)
    for rule in Firewall_Rule_List:
        rule.isInUse = False
        rule.save()

def buildMemberPortion(urlString):
    '''
    this function takes a string that has commas in it
    comes from the user input on firewallrule instance by the way
    and builds a xml string that we can push to panorama
    its used to build the members for a ULR catagory
    '''
    # assumed we've got a , sprtd URL string
    # example *.io.com,blah.blah.org
    print('rcvd: ' + urlString)
    url_list = urlString.split(",")
    myURLmembers = ""
    for url in url_list:
        # we want to insert <member></member>
        myURLmembers = myURLmembers + "<member>" + url + "</member>"
    print(myURLmembers)
    return myURLmembers

def buildfullInsertURL(url_cat_name, url_cat_members):
    # returns the config command
    myfullInsertURL = "&action=set&xpath=/config/shared/profiles/custom-url-category&element=" \
                      "<entry%20name='" + url_cat_name + "'><type>URL%20List</type><list>" + url_cat_members \
                      + "</list></entry>"
    return myfullInsertURL

import http.client
import ssl
def send_request(ip, stringToBeSent, http_method, api_key):
    conn = http.client.HTTPSConnection(ip, context=ssl._create_unverified_context())
    try:
        url_server = "/api/?type=config&key=" + api_key + stringToBeSent
        conn.request(http_method, url_server)
    except IOError:
        print("Connection was refused. Please check connectivity.")
        raise SystemExit(1)
    r1 = conn.getresponse()
    data1 = r1.read()
    print("############# RESPONSE RECEIVED ################")
    print(data1)
    conn.close()

def buildURLPushData(myFWRuleInstance, api_key):
    '''
    this function takes an instance of tools.FWRuleInstance
    it checks to see if there is a URL cat request in it
    if so it updates the url_dictionary of the ruleinstance with the needed push data
    this data will be used later in the script to push to pano
    '''

    #######################need to create URL objects and catagories
    category = 'any'
    if myFWRuleInstance.dbRuleInstance.urls:
        category = myFWRuleInstance.dbRuleInstance.catagory_name
        if category is None:
            category = myFWRuleInstance.dbRuleInstance.id
        tempString = myFWRuleInstance.dbRuleInstance.urls
        URL_Members = buildMemberPortion(tempString)
        myFWRuleInstance.url_dictionary= URL_Members
        insert_command = buildfullInsertURL(category, URL_Members)
        print('***PUSHING url FROM buildFirewallRulesWeb.buildURLPushData')
        if not THISISPROD: print(f'command is: {insert_command}')
        send_request(panorama_server, insert_command, 'GET', api_key)
    for key,rule in myFWRuleInstance.getFWRuleDictionary().items():
        rule['category'] = category
    return myFWRuleInstance


def buildScheduleforRule(myFWRuleInstance, api_key):
    '''
    this function takes an instance of tools.FWRuleInstance
    it checks to see if there is a  schedule in the rule
    if there is one it builds it to be used in the ansible play
    '''
    print(f'Entering FirewallRules.buildewallRulesWeb.buildSchduleforRule with {myFWRuleInstance}')
    schedule_name = 'NOSCHEDULE'
    response = ''
    if myFWRuleInstance.dbRuleInstance.rule_duration !='0':
        schedule_name = myFWRuleInstance.dbRuleInstance.id
        myStartDate = str(myFWRuleInstance.dbRuleInstance.start_date)
        myduration = myFWRuleInstance.dbRuleInstance.rule_duration  # get the duration.
        # print(myStartDate + ' ' + myduration)

        #build a schedule
        schedule_insert_string = buildSchedule('nonReoccuring', schedule_name , myStartDate,
                                                       myduration)
        response = send_XMLPanorequestv3(panorama_server, schedule_insert_string, 'GET', api_key)
        if not THISISPROD: print(f'response from panorama was {response}')
    for key, rule in myFWRuleInstance.getFWRuleDictionary().items():
        rule['rule_schedule'] = schedule_name
    print(f'Leaving FirewallRules.buildewallRulesWeb.buildSchduleforRule')
    return response



def appendRuleswithIDandLogging(myFWRuleInstance):
    '''
    this function takes an instance of tools.FirewallRuleInstance
    and appends its dictionary with the appropriate tags
    '''
    rule_dictionary = myFWRuleInstance.getFWRuleDictionary()
    for devicegroup , rule in rule_dictionary.items():
        rule.update(Firewall_Settings)
    return myFWRuleInstance

def checkServiceinPanoShared(django_service_object, api_key):

    '''
    this function takes the api key, and a FirewallRules.models.Service instance
    checks to see if it exists in panorama
    if not returns false
    '''
    service_name = django_service_object.service_name
    print(f'Entering buildFirewallRulesWeb.checkServiceinPanoShared with {service_name}')

    stringToBeSent = quote('&action=get&xpath=/config/shared/service/entry[@name="' + str(service_name).upper() + '"]',
                           safe='@="/:?&[]')
    if not THISISPROD: print(stringToBeSent)
    response = send_XMLPanorequestv3(panorama_server, stringToBeSent, 'GET', api_key)
    objinfo = xmltodict.parse(response)

    if str(response).find('entry') > 0:
        if not THISISPROD: print('Found Service ' + service_name + ' in Panorama, comparing DB and Panorama values')
        if not THISISPROD: print('Retrieving django service object for value comparison')

        #start value check code chunk
        if 'tcp' in str(objinfo['response']['result']['entry']['protocol']):
            if not THISISPROD: print('service object is tcp, extracting port value and comparing')
            if not THISISPROD: print('Panorama Value: ' + str((objinfo['response']['result']['entry']['protocol']['tcp']['port'])))
            if not THISISPROD: print('DB Value: ' + str(django_service_object.service_dest_port))
            if str((objinfo['response']['result']['entry']['protocol']['tcp']['port'])) == str(django_service_object.service_dest_port):
                if not THISISPROD: print('Values match')
                return True
            else:
                if not THISISPROD: print('Values do not match')
                return False
        elif 'udp' in str(objinfo['response']['result']['entry']['protocol']):
            if not THISISPROD: print('service object is udp, extracting port value and comparing')
            if not THISISPROD: print('Panorama Value: ' + str((objinfo['response']['result']['entry']['protocol']['udp']['port'])))
            if not THISISPROD: print('DB Value: ' + str(django_service_object.service_dest_port))
            if str((objinfo['response']['result']['entry']['protocol']['udp']['port'])) == str(django_service_object.service_dest_port):
                if not THISISPROD: print('Values match')
                return True
            else:
                if not THISISPROD: print('Values do not match')
                return False
        #end value check code chunk
    else:
        print('Did not find Object ' + service_name + ' in Panorama writing to file')
        return False

def buildServiceFileForPlay(myFWRuleInstance, api_key):
    '''
    this function takes an innce of tools.FWRuleInstance
    it checks to see if all the services in it are in panorama
    if not it updates the dictionary in the FWRuleInstance to include it for later write and run for play
    TODO: handle service-groups
    '''
    newService_Flag = False
    # go through the lists, pull out services, edit services, put back services.
    # using a dictionary to avoid duplicates
    newServicesforPlayDict_sql = {}
    newServicesforPlayList_List = []
    newSRVList = []
    # travers the rule set
    rule_dictionary = myFWRuleInstance.getFWRuleDictionary()
    for service in myFWRuleInstance.dbRuleInstance.service.all():
        if ('-dst-' in service.service_name.lower()): #only services that have -DST- should be verified and created
        #in theory all other services are manually created for some reason and should trust user that it exists in Pano
             if (checkServiceinPanoShared(service, api_key)):  # service is in Panorama
                 print('service found in Panorama, DB and Panorama values match, Skipping')
             else:
                 # object no in panorama
                 # retrieve it from server
                 Service_dict = {}
                 Service_dict['service_protocol'] = service.service_protocol.lower()
                 Service_dict['service_name'] = service.service_protocol.upper() + "-DST-" + str(
                     service.service_dest_port)
                 servicetags = service.service_tag.all()
                 if servicetags:
                     tagresult = []
                     for tag in servicetags:
                         tagresult.append(tag.tag_name)
                         Service_dict['service_tag'] = ",".join(tagresult)
                 else:
                     Service_dict['service_tag'] = "[]"
                 Service_dict['service_description'] = service.service_description
                 Service_dict['service_dest_port'] = str(service.service_dest_port)
                 myFWRuleInstance.newservice_list.append(Service_dict) #add it to the rule instance's service list return for later!
    return myFWRuleInstance


def checkObjectinPanoShared(object_name, api_key):
    print(f'sending: {object_name} & type is {type(object_name)}')
    if object_name.dbObject.getObjectType() != 'address-group':
        stringToBeSent = quote('&action=get&xpath=/config/shared/address/entry[@name="' + object_name.dbObject.getName() + '"]',
                               safe='@="/:?&[]')
        if not THISISPROD: print(stringToBeSent)

    else:
        stringToBeSent = quote(
            '&action=get&xpath=/config/shared/address-group/entry[@name="' + object_name.dbObject.getName() + '"]',
            safe='@="/:?&[]')
        if not THISISPROD: print(stringToBeSent)

    response = send_XMLPanorequestv3(panorama_server, stringToBeSent, 'GET', api_key)
    # print('**************************PT DEBUG - ABOUT TO PARSE RESPONSE FROM PANORAMA API CALL**************************')
    objinfo = xmltodict.parse(response)
    if str(response).find('entry') > 0:
        # print('**************************PT DEBUG - FOUND OBJECT IN PANORAMA**************************')
        print('Determining whether object is address or address group now...')
        if object_name.dbObject.getObjectType() != 'address-group':
            # print('Object is type ip-netmask or fqdn')
            print('Found Object ' + object_name.dbObject.getName() + ' in Panorama, comparing DB and Panorama values')
            if str(object_name.dbObject.getObjectType()) == 'fqdn':
                print('Panorama Value: %s' % str(objinfo['response']['result']['entry']['fqdn']))
            elif str(object_name.dbObject.getObjectType()) == 'ip-netmask':
                print('Panorama Value: %s' % str(objinfo['response']['result']['entry']['ip-netmask']))
            print('DB Value: %s' % str(object_name.dbObject.getValue()))
            if str(object_name.dbObject.getObjectType()) == 'fqdn':
                if str((objinfo['response']['result']['entry']['fqdn'])) == str(object_name.dbObject.getValue()):
                    print('Values match')
                    return True
                else:
                    print('Values do not match')
                    return False
            elif str(object_name.dbObject.getObjectType()) == 'ip-netmask':
                if str((objinfo['response']['result']['entry']['ip-netmask'])) == str(object_name.dbObject.getValue()):
                    print('Values match')
                    return True
                else:
                    print('Values do not match')
                    return False
        else:
            print('Object is address group')
            print(f'Address group {object_name} is in Panorama already')
            return True
    else:
        print(f'Did not find Object {object_name} in Panorama writing to file')
        return False


def buildObjectFileForPlay(myFWRuleInnce, api_key):
    newOBJList = []
    # print(rule_object_dictionary)
    # first pull all the sources
    rule_object_dictionary = {}
    rule_object_dictionary, firewall_rule_list_converted = loadObjectsforAllRulesintoDictionary([myFWRuleInnce.dbRuleInstance])

    for object in rule_object_dictionary.keys():
        objectTYPE = rule_object_dictionary[object].getObjectType()
        print("objectTYPE : " + str(objectTYPE))
        if (objectTYPE != 'special'):
            if (checkObjectinPanoShared(rule_object_dictionary[object], api_key) != True):
                temp_dict = {}
                temp_dict = rule_object_dictionary[object].getOBJDictionary()

                objectfortags_tags = rule_object_dictionary[object].dbObject.tags.all()
                print(f'found these tags: {objectfortags_tags}')
                if objectfortags_tags:
                    tagresult = []
                    for tag in objectfortags_tags:
                        tagresult.append(tag.tag_name)
                    print(f'adding these tags to object_tag dictionary: {tagresult}')
                    temp_dict['object_tag'] = ",".join(tagresult)
                else:
                    temp_dict['object_tag'] = "[]"
                if objectTYPE == 'address-group':
                    # we need to create a list of all members
                    real_address_group = AddressGroup.objects.get(Object_in_DB = rule_object_dictionary[object].dbObject)
                    myobject_member_list = real_address_group.object_group_members.all()
                    temp_list_for_names = []
                    for member in myobject_member_list:
                        temp_list_for_names.append(member.getName())
                    temp_dict['object_value'] = ",".join(temp_list_for_names)
                myFWRuleInnce.newobject_list.append(temp_dict)#add it to the list so we can deal with it later
    return myFWRuleInnce

def process_and_write_final_var_files(firewall_ruleinstances_to_process):
    '''
    this funct should take a list of fully prepped tools.FWRuleInstance and build the appropriate yamls files
    '''
    #step 1 compile a listf all objects, services, and rules that need to be built
    newobject_dictionary = {} #avoid duplicates use keys and object names
    newservice_dictionary = {} #avoid duplicates use keys a service name
    newfirewall_rule_list = [] #is a list no firewall rule is duplicate due to nature of how addrule works in FWRuleInstance
    old_firewall_rules_to_be_removed = [] #list of rule ON the firewall currently
    FIREWALL_RULES_ADDED = False
    OBJECTS_LOADING = False
    SERVICE_LOADING = False
    for ruleinstance in firewall_ruleinstances_to_process:
        #lets get the firewall rules that are currently in the DB and set to true
        for firewall_rule_pushed_already in FirewallRules.objects.filter(rule_instance = ruleinstance.dbRuleInstance,
                                                                         pushed_to_firewall=True):
            temp_dictionary = {}
            temp_dictionary['rule_name'] = firewall_rule_pushed_already.name_on_the_firewall
            temp_dictionary['devicegroup'] = firewall_rule_pushed_already.devicegroup.firewall_device_group_name.device_group_name
            temp_dictionary['state'] = 'absent' #remove the rule
            temp_dictionary['rule_schedule'] = 'NOSCHEDULE'  # remove the rule
            old_firewall_rules_to_be_removed.append(temp_dictionary)
        for myobj in ruleinstance.newobject_list:
            del myobj['zone_IDS']
            newobject_dictionary[myobj.get('object_name')] = myobj
        #now do services
        for service_dictionary in ruleinstance.newservice_list:
            newservice_dictionary[service_dictionary.get('service_name')] = service_dictionary
        #now do firewall rules
        for key in ruleinstance.getFWRuleDictionary().keys():
            newfirewall_rule_list.append(ruleinstance.getFWRuleDictionary().get(key))
    if newobject_dictionary:
        data = yaml.dump(list(newobject_dictionary.values()))
        writeYamltoFile('objects', data, FirewallFolder + newObject_Location)
        OBJECTS_LOADING = True
    if newservice_dictionary:
        data = yaml.dump(list(newservice_dictionary.values()))
        writeYamltoFile(service_root, data, FirewallFolder + services_play_var_file)
        SERVICE_LOADING = True
    if newfirewall_rule_list:
        newfirewall_rule_list.extend(old_firewall_rules_to_be_removed)
        Rules = yaml.dump(newfirewall_rule_list)
        writeYamltoFile(rule_root, Rules, FirewallFolder + resultFileName)
        FIREWALL_RULES_ADDED = True
    print(f'removing following firewall rules: {old_firewall_rules_to_be_removed}')
    print(f'newobject_dictionary : {newobject_dictionary}')
    print(f'newservice_dictionary : {newservice_dictionary}')
    print(f'newfirewall_rule_list: {newfirewall_rule_list}')
    return FIREWALL_RULES_ADDED,OBJECTS_LOADING,SERVICE_LOADING


def RunAnsiblePlays(FIREWALL_RULES_ADDED,OBJECTS_LOADING,SERVICE_LOADING, username, password, change_number):
    #TODO: check the status of the play and actually make sure it was done and didn't fail ? return False if failed
    RUN_PLAYS = FIREWALL_RULES_ADDED or OBJECTS_LOADING or SERVICE_LOADING
    print('Current Status for Plays is:' + str(RUN_PLAYS))
    today = date.today()
    # resultFileName = 'results/firewall_rules.yml'
    EndresultFileName = resultFolderPath + today.strftime("%b-%d-%Y") + "-" + str(change_number) + "-results.yml"
    EndresultServiceFileName = resultFolderPath + today.strftime(
        "%b-%d-%Y") + "-" + str(change_number) + "-Services.yml"
    Endobject_file_path = resultFolderPath + today.strftime("%b-%d-%Y") + "-" + str(change_number) + "-objects.yml"

    # i dont want to run plays right now - debug *****
    status_of_play_succeeded = True
    #RUN_PLAYS = False
    if RUN_PLAYS:
        ### Write the secret file
        secretfilelocation = writePanoSecretsFile(username, password, FirewallFolder + mysecretsfile_location)
        import time
        time.sleep(10)

        if OBJECTS_LOADING:
            print('Running Objects Play:')
            runner = ansible_runner.run(private_data_dir='',
                                        playbook=FirewallFolder + 'ansible-plays/build-objects.yml',
                                        inventory=FirewallFolder + 'ansible-plays/inventory/PALO-inventory.ini')
            stream = os.popen(
                'mv ' + FirewallFolder + newObject_Location + ' ' + FirewallFolder + Endobject_file_path)  # move the Service play var file
            print("{}: {}".format(runner.status, runner.rc))
            if runner.status == 'failed' :
                status_of_play_succeeded = False

        if SERVICE_LOADING:
            print('Running Services Play:')
            runner = ansible_runner.run(private_data_dir='',
                                        playbook=FirewallFolder + 'ansible-plays/build-services.yml',
                                        inventory=FirewallFolder + 'ansible-plays/inventory/PALO-inventory.ini')
            stream = os.popen(
                'mv ' + services_play_var_file + ' ' + EndresultServiceFileName)  # move the Service play var file
            print("{}: {}".format(runner.status, runner.rc))
            if runner.status == 'failed' :
                status_of_play_succeeded = False


        if FIREWALL_RULES_ADDED:
            print('Running FW Play:')
            runner = ansible_runner.run(private_data_dir='',
                                        playbook=FirewallFolder + 'ansible-plays/build-firewalls.yml',
                                        inventory=FirewallFolder + 'ansible-plays/inventory/PALO-inventory.ini')
            print("{}: {}".format(runner.status, runner.rc))
            stream = os.popen(
                'mv ' + FirewallFolder + resultFileName + ' ' + FirewallFolder + EndresultFileName)  # move the FW play
            if runner.status == 'failed' :
                status_of_play_succeeded = False

        print(f'nuking pass file@ {secretfilelocation}')
        # stream = os.popen(
        # 'ansible-vault encrypt ' + FirewallFolder + 'ansible-plays/inventory/firewall-secrets.yml --vault-password-file ' + FirewallFolder + 'ansible-plays/vaultpass.zp')  # encrypt keys
        # time.sleep(15)
        # stream = os.popen('rm ' + FirewallFolder + 'ansible-plays/vaultpass.zp')  # nuke the file
        stream = os.popen('rm ' + secretfilelocation)  # nuke the file

    else:
        print("Well that was anti-climatic no rules were created")
        # the bulk call passes change 'CHG000', however the buidDirectfromDB function will pass a real change number
    return status_of_play_succeeded


def close_service_now_change(change_number):
    print('Entering update and close snow change')
    mysnowrecord = SNOWChange()  # create a new instance of SNOWChange
    # get change SYSID
    change_sys_id = mysnowrecord.getChangeSYSID(change_number, getSNOW_Username(), getSNOW_Password())
    print('change system id: {change_sys_id}'.format(change_sys_id=change_sys_id))
    # close all tasks left but first get them
    temp_task_dictionary_list = mysnowrecord.gettaskLIST(change_sys_id, getSNOW_Username(), getSNOW_Password())
    print(temp_task_dictionary_list)
    # sorting the list based on name value. this way we close the first task before the next
    task_dictionary_list = sorted(temp_task_dictionary_list, key=lambda k: k['number'])
    print('Now sorting tasks:')
    print(task_dictionary_list)
    for task in task_dictionary_list:
        if task['state'] != 'Closed':
            print('closing task: {task}'.format(task=task))
            mysnowrecord.CloseThisTask(change_sys_id, task['sys_id'], getSNOW_Username(), getSNOW_Password())
    # we now assume all tasks are closed and we close the change
    myMohanChange = Change.objects.get(Change_Number=change_number)
    change_URL = "https://askmohan.company.local/DataCenter/change/{id}".format(id=myMohanChange.id)
    close_data = {}
    close_data['u_conflict_acknowledged'] = 'Yes'
    close_data['close_code'] = 'Implemented'
    close_data['u_resulting_issues'] = 'No Issues'
    close_data['u_resulting_impact'] = 'No Negative Impact'
    close_data['close_notes'] = "Mohan Did it!\r" + change_URL
    mysnowrecord.closeChange(change_sys_id, getSNOW_Username(), getSNOW_Password(), close_data)



def pushrulestofirewall(username, password, change_number):
    '''
        in theory this function is called WHEN we are ready to push a change to our firewalls
        the change number will have requests in it
        each request will have afirewallrules associated with it.
        we pull those
        we build those
        we pad those and process em and give em a number 6...
        a Number 6 whats that you might ask?
        Well, that's where we go a-ridin' into town, a whampin' and whompin' every livin' thing that moves within an inch of its life. Except the women folks, of course. (blazing-saddles)
    '''
    #######################################################################################################
    ############              START OF SCRIPT                                   ###########################
    #################                                                     #################################
    #########################     #########################################################################
    print("pulling API keys")
    panoObj = panorestapi(panorama_server, username, password)
    api_key = panoObj.apikey()
    errors = []
    if ('Invalid' in api_key):
        print("Detected Invalid Credentials ")
        errors.append('Invalid Credentials or Unable to pull key')
        return errors
    ####  MY VARS #####
    ###### maybe this goes inside its own class(?)
    #######something for DEV Vs PROD? or is that overkill?
    ##setup date and time
    today = date.today()
    # resultFileName = 'results/firewall_rules.yml'
    EndresultFileName = resultFolderPath + today.strftime("%b-%d-%Y") + "-" + str(change_number) + "-results.yml"
    EndresultServiceFileName = resultFolderPath + today.strftime(
        "%b-%d-%Y") + "-" + str(change_number) + "-Services.yml"
    Endobject_file_path = resultFolderPath + today.strftime("%b-%d-%Y") + "-" + str(change_number) + "-objects.yml"
    ##setup local vars for plays
    OBJECTS_LOADING = False  # setting to true since we always need to make sure obj exist for now
    SERVICE_LOADING = False
    OBJECT_GROUPLOADING = False
    FIREWALL_RULES_ADDED = False
    URL_LOADING = False
    ####  END OF MY VARS #####
    #createa  list of rules we need to build for
    mychange = Change.objects.get(id = change_number)
    print(f'You Trusted me with high level creds!?, lets have some fun with change# {(change_number)}')
    #set chnage status to 'started'
    mychange.change_status = 'Started'
    mychange.save()
    firewall_ruleinstances_to_process = []
    #process the change for URLS and build them if needed

    for ruleinstance in mychange.Requests.all():
        # firewall_rule_dictionary = ruleinstance.getFWRuleDictionary()
        myFWRuleInstance = FWRuleInstance(ruleinstance)
        myFWRuleInstance = rebuildfrewallruledictionary(myFWRuleInstance)
        # process URLS
        myFWRuleInstance = buildURLPushData(myFWRuleInstance, api_key)
        result = buildScheduleforRule(myFWRuleInstance, api_key)
        myFWRuleInstance = appendRuleswithIDandLogging(myFWRuleInstance)
        myFWRuleInstance = buildServiceFileForPlay(myFWRuleInstance, api_key)
        myFWRuleInstance = buildObjectFileForPlay(myFWRuleInstance, api_key)
        firewall_ruleinstances_to_process.append(myFWRuleInstance)

    print(f'finalized all ruleinstances - going to write new var files for plays')
    FIREWALL_RULES_ADDED,OBJECTS_LOADING,SERVICE_LOADING = process_and_write_final_var_files(firewall_ruleinstances_to_process)
    Success = RunAnsiblePlays(FIREWALL_RULES_ADDED=FIREWALL_RULES_ADDED,
                              OBJECTS_LOADING=OBJECTS_LOADING,
                              SERVICE_LOADING=SERVICE_LOADING,
                              username=username, password=password,
                              change_number=change_number)
    if Success:
        for ruleinstance in mychange.Requests.all():
            #we assume ansible ran successfully and commit = true
            #so now we close the change and set the 'pushed' status to TRUE
            #set the pushed status to True
            firewall_rule_query = FirewallRules.objects.filter(rule_instance=ruleinstance)
            for firewall_rule in firewall_rule_query:
                if firewall_rule.pushed_to_firewall:
                    #we removed all the rules that were ON the firewall so delete them from DB
                    firewall_rule.rule_instance = None
                    firewall_rule.delete()
                else:
                    firewall_rule.pushed_to_firewall = True
                    firewall_rule.save()
            #tag the instance as usable again
            ruleinstance.isInUse = False
            ruleinstance.save()

        #set the change status to completed
        mychange.change_status = 'Complete'
        mychange.save()
        if SERVICE_NOW_IS_SETUP:
            close_service_now_change(mychange.Change_Number)
        ####DONE
        return firewall_ruleinstances_to_process
    else:
        print('invisible_tag_start')
        print(f'CHANGE -- {change_number} did not succeed - it FAILED')
        print(f'CHANGE -- please review the logs - I think something to do with Ansible.'
              f'I left the change open in Service now!\r\n '
              f'and was nice enough to not push/close the rules\r\n')
        print('invisible_tag_end')

