from netaddr import IPNetwork, IPAddress
import requests
import xmltodict
from urllib.parse import quote, urlencode
import copy
from FirewallRules.models import routingBubble, Firewall_Interface, Location
from datetime import datetime, timedelta


class staticVariables():

    def __init__(self):
        self.inside_interface = self.get_inside_interface()


    def get_inside_interface(self):
        '''
            creates a dictionary of routing bubbles(key) and their inside interface(value)
            returns: {'AWS-CC-FW':2291,etc...}
        '''
        routing_bubble_list = routingBubble.objects.all() #obtain a list of all bubbles
        inside_default_dictionary = {} #create a dictionary to store data
        for bubble in routing_bubble_list:
            inside_default_dictionary[
                bubble.getID()] = bubble.routingBubble_inside_interface.Firewall_Interface_security_zone.id
        return inside_default_dictionary #return bubble dictionary

#initialize Static Variable
mystatics = staticVariables()

def makestringhttpsafe(string_Data):
    return quote(string_Data, safe='=@&?<>/:;+$,')



def writePanoSecretsFile(username, password,mysecretsfile_location):
    #writes a panos file to a place you tell it to
    #
    from FirewallRules.vars import panorama_server
    f = open(mysecretsfile_location, 'w')
    f.write('PANO_Provider:\r\n')
    f.write(f"           ip_address: '{panorama_server}'\r\n")
    f.write("           username: '" + username + "'\r\n")
    f.write("           password: '" + password + "'\r\n")
    f.close()
    return mysecretsfile_location

def writeYamltoFile(root, data, filename):
    print('writing to file ' + filename)
    f = open(filename, 'w')
    f.write(root + ':\r\n')
    f.write(data)
    f.close()


def getSecurityZoneGiveRoutingBubble(securityZoneObject):
    '''
    assumptions here is that all interfaces that belong to a security zone on a firewall belong to the same routing bubble
    this might need some more rework if we run into 'fun' however i suspect it should suffice for our purposes.
    this function takes a security zone, looksup interfaces that belong to it, and then returns the routing bubble that interface belongs to
    '''
    print(f'entering tools.getSecurityZoneGiveRoutingBubble')
    print(f'with security zone id {securityZoneObject.id}')
    myFirewallInterfaceQuerySet = Firewall_Interface.objects.filter(Firewall_Interface_security_zone = securityZoneObject)
    if len(myFirewallInterfaceQuerySet) > 0 :
        myFirewallInterface = myFirewallInterfaceQuerySet[0] #get the first result. we only need the bubble here
        mybubble = routingBubble.objects.get(
        routingBubble_virtualrouters= myFirewallInterface.Firewall_Interface_virtual_router)
        return mybubble
    else:
        print(f'Failed to find a matching interface for securityZoneObject')
        print(f'returning None Deal with it ')


class FWObject():
    def __init__(self, myDBObject):
        print(f'init FWObject: {myDBObject.getName()}')
        self.dbObject = myDBObject
        self.zone_IDS = copy.deepcopy(mystatics.inside_interface) #make your own copy of our dictionary
        if self.dbObject.getObjectType() != 'address-group':
            self.setMyLocation() #set its location
    def getObjectType(self):
        return self.dbObject.getObjectType()
    def getmyRoutinbBubble(self):
        #should return the routing bubble the object bongs to
        #this is to correctly SET the object's zone.IDs dictionary
        return routingBubble.objects.get(routingBubble_virtualrouters = self.dbObject.object_firewall_interface.Firewall_Interface_virtual_router)
    def getOBJDictionary(self):
        response_dictionary = self.dbObject.getOBJDictionary() #call my SUPER
        response_dictionary['zone_IDS'] = self.zone_IDS
        return response_dictionary
    def setMyLocation(self):
        #correctly set the zone_IDS dictionary for this object
        '''
        object is either on a Firewall, On the Core, in a specific Location or on the Internet (INT)
        so in theory if its on a Firewall we have that interface configured and easy to set in our Zone.IDS dictionary
        if on the CORE we dont have to do anything since default inside captures it
        if its on a location we need to find out which one and set accordingly
        '''
        print(f'Entering FWObject.setMyLocation - ')
        print(f'with current Zone IDs: {self.zone_IDS}')
        if self.dbObject.object_location == 'FW':
            #change the firewall interface to the one that matters
            self.zone_IDS[self.getmyRoutinbBubble().getID()] = self.dbObject.object_firewall_interface.Firewall_Interface_security_zone.id
        elif self.dbObject.object_location == 'CORE':
            pass #nothing needs to happen for CORE
        else:
            #get the location the object belongs
            myObject_Location = Location.objects.get(location_name = self.dbObject.object_location)
            print(f'Setting Location {myObject_Location} with Zones: {myObject_Location.location_path.all()}')
            for securityzone in myObject_Location.location_path.all():
                myrouting_bubble = getSecurityZoneGiveRoutingBubble(securityzone)
                print(f'setting {myrouting_bubble} from {self.zone_IDS[myrouting_bubble.getID()]} to {securityzone.id}')
                self.zone_IDS[
                    myrouting_bubble.getID()] = securityzone.id
            if myObject_Location.location_type == 'Child':
                myObject_Location_parent = myObject_Location.location_parents.all()[0]
                print(f'Setting Parent Location {myObject_Location_parent} with Zones: {myObject_Location_parent.location_path.all()}')
                for securityzone in myObject_Location_parent.location_path.all():
                    myrouting_bubble = getSecurityZoneGiveRoutingBubble(securityzone)
                    print(f'setting {myrouting_bubble} from {self.zone_IDS[myrouting_bubble.getID()]} to {securityzone.id}')
                    self.zone_IDS[
                        myrouting_bubble.getID()] = securityzone.id
        print(f'Leaving FWObject.setMyLocation - ')
        print(f'with finalized Zone IDs: {self.zone_IDS}')

class FWRuleInstance():
    def __init__(self, myDBRuleInstance):
        '''
            Input: instance of FirewallRules.models.RuleInstance

            function:
                initiates an empty rule dictionary to keep track of rules to be added to firewalls
                the keys of the dictionary will be device_group names that need be touched
        '''
        self.dbRuleInstance = myDBRuleInstance
        self.firewall_rule_dictionary = {} #using a dictionary so my keys can be device groups, i know im SMRT..DOH
        self.source_list = set() #using a set to keep things unique
        self.dest_list = set() #using a set to keep things unique
        self.url_dictionary = "" #used to create url cat if any
        self.newservice_list = [] #used to create var file if we have new services
        self.newobject_list = [] #used to create new object/object group if new one

    def addsource(self,source_list_name):
        for source_name in source_list_name:
            self.source_list.add(source_name)
    def getsourcelist(self):
        return list(self.source_list)
    def adddest(self,destination_list_name):
        for destination_name in destination_list_name:
            self.dest_list.add(destination_name)
    def getdestlist(self):
        return list(self.dest_list)
    def addrule(self, rule_list):
        '''
        Input:
            firewall Rule processed from buildSingleSourceSingleDestination function most likely
            format: [{'source_zone_id': [1387], 'destination_zone_id': [1298], 'source_zone': [<secZone: >], 'destination_zone': [<secZone: >], 'devicegroup': ''},...]

        function:
            this function will add or *MERGE* the rule into our self.firewall_rule_list

        output:
            none
        '''
        for rule in rule_list:
            if rule.get('devicegroup') in self.firewall_rule_dictionary.keys():
                #we have to do some merging here.  NOTE ASSUMPTION IS THAT WE HAVE SINGLE DEVICE GROUP!
                myrule = self.firewall_rule_dictionary.get(rule.get('devicegroup'))
                #below we merge all keys in the rules except the device group - remember we are supposedly matching here
                for key in (set(myrule.keys()) ^ (set({'devicegroup'}))):
                    temp_key_list = myrule[key]
                    temp_key_list.append((rule.get(key, [])[0]))
                    myrule[key] = list(set(temp_key_list))
            else:
            #not in my dictionary already lets add it!
                self.firewall_rule_dictionary[rule.get('devicegroup')] = copy.deepcopy(rule) #deep copy the rule

    def getFWRuleDictionary(self):
        return self.firewall_rule_dictionary



class FWLocation():

    def __init__(self, mLocation):
        self.location = mLocation
    def isInLocation(self, value):
        # should provide a True or False to the question of:
        # are our objects learning
        # and also if the value provided in this location
        response = False
        # we assume that networks is a list of subnets
        # split the networks in the list:
        # print(self.networks)
        mysubnets = self.location.location_networks.split(",")
        # we now have a possibe list
        for subnet in mysubnets:
            # print("checking: " + value + " is in: " + subnet)
            if IPAddress(value.split("/")[0]) in IPNetwork(subnet):
                response = True
                break
        return response





def isInRFC1918(value):
    '''
    Below will return true or false
    True if the value sent is in RFC_1918 subnet
    False if its not
    this function is used as last resort to set the object's location to CORE
    '''

    response = False
    # below we create a LIST of RFC_1918 subnets
    myRFCSubnets = '10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16'.split(",")
    # we now have a possibe list
    for subnet in myRFCSubnets:
        # print("checking: " + value + " is in: " + subnet)
        if IPAddress(value.split("/")[0]) in IPNetwork(subnet):
            response = True
            break
    return response


def findObjectLocation(object_ip, location_dictionary_parent, location_dictionary_child):
    '''
    either we'll find a firewall to match
    or a location to match (child first then parent for granular match)
    or the CORE
    or the INTernet
    '''
    print('%%%%%%%%%%%%entering tools.findObjectLocation')
    fuzzy_match = object_ip[0:object_ip.find('.')] #get first octect
    # obtain a full list of security zones now
    response = {}
    #pull all interfaces tha thave values matching our first octet
    myinterfaces = Firewall_Interface.objects.filter(Firewall_Interface_value__contains=fuzzy_match)
    location_found = False
    #match the one we want
    for interface in myinterfaces:
        if IPAddress(object_ip.split("/")[0]) in IPNetwork(interface.getValue()):
            print(
            f'hazzah {interface}, and {interface.Firewall_Interface_virtual_router.virtual_router_firewall.firewall_Name}')
            # response['object_fw'] = interface.Firewall_Interface_virtual_router.virtual_router_firewall.firewall_ID
            response['location'] = 'FW'
            response['interface_id'] = interface.Firewall_Interface_id
            response['interface_name'] = interface.getfullname()
            print(f'sending response : {response}')
            return response
    #I assume im here because no location on a firewall has been found
    for mylocation in location_dictionary_child:
        if FWLocation(mylocation).isInLocation(object_ip):
            print(f'hazzah {object_ip} belongs in location {mylocation}')
            response['location'] = mylocation.location_name
            return response
    for mylocation in location_dictionary_parent:
        if FWLocation(mylocation).isInLocation(object_ip) and (mylocation.location_classification_type != 'special'):
            print(f'hazzah {object_ip} belongs in location {mylocation}')
            response['location'] = mylocation.location_name
            return response
    if isInRFC1918(object_ip):
        print(f'hazzah {object_ip} belongs in location CORE')
        response['location'] = 'CORE'
        return response
    else:
        print(f'hazzah {object_ip} belongs in location Internet')
        response['location'] = 'INT'
        return response

def buildNonRecurringSchedule(start_date_String, duration):
    # duration of 0 means no schedule its handled w/in buildFirewallRulesWeb
    # calculate end date
    print('im in tool.buildNonRecurringSchedule')
    print('i got: ' + str(start_date_String))
    start_date = datetime.strptime(start_date_String[:start_date_String.find('+')], '%Y-%m-%d %H:%M:%S')
    end_date = start_date + timedelta(int(duration))
    # print(start_date.date())
    # print(end_date.date())
    scheduledata = "<schedule-type><non-recurring><member>" + str(start_date.date()).replace('-',
                                                                                             '/') + '@00:00-' + str(
        end_date.date()).replace('-', '/') + '@23:45</member></non-recurring></schedule-type>'
    print(f'returned: {scheduledata} before leaving tools.buildNonRecurringSchedule')
    return scheduledata

def send_XMLPanorequestv3(ip, stringToBeSent, http_method, api_key):
   print('sending https://{ip}/api/?type=config&key={api_key}{stringToBeSent}'.format(ip=ip, api_key = api_key,stringToBeSent=stringToBeSent))
   response = requests.get('https://{ip}/api/?type=config&key={api_key}{stringToBeSent}'.format(ip=ip, api_key = api_key,stringToBeSent=stringToBeSent), verify=False)
   return response.text

def buildSchedule(type, schedule_name, start_date_String, duration):
    # returns the config command

    scheduledata = buildNonRecurringSchedule(start_date_String, duration)
    print('I am in tools.buildSchedule')
    print(scheduledata)
    schedule_url = (
                "&action=set&xpath=/config/shared/schedule&element=<entry%20name='" +
                schedule_name + "'>" + scheduledata + "</entry>")  # , safe='@="/:?&[]')
    print('returning : ' + schedule_url)
    print(f'i built : {schedule_url}')
    return schedule_url

class panorestapi():
    print('Initializing PAN rest API object')

    def __init__(self, ip, username, password):
        self.ip = ip
        self.username = username
        self.password = password
        self.paloapikey = ""  ##self.getapikey(ip, username, password)
        self.baseurl = 'https://{ip}/restapi/v10.0/'.format(ip=self.ip)

        print('Generated PAN rest API key')

    def getapikey(self, ip, username, password):
        print('Gathering PAN rest API key')
        parameters_list = [('user' ,self.username), ('password', self.password)]
        encoded_parameters = urlencode(parameters_list)

        response = requests.get(
            'https://{ip}/api/?type=keygen&{encoded_parameters}'.format(ip=ip,
                                                                        encoded_parameters=encoded_parameters), verify=False)
        apikeydict = xmltodict.parse(response.text)
        print('obtained {apikeydict}'.format(apikeydict=apikeydict))
        if (apikeydict['response']['@status'] != 'error'):
            self.paloapikey = apikeydict['response']['result']['key']  # set the paloapi key
        else:
            self.paloapikey = 'Invalid Credentials'
        return self.paloapikey

    def apikey(self):
        if self.paloapikey == "":
            self.paloapikey = self.getapikey(self.ip, self.username, self.password)
        return self.paloapikey

    ##WIP from here onward-------------------------------------------------------------------------------
    # for the method below, take the object type as an argument/variable passed to it and work that by populating a variable called 'objecttype' based on if statements so you only have to build the query url once

def sendCommand_toPalo_GetXML(ip, stringToBeSent, http_metho):
   print('sending https://{ip}/api/?{stringToBeSent}'.format(ip=ip, stringToBeSent=stringToBeSent))
   response = requests.get('https://{ip}/api/?{stringToBeSent}'.format(ip=ip, stringToBeSent=stringToBeSent), verify=False)
   return response.text
