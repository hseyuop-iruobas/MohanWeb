#in theory this will take a source/dest/service
#and eventually query the firewalls to see if it woudl pass
'''


#load the objects
#init the location for each object.
#send it to MMBuildRule
#get The rule back
#for each rule make an Api call
#store the response back into the 'rule'
#send result to views (return) so it can be formatted there cause you are doing back end!
#those front end people.. dnt get me started

'''


from celery import shared_task
from FirewallRules.models import (Object,
                                  Service,
                                  task,
                                  secZone,
                                  routingBubble,
                                  FirewallRules)
from FirewallRules.tools import (panorestapi,
                                 sendCommand_toPalo_GetXML,
                                 FWObject,
                                 makestringhttpsafe)
import xmltodict
import json
from FirewallRules.buildFirewallRulesWeb import checktoseeifruleisneeded

@shared_task()
def testFirewallRules(username, password, task_id, source_address_id, destination_address_id, service_id):

    mytask = task.objects.get(task_id=task_id)
    mytask.task_status = 'Started' #setting status to Started
    mytask.save()
    source_address = Object.objects.get(object_id = source_address_id)
    destination_address = Object.objects.get(object_id = destination_address_id)
    service = Service.objects.get(service_id = service_id)
    fw_source = FWObject(source_address)
    fw_destination = FWObject(destination_address)
    routinbBubble_checklist = []
    end_firewall_rule_list = []
    apiquery_list = []

    #the api that allows this only takes / 32s .. so strip the /
    source_ip = source_address.object_value[:source_address.object_value.find("/")]
    destination_ip = destination_address.object_value[:destination_address.object_value.find("/")]


    # below we are creating a set of differences in the dictionaries
    # and then extracting a list of keys we need to build our rules
    for routinbBubble_key, securityZone_value in \
            (fw_source.zone_IDS.items() ^ fw_destination.zone_IDS.items()):
        if routinbBubble_key not in routinbBubble_checklist:
            routinbBubble_checklist.append(routinbBubble_key)
    # routinbBubble_checklist now has the list of all routing bubbles where object 1 and 2 are different
    # with this information we can easily build a firewall rule without having to iterate through all of them


    for routingBubble_id in routinbBubble_checklist:
        myquerydictionary= {}
        source_zone_id = fw_source.zone_IDS.get(routingBubble_id)
        destination_zone_id = fw_destination.zone_IDS.get(routingBubble_id)
        source_zone = secZone.objects.get(id=source_zone_id)
        destination_zone = secZone.objects.get(id=destination_zone_id)
        myroutingBubble = routingBubble.objects.get(routingBubble_id=routingBubble_id)
        #devicegroup = myroutingBubble.routingBubble_firewall.firewall_device_group_name.device_group_name
        devicegroup_ip = myroutingBubble.routingBubble_firewall.firewall_mgt_ip
        api_key = panorestapi(ip = devicegroup_ip,
                              username = username,
                              password = password).apikey()
        myquerydictionary['devicegroup'] = myroutingBubble.routingBubble_firewall.firewall_device_group_name.device_group_name
        myquerydictionary['devicegroup_ip'] = devicegroup_ip
        myquerydictionary['source_zone'] = source_zone.security_zone_name
        myquerydictionary['destination_zone'] = destination_zone.security_zone_name
        myquerydictionary['routing_bubble'] = myroutingBubble.routingBubble_name
        myquerydictionary[
            'firewall'] = [myroutingBubble.routingBubble_firewall]
        myquerydictionary['query'] = makestringhttpsafe("type=op&cmd=<test><security-policy-match><from>{source_zone}" \
                                           "</from><to>{destination_zone}</to><source>{source_ip}</source>" \
                                           "<destination>{destination_ip}</destination><protocol>{service}</protocol>" \
                                           "<destination-port>{destination_port}</destination-port></security-policy-match>" \
                                           "</test>&key={api_key}".format(
                                                                          source_zone=source_zone.security_zone_name,
                                                                          destination_zone=destination_zone.security_zone_name,
                                                                          source_ip=source_ip,
                                                                          destination_ip=destination_ip,
                                                                          service=('6'
                                                                                   if service.service_protocol.lower() == 'tcp'
                                                                                   else '17'),
                                                                          api_key=api_key,
                                                                          destination_port=service.service_dest_port),)
        #check businesslogic
        if checktoseeifruleisneeded(firewall_rule_dictionary=myquerydictionary,
                                    source_address=fw_source,
                                    destination_address=fw_destination):
            apiquery_list.append(myquerydictionary)
    print('done setting query results')
    print(f'query list is now : {apiquery_list}')
    for apiquery in apiquery_list:
        result = (sendCommand_toPalo_GetXML(apiquery['devicegroup_ip'],
                                    apiquery['query'], 'GET'))
        myparsedResult = xmltodict.parse(result)
        print('our parsed results are:')
        print(myparsedResult)
        del apiquery['firewall']
        apiquery['result'] = myparsedResult.get('response',{}).get('result',{}).get('rules',{}).get('entry',{}).get('action',"Need a Rule") if myparsedResult.get('response',{}).get('result') else "Need a Rule"
        apiquery['matched_name'] = myparsedResult.get('response',{}).get('result',{}).get('rules',{}).get('entry',{}).get('@name',"Nothing Matched Bro") if myparsedResult.get('response',{}).get('result') else "No Match"
        if apiquery['result'] !='Need a Rule':

            myrule = FirewallRules.objects.filter(name_on_the_firewall=apiquery['matched_name'])
            if len(myrule)>0 :
                apiquery['rule_id'] = myrule[0].rule_instance.ruleinstance_primarykey
            else:
                apiquery['rule_id'] = None
        print('********We found answers:')
        print(apiquery)

    mytask.myAPIKey = "all keys were received"
    mytask.task_results = ""
    mytask.task_results = json.dumps(apiquery_list)
    mytask.task_status = 'Completed'
    mytask.save()

    return apiquery_list