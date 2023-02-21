
from FirewallRules.myExceptions import DumbAssException
from DataCenter.SnowChange import SNOWChange
from DataCenter.models import (Vlan, Tenant, DataCenter,SNOWChangeTemplate)
from FirewallRules.models import (Change, RuleInstance, FirewallRules, task,tag,
                                  secZone, Object, Service, Firewall_Interface, Duplicates,
                                  Location, IKE_VPN, AddressGroup)
from FirewallRules.buildikevpn import buildikeVPN
from FirewallRules.vars import (getSNOW_Username, getSNOW_Password,relativePath,
                                panorama_server, pano_readonly_username, pano_readonly_password,
                                THISISPROD, SERVICE_NOW_IS_SETUP)

from FirewallRules.tools import (panorestapi,findObjectLocation, makestringhttpsafe)
from FirewallRules.populateDBFirewallsFromPano import (getSingleobjectswithtag,pushObjectfromDBtoPano,
                                                       pushStaticObjectGroupfromDBtoPano,getSingleobjectGroupswithtag,
                                                       getallobjectswithtag,)
from FirewallRules.buildFirewallRulesWeb import buildFirewallwebRules
from FirewallRules.checkSrcDstLogs import (get_job_id_SrcDstLogsv2,
                                           get_job_data_fromPanorama,
                                           get_job_id_RoutingChange,
                                           get_job_data_from_device)
from FirewallRules.EDLtoObject import EDLtoObjectGroupFunction
from DataCenter.forms import (RuleInstanceForm, ChangeInstancePushForm, ChangeInstanceFormv2,
                              CreateObjectForm, ServiceInstanceForm,
                              CheckTheLogsForm5000EntriesSingleAddress,
                              CheckTheLogsForm,checkFirewallFlow,
                              UpdateVlanDatabaseFromSwitchForm,UpdateTenantDatabaseFromSwitchForm,
                              IKEVPNForm, replicateRulesForm, CreateAddressGroupForm,
                              EDLtoObjectGroupForm,)
from DataCenter.redirectedbuildRulefromDBDirect import redirectedbuildRulefromDBDirect
from DataCenter.vlanandtenants import (sendAPIRequeststoAristaSwitch,
                                           getVlansFromSwitch,
                                           getTenantandVlans,
                                           addVlansToDatabase,
                                           addTenantInfotoDatabase,
                                           getTenantsfromSWitch)

from FirewallRules.needFirewallRule import testFirewallRules

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.db import transaction
from django.views import generic
from django.http import HttpResponse
from django.http import JsonResponse
import django.db.utils
import pyeapi
import json
from datetime import datetime, timedelta,date
import xml.etree.ElementTree as ET
######################################## THIS SECTION IS FOR VIEWS THAT ARE GENERIC STUFF


class RITMDetailView(LoginRequiredMixin,generic.DetailView):
   model = RuleInstance


class RITMListView(LoginRequiredMixin,generic.ListView):
    model = RuleInstance
    paginate_by = 20
    ordering = ['-ruleinstance_primarykey']


@login_required
def ChangeListView(request):
    change_list = Change.objects.all().order_by('-id')[::-1]
    return render(request, 'FirewallRules/change_list.html', {'change_list': change_list, })


class ChangeDetailView(LoginRequiredMixin,generic.DetailView):
   model = Change

   def get_context_data(self, **kwargs):
        # Call the base implementation first to get the context
        context = super(ChangeDetailView, self).get_context_data(**kwargs)
        return context

class VlanDetailView(LoginRequiredMixin,generic.DetailView):
   model = Vlan

   def get_context_data(self, **kwargs):
        # Call the base implementation first to get the context
        context = super(VlanDetailView, self).get_context_data(**kwargs)
        # Create any data and add it to the context
        #print(f"my vlan id db context is: {context['vlan'].id}")
        interface_query = Firewall_Interface.objects.filter(Firewall_Interface_vlan = context['vlan'])
        if len(interface_query)>0:
           context['interface_query'] = interface_query
        return context



class VlanListView(LoginRequiredMixin,generic.ListView):
    model = Vlan


class TenantDetailView(LoginRequiredMixin,generic.DetailView):
   model = Tenant

class TenantListView(LoginRequiredMixin,generic.ListView):
    model = Tenant


class ObjectDetailView(LoginRequiredMixin,generic.DetailView):
   model = Object



class ObjectListView(LoginRequiredMixin,generic.ListView):
    model = Object
    template_name = 'FirewallRules/object_list.html'
    paginate_by = 300


class ServiceDetailView(LoginRequiredMixin,generic.DetailView):
   model = Service

class ServiceListView(LoginRequiredMixin,generic.ListView):
    model = Service
    def get_ordering(self):
        ordering = self.request.GET.get('ordering', 'service_name')
        # validate ordering here
        return ordering


######################################## VIEW BASED /LIST BASED CLASSES END
def index(request):
    # this should in theory request index.html and pass it a dictionary created here
    # dictionary's name is context
    totalVLAN_count = Vlan.objects.all().count()
    totalVRF_count = Tenant.objects.all().count()
    totalChanges_count = Change.objects.all().count()
    totalRuleInstance_count = RuleInstance.objects.all().count()
    totalfirewallRules_count = FirewallRules.objects.all().count()
    totalsearchTasks = task.objects.all().count()

    context = {
        'totalVLAN_count' : totalVLAN_count,
        'totalVRF_count' : totalVRF_count,
        'totalChanges_count' : totalChanges_count,
        'totalRuleInstance_count': totalRuleInstance_count,
        'totalfirewallRules_count' :totalfirewallRules_count,
        'totalsearchTasks' :totalsearchTasks,
    }

    return render(request, 'index.html', context=context)

@login_required
def searchboxresult(request):
    if request.method == "POST":
        searched = request.POST.get('searched' , None)
        if searched:
            return redirect('SEARCHRESULTGET', searched=searched)
        else:
            return render(request, 'search.html', {})


@login_required
def cloneRuleInstance(request):
    if request.method == 'POST':
        #in theory since transaction is atomic if we dont fail we can delete
        #if we fail we dont delete
        with transaction.atomic():
            rule_list_to_clone = request.POST.getlist('rule_list_ids[]')
            for rule_id in rule_list_to_clone:
                #but why are we doing FILTER when we know there is a rule ID for sure??? WELL MY FRIEND!
                myruleInstance_query = RuleInstance.objects.filter(ruleinstance_primarykey = rule_id)
                myruleInstance_Dictionary = myruleInstance_query.values()[0]
                del myruleInstance_Dictionary['ruleinstance_primarykey'] #nuke primary key
                myruleInstance_Dictionary['id'] = request.POST.get('rule_list_label') + myruleInstance_Dictionary['id']
                myruleInstance_Dictionary['rule_description'] = f'Cloned from Rule {myruleInstance_query[0].ruleinstance_primarykey}'
                newClone = RuleInstance(**myruleInstance_Dictionary)
                newClone.save()
                #do all the M2Ms:
                newClone.source.set(myruleInstance_query[0].source.all())
                newClone.dest.set(myruleInstance_query[0].dest.all())
                newClone.service.set(myruleInstance_query[0].service.all())
                #save it!
                newClone.save()
            response_data = {}
            response_data['result'] = 'success'
    else:
        response_data = {}
        response_data['result'] = 'failed'
        response_data['data'] = 'You need to POST to me'
    return HttpResponse(json.dumps(response_data),
                        content_type="application/json")


@login_required
def replicateRuleInstance(request):
    if request.method == 'POST':
        target_rules = request.POST.getlist('rule_list_ids[]')
        target_servers = request.POST.get('target_values')
        target_label = request.POST.get('rule_list_label')
        current_server = request.POST.get('current_server_id')

        target_Servers_object = Object.objects.get(object_id = target_servers)
        if not THISISPROD : print(f'Ive been asked to replace {current_server} in rule ID:{target_rules} with {target_Servers_object} and prePend with {target_label}')
        with transaction.atomic():
            response_data = {}
            try:
                for rule_id in target_rules:
                    #but why are we doing FILTER when we know there is a rule ID for sure??? WELL MY FRIEND!
                    myruleInstance_query = RuleInstance.objects.filter(ruleinstance_primarykey = rule_id)
                    myruleInstance_Dictionary = myruleInstance_query.values()[0]
                    del myruleInstance_Dictionary['ruleinstance_primarykey'] #nuke primary key
                    from FirewallRules.vars import max_rule_name_lenght
                    new_rule_lenght = max_rule_name_lenght - len(target_label)
                    newID = '' #set to empty
                    if len(myruleInstance_Dictionary['id']) > new_rule_lenght:
                        newID = target_label + "-" + myruleInstance_Dictionary['id'][:new_rule_lenght-1]
                    else:
                        newID = target_label + "-" + myruleInstance_Dictionary['id']
                    myruleInstance_Dictionary['id'] = newID
                    myruleInstance_Dictionary['rule_name'] = newID
                    myruleInstance_Dictionary['rule_description'] = f'Cloned from Rule {myruleInstance_query[0].ruleinstance_primarykey} with {target_servers} to replace {current_server}'
                    newClone = RuleInstance(**myruleInstance_Dictionary)
                    newClone.save()
                    #do all the M2Ms:
                    if not THISISPROD : print(f'checking {(current_server)} in {[(object.object_id) for object in myruleInstance_query[0].source.all()]} - source')
                    rule_source = [str(object.object_id) for object in myruleInstance_query[0].source.all()]
                    if current_server in rule_source:
                        if not THISISPROD : print(f'found {current_server} in sources')
                        newClone.source.set([target_Servers_object])
                    else:
                        newClone.source.set(myruleInstance_query[0].source.all())
                    print(
                        f'checking {(current_server)} in {[(object.object_id) for object in myruleInstance_query[0].dest.all()]} - dest')
                    rule_dest = [str(object.object_id) for object in myruleInstance_query[0].dest.all()]
                    if current_server in rule_dest:
                        if not THISISPROD : print(f'found {current_server} in destination')
                        newClone.dest.set([target_Servers_object])
                    else:
                        newClone.dest.set(myruleInstance_query[0].dest.all())
                    #set the services to be identical
                    newClone.service.set(myruleInstance_query[0].service.all())
                    #save it!
                    newClone.save()
                    buildFirewallwebRules.delay([newClone.id])
                response_data['result'] = 'success'
                response_data['data'] = target_label
            except Exception as e:
                response_data['result'] = 'failed'
                response_data['data'] = str(e)

            return HttpResponse(json.dumps(response_data),
                                content_type="application/json")

@login_required
def mergeRuleInstances(request):
    '''this function takes rule list IDs selected in front end
    and merges their fields together, picking the one with the LOWEST ID as primary record
    reads the rest and adds their data to the primary record. it moves the firewall rules over too

    '''
    if request.method == 'POST':
        #in theory since transaction is atomic if we dont fail we can delete
        #if we fail we dont delete
        with transaction.atomic():
            rule_list_for_merging = request.POST.getlist('rule_list_ids[]')
            if len(rule_list_for_merging)>1:
                rule_list_for_merging.sort(reverse=False) #i want the lowest ID to be master
                if not THISISPROD : print(f'mergeRUleInstances received: {rule_list_for_merging}')
                master_rule_instance_id = rule_list_for_merging.pop() #get the first one out
                master_rule_instance = RuleInstance.objects.get(ruleinstance_primarykey = master_rule_instance_id)
                master_urls_list = []
                master_users_list = []
                master_application_list = []
                result_data = "Deleted: "
                for rule_instance in rule_list_for_merging:
                    myrule = RuleInstance.objects.get(ruleinstance_primarykey = rule_instance)
                    result_data += f"{myrule.id}, "
                    if not THISISPROD : print(f'loaded: {myrule}')
                    FirewallRule_query = FirewallRules.objects.filter(rule_instance = rule_instance)
                    for fwRule in FirewallRule_query:
                        #attach the Firewall Rule to Master Rule instance
                        fwRule.rule_instance = master_rule_instance
                        fwRule.save()
                    #put these into a master list so we can do SET and JOIN later
                    for source in myrule.source.all():
                        master_rule_instance.source.add(source)
                    for destination in myrule.dest.all():
                        master_rule_instance.dest.add(destination)
                    for service_thing in myrule.service.all():
                        master_rule_instance.service.add(service_thing)
                    master_urls_list.append(myrule.urls)
                    master_users_list.append(myrule.source_user)
                    master_application_list.append(myrule.application)
                    master_rule_instance.rule_description += myrule.rule_description
                #make it a SET so we remove dups, make it a list so we can join
                if not THISISPROD : print(f"Setting {master_rule_instance} url to {master_urls_list}")
                master_rule_instance.urls = ",".join(list(set(master_urls_list)))
                if not THISISPROD : print(f"Setting {master_rule_instance} source_user to {master_users_list}")
                master_rule_instance.source_user = ",".join(list(set(master_users_list)))
                if not THISISPROD : print(f"Setting {master_rule_instance} application to {master_application_list}")
                master_rule_instance.application = ",".join(list(set(master_application_list)))
                if not THISISPROD : print(f'saving primary record {master_rule_instance.id} -- {master_rule_instance.id}')
                master_rule_instance.save()
                #save is done, now we can delete
                for rule_instance in rule_list_for_merging:
                    myrule = RuleInstance.objects.get(ruleinstance_primarykey=rule_instance)
                    result_data += f"{myrule.id}, "
                    myrule.delete()
                response_data = {}
                response_data['result'] = 'success'
                response_data['data'] = result_data
                response_data['master_id'] = master_rule_instance.ruleinstance_primarykey
            else:
                response_data = {}
                response_data['result'] ='failed'
                response_data['data'] = 'You need to select at least 2 or more Rules'
            return HttpResponse(json.dumps(response_data),
                            content_type="application/json")

@login_required
def searchObjectResAPI(request):
    messages = []
    if request.method == 'POST':
        object_id = request.POST.get('current_server_id')
        if not THISISPROD : print(f'received object id {object_id}')
        ruleinstanceResults = RuleInstance.objects.filter(Q(source__object_id__in=[object_id]) | Q(dest__object_id__in=[object_id])).distinct()
        if not THISISPROD : print(f'sending back: {ruleinstanceResults}')
        messages.append({'type': 'warning', 'message': f'٩(ˊ〇ˋ*)و -- Found {len(ruleinstanceResults)} Rules'})
        return render(request, 'FirewallRules/searchandreplace_table_results.html',
                      {'messages': messages, 'ruleinstanceResults': ruleinstanceResults, })


@login_required
def searchAndReplaceView(request):
    messages = []
    if request.method == 'GET':
        action = {'action': 'create'}
        print(request.GET)
        form = replicateRulesForm()
        messages.append({'type': 'warning', 'message': '٩(ˊ〇ˋ*)و -- Making me work this early in the day?'})
        return render(request, 'FirewallRules/searchandreplacefirewallrules.html',
                      {'form': form, 'messages': messages, 'action': action, })


@login_required
def searchboxresult_geturl(request, searched=None):

    if request.method == 'GET' and searched:

        if searched:  # searched is not None
            result = {}
            firewall_interfaceResults = Firewall_Interface.objects.filter(
                Q(Firewall_Interface_name__contains=searched) | Q(Firewall_Interface_value__contains=searched))
            searched_number = 0
            #search for vlans
            try:
                # going to see if i can get a number out of searched
                searched_number = int(searched)
            except:
                # not a number booo
                searched_number = 0

            vlanResults = (Vlan.objects.filter(Q(vlan_name__icontains=searched)) |
                           Vlan.objects.filter(Q(vlan_number=searched_number)))
            # print(vlanResults)
            #search for rule instances
            ruleinstanceResults = RuleInstance.objects.filter(
                Q(id__icontains=searched) |
                Q(rule_name__icontains=searched) |
                Q(rule_description__icontains=searched) |
                Q(source__object_name__icontains=searched) |
                Q(source__object_value__icontains=searched) |
                Q(dest__object_name__icontains=searched) |
                Q(dest__object_value__icontains=searched) |
                Q(urls__icontains=searched) |
                Q(service__service_name__icontains=searched) |
                Q(service__service_dest_port__icontains=searched)).distinct()
            # objects, changes, services,
            objectResults = Object.objects.filter(Q(object_name__icontains=searched) |
                                                  Q(object_value__icontains=searched))
            changeResults = Change.objects.filter \
                (Q(Change_Number__icontains=searched) |
                 Q(Requests__in=ruleinstanceResults)).distinct()
            serviceResults = Service.objects.filter(Q(service_name__icontains=searched))
            return render(request, 'search.html',
                          {'searched': searched, 'firewall_interfaceResults': firewall_interfaceResults, 'vlanResults': vlanResults,
                           'ruleinstanceResults': ruleinstanceResults, 'objectResults': objectResults,
                           'changeResults': changeResults, 'serviceResults': serviceResults, })
    else:
            return render(request, 'search.html', {})




@login_required
def createRITM(request):
    username = request.user.username
    messages = []
    if request.method == 'GET':
        action = {'action': 'create'}
        if not THISISPROD : print(request.GET)
        form = RuleInstanceForm(initial={'application': 'any'})
        messages.append({'type': 'warning', 'message': '٩(ˊ〇ˋ*)و -- Making me work this early in the day?'})
        return render(request, 'FirewallRules/ruleinstance_form.html', {'form': form, 'messages': messages, 'action':action,})
    elif request.method == 'POST':
        if not THISISPROD : print(f'got request: {request.POST}')
        response_data = {}
        try:
            ruleinstance_primarykey = request.POST.get('ruleinstance_primarykey')
            id = request.POST.get('rule_id') #get ID
            action = request.POST.get('action')
            if not THISISPROD : print(f'got action: {action}')
            ourRuleInstance = None  # init var so it lives outside of if all the time
            if action == 'update':
                ourRuleInstance = RuleInstance.objects.get(ruleinstance_primarykey = ruleinstance_primarykey)
            else:
                if not THISISPROD : print(f'action was not update!')
                if RuleInstance.objects.filter(id=id).count() >0 :
                    if not THISISPROD : print(f'{request.POST.user} tried to create rule instance {id} which is duplicate!')
                    raise Exception("using duplicate ID")
                #i mean if i throw an exception we good right?
                ourRuleInstance = RuleInstance()
            rule_sources = request.POST.getlist('rule_sources[]')
            rule_destinations = request.POST.getlist('rule_destinations[]')
            #below im changing to STRING as the ajax call made sends me strings and i need a compare
            #get RFC_1918 ID
            RFC_1918_ID = str(Object.objects.get(object_name='RFC_1918').object_id)
            RFC_1918_CORE_ID = str(Object.objects.get(object_name='RFC_1918_CORE').object_id)
            #get object called ANY ID
            ANY_OBJECT_ID = str(Object.objects.get(object_name='any').object_id)
            #make it a set so we can do FUN stuff
            exception_set = set({RFC_1918_ID, ANY_OBJECT_ID, RFC_1918_CORE_ID})
            #check to see if the user was being dumb
            #they used a bad combo in BOTH source or Destination
            if bool(exception_set & set(rule_sources)) \
                    and bool(exception_set & set(rule_destinations)):
                raise DumbAssException
            ourRuleInstance.id = id
            ourRuleInstance.rule_name = request.POST.get('rule_name')
            ourRuleInstance.rule_description = request.POST.get('rule_description')
            ourRuleInstance.application = request.POST.get('rule_applications')
            ourRuleInstance.source_user = request.POST.get('rule_users')
            ourRuleInstance.urls = request.POST.get('rule_urls')
            if ourRuleInstance.urls:
                ourRuleInstance.catagory_name = id #set the cat name otherwise leave it None
            ourRuleInstance.start_date = request.POST.get('rule_start_date')
            ourRuleInstance.rule_duration = request.POST.get('rule_schedule')
            ourRuleInstance.db_created_by = request.user
            ourRuleInstance.save()
            ourRuleInstance.source.clear()
            ourRuleInstance.dest.clear()
            ourRuleInstance.service.clear()
            #now do all the relation stuff

            print(f'rulesources are: {rule_sources}')
            for source_id in rule_sources:
                if not THISISPROD : print(f'adding S {source_id}')
                ourRuleInstance.source.add(Object.objects.get(object_id = source_id))

            for destination_id in rule_destinations:
                if not THISISPROD : print(f'adding d {destination_id}')
                ourRuleInstance.dest.add(Object.objects.get(object_id = destination_id))
            rule_services = request.POST.getlist('rule_services[]')
            for service_id in rule_services:
                if not THISISPROD : print(f'adding Ser {service_id}')
                ourRuleInstance.service.add(Service.objects.get(service_id = service_id))
            ourRuleInstance.save()
            rule_list = []
            rule_list.append(ourRuleInstance.id)
            if not THISISPROD : print(f'sending {ourRuleInstance} to buildFirewallwebRules')

            task = buildFirewallwebRules.delay(rule_list)
            response_data['result'] = 'success'
            response_data['rule_id'] = ourRuleInstance.ruleinstance_primarykey
        except DumbAssException as e:
            print(e)
            response_data['result'] = 'failed'
            response_data['data'] = "Please Fix your rule. This source and destination combo is dangerous"
        except Exception as e:
            print(e)
            response_data['result'] = 'failed'
            response_data['data'] = 'Check the Logs you did something bad'
        return HttpResponse(json.dumps(response_data),
                            content_type = "application/json")

    else:
        response_data = {}
        response_data['message'] = "not Sure what you want?"
        return HttpResponse(json.dumps(response_data),
                            content_type="application/json")


@login_required
def updateRITM(request,pk):
    username = request.user.username
    messages = []
    if request.method == 'GET':
        print(request.GET)
        ourRuleInstance = get_object_or_404(RuleInstance, ruleinstance_primarykey=pk)
        form = RuleInstanceForm(instance = ourRuleInstance, data=request.POST or None)
        messages.append({'type': 'warning', 'message': '٩(ˊ〇ˋ*)و -- Loading a RITM hold yer horsey'})
        action = 'update'
        return render(request, 'FirewallRules/ruleinstance_form.html', {'form': form, 'messages': messages, 'action':action, 'ruleinstance_primarykey':pk })
    else:
        response_data = {}
        response_data['message'] = "not Sure what you want?"
        return HttpResponse(json.dumps(response_data),
                            content_type="application/json")





@login_required
def createCHANGE(request):
    messages = []
    form = ChangeInstanceFormv2()
    if request.method == 'GET':
        form = ChangeInstanceFormv2()
        messages.append({'type': 'success', 'message': 'Gonna talk to SNOW'})
        messages.append({'type': 'success', 'message': 'call Some APIs ☜(⌒▽⌒)☞'})
    else:
        if request.method == 'POST':
            #firewall rule change
            if request.POST.get('request_type') == 'FIREWALL_RULE':
                if not THISISPROD: print(f'adding a firewall rule change! {request.POST}')
                requests_in_fw_rule = request.POST.getlist('requests_in_change[]',request.POST.getlist('requests_in_change'))
                newSNOWChange = SNOWChange()
                # make a person from the requester's name; its used in the change tempalte
                Person_Name = Person_Name = '{first_name} {last_name}'.format(first_name=request.user.first_name,
                                                                              last_name=request.user.last_name)
                # we do a filter get a querylist so we can do the values() function on it and get a dictionary!
                mysnowTemplateDictionary = SNOWChangeTemplate.objects.filter(
                    short_description="Network: New Firewall Rule - Automated Delivery Tool"
                ).values()[0]

                requests_list = []
                for request_id in requests_in_fw_rule:
                    myrequest = RuleInstance.objects.get(ruleinstance_primarykey=request_id)
                    if myrequest.isInUse:
                        response_data = {}
                        response_data['result'] = "fail"
                        response_data['data'] = 'Some Selected RUles are still being processed by DB please Wait'
                        return HttpResponse(json.dumps(response_data),
                                            content_type="application/json")

                    requests_list.append(myrequest)
                ##add additional details to the SNOW ticket
                mysnowTemplateDictionary['description'] += ", ".join([ritm.id for ritm in requests_list])
                additional_change_description = ""  # init my var so ican do stuff in a loop to it
                for ruleinstance in requests_list:
                    # assumption is that we have a real rule instance i mean how else would it be here?
                    # add the following info to the description

                    additional_change_description += "*******\r\n" \
                                                     "\tRequest Number: {request_number}\r\n " \
                                                     "\t\tsource: {source_address} \r\n" \
                                                     "\t\tdestination: {destination_address} \r\n" \
                                                     "\t\tservices: {services}\r\n" \
                                                     "\t\tapplication: {application}\r\n" \
                                                     "\t\tURLs (if any): {url_list}\r\n" \
                                                     "\t\tSchedule (if any): {rule_duration}\r\n" \
                                                     "*******\r\n".format(
                        request_number=ruleinstance.id,
                        source_address=", ".join([source.object_name for source in ruleinstance.source.all()]),
                        destination_address=", ".join(
                            [destination.object_name for destination in ruleinstance.dest.all()]),
                        services=", ".join([service.service_name for service in ruleinstance.service.all()]),
                        application=ruleinstance.application,
                        url_list=ruleinstance.urls,
                        rule_duration=ruleinstance.rule_duration,
                    )
                    firewall_rule_list = FirewallRules.objects.filter(rule_instance=ruleinstance)
                    for rule in firewall_rule_list:
                        if rule.pushed_to_firewall:
                            # we are removing existing rules
                            additional_change_description += "\t=====\t=====\r\n\r\n" \
                                                             "The Following Rules will be **REMOVED** to the Firewall(s):\r\n" \
                                                             "\tFirewall: {firewall}\r\n" \
                                                             "\tSource_Zone: {source_zone}\r\n" \
                                                             "\tDestination_Zone: {dest_zone}\r\n" \
                                                             "\t=====\r\n\t=====\r\n".format(
                                firewall=rule.devicegroup,
                                source_zone=",".join([x.security_zone_name for x in rule.source_zone.all()]),
                                dest_zone=",".join([x.security_zone_name for x in rule.destination_zone.all()])
                            )
                        else:
                            # adding new rules
                            additional_change_description += "\t=====\r\n\t=====\r\n" \
                                                             "The Following Rules will be added to the Firewall(s)\r\n:" \
                                                             "\tFirewall: {firewall}\r\n" \
                                                             "\tSource_Zone: {source_zone}\r\n" \
                                                             "\tDestination_Zone: {dest_zone}\r\n" \
                                                             "\t=====\t=====\r\n".format(
                                firewall=rule.devicegroup,
                                source_zone=",".join([x.security_zone_name for x in rule.source_zone.all()]),
                                dest_zone=",".join([x.security_zone_name for x in rule.destination_zone.all()])
                            )
                mysnowTemplateDictionary['description'] += "\r\n" + additional_change_description

                mysnowTemplateDictionary['justification'] += ", ".join([ritm.id for ritm in requests_list])
                # need to get request number correctly .. in case of mulitple instance in a RITM there will be -xx numbering
                # belwo we make myrequest_ibe either the request if no "-" is in there, or the string stripping everything after dash
                myrequest_id = requests_list[0].id if "-" not in requests_list[0].id else requests_list[0].id[
                                                                                          :requests_list[0].id.find(
                                                                                              "-")]
                mysnowTemplateDictionary['u_request_item'] = myrequest_id  # set it to the RITM
                mysnowTemplateDictionary['short_description'] += f" - {myrequest_id}"
                mysnowTemplateDictionary['start_date'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                mysnowTemplateDictionary['end_date'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                mysnowTemplateDictionary['requested_by_date'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                mysnowTemplateDictionary['u_return_to_service_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                mysnowTemplateDictionary['u_change_participant_1'] = Person_Name
                mysnowTemplateDictionary['u_raci_1'] = 'Responsible'
                mysnowTemplateDictionary['u_implementer'] = Person_Name
                mysnowTemplateDictionary['u_support_person'] = Person_Name
                mysnowTemplateDictionary['requested_by'] = mysnowTemplateDictionary['u_technical_approvers']
                # do a check if we are in december add secondary approver for december
                # if datetime.today().month == 12:
                #     mysnowTemplateDictionary['u_technical_approvers'] += "," + mysnowTemplateDictionary['u_technical_approver_Freeze']
                if SERVICE_NOW_IS_SETUP :
                    change_number_result = newSNOWChange.buildStandardNetworkautomatedChange(getSNOW_Username(),
                                                                                         getSNOW_Password(),
                                                                                         Person_Name,
                                                                                         mysnowTemplateDictionary)
                # get the change SysID
                    change_sys_id = newSNOWChange.getChangeSYSID(change_number_result, getSNOW_Username(),
                                                             getSNOW_Password())
                    print("**change-sysid:")
                    print(change_sys_id)
                    # upload the file
                    file_name = "TandFapproval.docx"
                    file_location = relativePath + '/DataCenter/templates/TFapprovallist.docx'
                    result = newSNOWChange.attachdocxFileChanage(change_sys_id, getSNOW_Username(), getSNOW_Password(),
                                                                 file_name,
                                                                 file_location)
                    print("**attach doc policy result:")
                    print(result)
                    # now get the tasks lists from the Change:
                    chanage_task_list_dictionary = newSNOWChange.gettaskLIST(change_sys_id, getSNOW_Username(),
                                                                             getSNOW_Password())
                    print("**received follwing task list:")
                    print(chanage_task_list_dictionary)
                    # find the open task and close it its our validation task
                    for task in chanage_task_list_dictionary:
                        print('verifying task {task_name}'.format(task_name=task['number']))
                        if task['state'] == 'Open':
                            if (newSNOWChange.CloseThisTask(change_sys_id, task['sys_id'], getSNOW_Username(),
                                                            getSNOW_Password()) == True):
                                print('Closed Task {task_name}'.format(task_name=task['number']))
                else:
                    change_number_result = f'change-{Change.objects.all().count()+1}'

                ourChange = Change()
                ourChange.db_created_by = request.user
                ourChange.created_by = 'system - Mohan PROD'
                ourChange.Change_Number = change_number_result
                ourChange.save()  # save it so we can form relationship below

                for request in requests_list:
                    ourChange.Requests.add(request)
                # save the RITMs in there now
                ourChange.save()
                #     return redirect('CHANGELIST')

            response_data = {}
            response_data['result'] = "success"
            response_data['change_number'] = change_number_result
            response_data['change_id'] = ourChange.id
            return HttpResponse(json.dumps(response_data),
                                content_type="application/json")
    return render(request, 'FirewallRules/change_form.html', {'form': form, 'messages': messages, })


@login_required
def checksnowstatus(request,pk):
    response_data = {}
    if SERVICE_NOW_IS_SETUP :
        if request.method == "POST":
            change_id =request.POST.get('change_id')
            print(change_id)
            myChange = Change.objects.get(id=pk)
            change_number = myChange.Change_Number #get the change number
            #create a new SNOWChange handler thing
            mysnowChangeRecord = SNOWChange()
            change_sys_id = mysnowChangeRecord.getChangeSYSID(change_number, getSNOW_Username(), getSNOW_Password())
            #get the tasks
            task_dictionary_list = mysnowChangeRecord.gettaskLIST(change_sys_id, getSNOW_Username(), getSNOW_Password())
            change_approved = False
            for task in task_dictionary_list:
                print('checking tasks - in checksnowstatus - {task}'.format(task = task))
                if "Implement" in task['name']:
                    if task['state']=='Open':
                        #change_approved = True #change is clearly in approved state
                        response_data['status'] = 'Ready'
                    elif ("Implement" in task['name']) and (task['state'] == 'Closed') :
                        response_data['status'] = 'Closed'
                    else:
                        response_data['status'] = 'Not Ready'
    else:
        #no service now integration just return ready
        response_data['status'] = 'Ready'

    return HttpResponse(json.dumps(response_data), content_type ="application/json")


@login_required
def UpdateChange(request, pk):
    Change_Number = ""
    messages = []
    if request.method == 'GET':
        ourChange = get_object_or_404(Change, id=pk)
        form = ChangeInstancePushForm()
        messages.append({'type': 'success', 'message': 'Loading an approved(?) SNOW  Change'})
        messages.append({'type': 'success', 'message': 'Mohan is excited to work ☜(⌒▽⌒)☞'})
        form = ChangeInstancePushForm(instance=ourChange, data=request.POST or None)
        Change_Number = ourChange.Change_Number  # set teh change number
    else:
        # we have a post in theory?
        form = ChangeInstancePushForm(request.POST)
        if form.is_valid():
            ourChange = Change.objects.get(id=pk)
            ourChange.db_created_by = request.user
            ourChange.created_by = 'system - Mohan PROD'
            Change_Number = ourChange.Change_Number
            ourChange.save()  # save it so we can form relationship below
            Requests = ourChange.Requests.all()
            for request in Requests:
                #check the rules you are about to push or not push
                #there has to be a subset of firewall rules in each request that are FALSE for pushed_to_firewall
                #otherwise why are we pushing to firewall? and what are we pushing to firewall?
                if all([myrule.pushed_to_firewall for myrule in FirewallRules.objects.filter(rule_instance=request)]):
                    print(f'all() of FW rules: {all([myrule.pushed_to_firewall for myrule in FirewallRules.objects.filter(rule_instance=request)])} for {request}')
                    ourChange.change_status = 'ERROR'
                    ourChange.save()
                    return redirect('CHANGELIST')
                else:
                    # ok about to get serios?
                    pano_username = form.cleaned_data['pano_username']
                    pano_password = form.cleaned_data['pano_password']
                    ourChange.change_status = 'Not Started'
                    ourChange.save()
                    task = redirectedbuildRulefromDBDirect.delay(ourChange.id, ourChange.Change_Number, pano_username,
                                                                 pano_password)
                    # send the user to change detail view page
                    #         return redirect('CHANGEDETAILS', pk = ourChange.id)
                    return redirect('CHANGELIST')
        else:
            for key in form.errors.keys():
                if not THISISPROD : print(f'key: {key} - value:{form.errors[key]}')
                messages.append({'type': 'error', 'message': f' {form.errors[key][0]}'})
            if not THISISPROD : print(messages)

    return render(request, 'FirewallRules/change_form_push.html',
                  {'form': form, 'messages': messages, 'Change_Number': Change_Number})


@login_required
def getchangeLog(request,pk):
    if request.method == "GET":
        change_id = pk
        if not THISISPROD : print(change_id)
        myChange = Change.objects.get(id=pk)
        change_number = myChange.Change_Number #get the change number
        change_log = [] #initialize data variae so i canuse it after the try
        try:
            #open the file
            filename = relativePath+'/FirewallRules/logs/'+change_number+'.txt'
            if not THISISPROD : print(f'trying to open {filename}')
            with open(filename, "r") as myfile:
                change_log=myfile.readlines()
                change_log.reverse() #bottom up

        except:
          #print('no logs')
          change_log.append('no logs where found yet. If the Change is in started status wait a few seconds. If you are'
                            'still seeing this message after a 1 minute of the change starting, '
                            'open a ticket with your change ID/Number')

        #return HttpResponse(json.dumps(data), content_type ="application/json")
        return render(request, 'FirewallRules/change_detail_log.html', {'change_log': change_log, })


@login_required
def getPanoObjectDetail(request, pano_object_name):
    #view for only object for now lets see how it goes
    #make an api call
    #filter and find your object
    #retrun a view with your object
    #reuse a lot of code from reconcileDB
    mypano = panorestapi(panorama_server, pano_readonly_username, pano_readonly_password)
    myapikey = mypano.getapikey(panorama_server, pano_readonly_username, pano_readonly_password)
    object_json_data = getSingleobjectswithtag(myapikey, panorama_server,pano_object_name)
    my_object_dictionary = object_json_data.get('result', {}).get('entry',[])  # getme the entry dictionary stuff or return empty LIST
    matched_dictionary = {}
    messages = []
    if len(my_object_dictionary) > 0:
        for pano_object in my_object_dictionary:
            if (pano_object.get('@name') == pano_object_name):
                if not THISISPROD : print(f'matched and found : {pano_object}')
                matched_dictionary['name'] = pano_object.get('@name')
                matched_dictionary['value'] = pano_object.get('ip-netmask', pano_object.get('fqdn'))
                matched_dictionary['description'] = pano_object.get('description')
                if pano_object.get('ip-netmask'):
                    matched_dictionary['type'] = 'ip-netmask'
                elif pano_object.get('fqdn'):
                    matched_dictionary['type'] = 'fqdn'
                else :
                    matched_dictionary['type'] = 'unsupported'
                matched_dictionary['tag'] = pano_object.get('tag',{}).get('member')
                break
    else:
        messages.append({'type':'error', 'message':f'Mohan Failed in finding {pano_object_name} in {panorama_server}'})
    return render(request, 'FirewallRules/pano_object_detail.html',{'matched_dictionary':matched_dictionary,'messages':messages,})


@login_required
def pushObjectfromDBtoPanoama(request):
    # pano_object_name = request.GET.get('pano_object_name')
    object_id = request.POST.get('object_id')
    pano_username = request.POST.get('pano_username')
    pano_password = request.POST.get('pano_password')
    object_type = request.POST.get('object_type')
    if not THISISPROD : print(f'object_type : {object_type}')
    mypano = panorestapi(panorama_server, pano_username, pano_password)
    myapikey = mypano.apikey() #get pano API key
    if object_type == 'address-group':
        answer = pushStaticObjectGroupfromDBtoPano(myapikey, object_id)
    else:
        answer = pushObjectfromDBtoPano(myapikey, object_id)
    response_dictionary = {}
    if answer.get('@status') == 'success':
        response_dictionary['message'] = '200'

    else:
        response_dictionary['message'] = 'fail'
        if answer.get('@code') == '403':
            response_dictionary['reason']='Invalid Creds Holmes'
    response_dictionary['answer'] = answer
    return JsonResponse(response_dictionary)


@login_required
def getPanoValueObjectGroupNameView(request):
    # pano_object_name = request.GET.get('pano_object_name')
    pano_object_name = request.GET.get('object_name')
    mypano = panorestapi(panorama_server, pano_readonly_username, pano_readonly_password)
    myapikey = mypano.getapikey(panorama_server, pano_readonly_username, pano_readonly_password)
    object_json_data = getSingleobjectGroupswithtag(myapikey, panorama_server, pano_object_name)
    my_object_dictionary = object_json_data.get('result', {}).get('entry',
                                                                  [])  # getme the entry dictionary stuff or return empty LIST
    real_group_members = []
    matched_dictionary = {}
    messages = []
    temp_object = None
    if len(my_object_dictionary) > 0:
        for pano_object in my_object_dictionary:
            # if this works i either get the ip-netmask if it exists or the 'fqdn' value or None
            if (pano_object_name == pano_object.get('@name')): #get the name
                if not THISISPROD : print(f'found object group {pano_object_name}')
                group_member_list = pano_object.get('static', {}).get('member') #get the member list
                if group_member_list:
                    # we have a static object group - no fancy DAGs
                    matched_dictionary['object_name'] = pano_object.get('@name')
                    matched_dictionary['object_description'] = pano_object.get('description')
                    matched_dictionary['object_location'] = None
                    matched_dictionary['object_value'] = pano_object.get('@name')
                    matched_dictionary['object_type'] = 'address-group'
                    matched_dictionary['object_firewall_interface'] = None
                    temp_object = Object(**matched_dictionary)
                    try:
                       temp_object.save() #save so ave ID
                    except django.db.utils.IntegrityError:
                        temp_object = Object.objects.get(object_value = pano_object.get('@name'))


                    matched_dictionary['tags'] = pano_object.get('tag', {}).get('member', [])
                    messages.append({'type': 'Success',
                                     'message': f'i found something!'})

                    if matched_dictionary.get('tags'):
                        for tag_memeber in matched_dictionary.get('tags'):
                            t_tag_query = tag.objects.filter(tag_name = tag_memeber)
                            if len(t_tag_query)>0:
                                temp_object.tags.add(t_tag_query[0])
                            else:
                                t_tag = tag(tag_name = tag_memeber)
                                t_tag.save()
                                temp_object.tags.add(t_tag)
                    myAddressGroupQuery = AddressGroup.objects.filter(Object_in_DB = temp_object)
                    myAddressGroup = None
                    if len(myAddressGroupQuery) < 1:
                        myAddressGroup = AddressGroup()
                        myAddressGroup.save()
                        myAddressGroup.Object_in_DB = temp_object
                    else:
                        myAddressGroup = myAddressGroupQuery[0]
                    for member in group_member_list:
                        if not THISISPROD : print(f'found {member}')
                        myobjectquery = Object.objects.filter(object_name=member)
                        if not THISISPROD : print(f'and the eqv object is: {myobjectquery}')
                        if len(myobjectquery) > 0:
                            myobject = myobjectquery[0]
                        else:
                            mydupobjectquery = Duplicates.objects.filter(object_name=member)
                            if len(mydupobjectquery)>0:
                                myobject = mydupobjectquery[0].current_db_value
                                messages.append({'type': 'warning', 'message': f'added {myobject} to {pano_object_name} and I might have replaced org {member}'})
                        if not THISISPROD : print(f'insert member: {myobject}')
                        myAddressGroup.object_group_members.add(myobject)
                    temp_object.save()
                    myAddressGroup.save()

                else:
                    messages.append({'type': 'error', 'message': f'Mohan Failed in finding any STATIC members'})
    if temp_object:
        if not THISISPROD : print("found the object-group")
        return render(request, 'FirewallRules/object_form_holder_object_group.html', {'object': temp_object , 'messages':messages})
    else :
        return render(request, 'FirewallRules/object_form_holder_object_group.html', {'messages': messages})
    # matched_dictionary['messages'] = messages
    # return JsonResponse(matched_dictionary)


@login_required
def getPanoObjectGroupDetail(request, pano_object_name):
    #view for only object for now lets see how it goes
    #make an api call
    #filter and find your object
    #retrun a view with your object
    #reuse a lot of code from reconcileDB
    mypano = panorestapi(panorama_server, pano_readonly_username, pano_readonly_password)
    myapikey = mypano.getapikey(panorama_server, pano_readonly_username, pano_readonly_password)
    object_json_data = getSingleobjectGroupswithtag(myapikey, panorama_server,pano_object_name)
    my_object_dictionary = object_json_data.get('result', {}).get('entry',[])  # getme the entry dictionary stuff or return empty LIST
    matched_dictionary = {}
    messages = []
    if len(my_object_dictionary) > 0:
        for pano_object in my_object_dictionary:
            if (pano_object.get('@name') == pano_object_name):
                group_member_list = pano_object.get('static', {}).get('member', [])  # get the member list
                matched_dictionary['name'] = pano_object.get('@name')
                matched_dictionary['value'] = ",".join(group_member_list)
                matched_dictionary['description'] = pano_object.get('description')
                matched_dictionary['type'] = 'address-group'
                matched_dictionary['tag'] = pano_object.get('tag',{}).get('member')
                member_list = []
                for member in group_member_list:
                    myobjectquery = Object.objects.filter(object_name=member)
                    if len(myobjectquery) > 0:
                        myobject = myobjectquery[0]
                        member_list.append(myobject)
                    else:
                        mydupobjectquery = Duplicates.objects.filter(object_name=member)
                        if len(mydupobjectquery) > 0:
                            myobject = mydupobjectquery[0].current_db_value
                            member_list.append(myobject)
                            messages.append({'type': 'warning',
                                             'message': f'Mohan replaced {member} with its DB value {myobject.object_name}'})
                        else:
                            messages.append({'type': 'error',
                                             'message': f"Mohan Failed in finding {member} in {panorama_server} as part of {pano_object.get('@name')}"})
                matched_dictionary['members'] = member_list
                break
    else:
        messages.append({'type':'error', 'message':f'Mohan Failed in finding {pano_object_name} in {panorama_server}'})
    return render(request, 'FirewallRules/pano_object_detail.html',{'matched_dictionary':matched_dictionary,'messages':messages,})


@login_required
def vlanTableView(request):
    '''
    first initial request to load the page
    load the current available datacenters and send them over to tempalte
    template is going to make pretty buttuons out of it!
    '''
    if request.method == 'GET':
        data_center_query = DataCenter.objects.all()
        return render(request, 'DataCenter/vlan_table_detail.html', {'data_center_query' : data_center_query,})

@login_required
def AddressGroupViewDetail(request,pk):
    '''
    first initial request to load the page
    load the current available datacenters and send them over to tempalte
    template is going to make pretty buttuons out of it!
    '''
    if request.method == 'GET':
        request.GET.get('name')
        object = get_object_or_404(Object, object_id=pk)
        myAddressGroup = AddressGroup.objects.filter(Object_in_DB = object)
        myAddressGroup = myAddressGroup[0] if len(myAddressGroup)> 0 else None
        return render(request, 'FirewallRules/address_group_detail_view.html', {'object' : myAddressGroup,})



@login_required
def vlanTableViewDataCenter(request,data_center_id):
    data_center_instance = DataCenter.objects.get(id = data_center_id)
    vlan_list = Vlan.objects.all().filter(vlan_datacenter = data_center_instance)
    vlan_dictionary_list = []
    #check to see if there is a firewall inerface attached if yes get the ip address
    for vlan in vlan_list:
        ip_address = 0
        firewall_interface_query = Firewall_Interface.objects.filter(Firewall_Interface_vlan = vlan)
        if len(firewall_interface_query)>0:
            ip_address = firewall_interface_query[0].Firewall_Interface_value
        vlan_dictionary_list.append({'vlan_number': vlan.vlan_number,
                                           'ip_address': ip_address,
                                           'vlan_name': vlan.vlan_name})
        vlan_dictionary_list_count = len(vlan_dictionary_list)
    return render(request, 'DataCenter/vlan_table_detail_table.html',
                  {'vlan_dictionary_list':vlan_dictionary_list,
                   'data_center_instance':data_center_instance,
                   'vlan_dictionary_list_count':vlan_dictionary_list_count})


@login_required
def guessObjectLocation(request):
    import socket
    if request.method == 'POST':
        object_value = request.POST.get('object_value')
        if request.POST.get('object_type') == 'fqdn':
            try:
                object_value = (socket.gethostbyname(object_value))
            except socket.gaierror:
                if not THISISPROD : print(f'Unable to resolve {object_value} skipping invalid FQDN')
                location_response={}
                location_response['error'] = 'invalid FQDN unable to resolve!'
                return HttpResponse(json.dumps(location_response), content_type='application/json')


        if not THISISPROD : print(f'object_value is : {object_value}')
        location_dictionary_parent = Location.objects.filter(location_type='Parent')
        location_dictionary_child = Location.objects.filter(location_type='Child')
        location_response = findObjectLocation(object_ip=object_value,
                                               location_dictionary_parent= location_dictionary_parent,
                                               location_dictionary_child = location_dictionary_child)
        if not THISISPROD : print(location_response)
        return HttpResponse(json.dumps(location_response), content_type='application/json')
    pass






@login_required
def createAddressGroup(request):
    action = 'CREATE'
    messages = []
    results = []
    if request.method == 'GET':
        if not THISISPROD : print(request.GET)
        form = CreateAddressGroupForm(initial={'hidden_value': 0})
        form.hidden_value = 0
        if not THISISPROD : print(f' hidden value = {form.hidden_value}')
        messages.append({'type': 'success', 'message': f'Hi, Mohan Build Object with you?'})
        return render(request, 'FirewallRules/address_group_form.html', {'form': form, 'messages': messages,'action':action, })
    else:
        if request.method == 'POST':
            response = {}
            object_name = request.POST.get('object_name')
            object_group_members_ids = request.POST.getlist('object_group_members[]')
            object_group_members= []
            for id in object_group_members_ids:
                object_group_members.append(Object.objects.get(object_id = id))
            my_Object_in_DB_query = Object.objects.filter(object_name = object_name)
            if len(my_Object_in_DB_query) > 0:
                if request.POST.get('action') !='UPDATE':
                    #someone is using the CREATE link/form and using duplicate values
                    response['result'] = 'failed'
                    response['data'] = 'Duplicate Address Group name not Allowed. Either use Update or Change the Name'
                    return HttpResponse(json.dumps(response), content_type='application/json')
                else:
                    #updating here not creating
                    my_Object_in_DB = my_Object_in_DB_query[0]
                    myAddressGroup_query = AddressGroup.objects.filter(Object_in_DB=my_Object_in_DB)
                    myAddressGroup= myAddressGroup_query[0]
                    myAddressGroup.object_group_members.set(object_group_members)
                    myAddressGroup.Object_in_DB = my_Object_in_DB
                    myAddressGroup.save()
                    response['result'] = 'success'
                    response['data'] = f'We made an Object Group called {object_name}'
                    response['object_id'] = my_Object_in_DB.object_id  # send back OBJ in database
                    return HttpResponse(json.dumps(response), content_type='application/json')
            #creating not updating
            else:
                my_Object_in_DB = Object()
                my_Object_in_DB.object_name = object_name
                my_Object_in_DB.object_type = 'address-group'
                my_Object_in_DB.object_description = object_name
                my_Object_in_DB.object_value = hash(",".join([object.object_name for object in object_group_members]))
                my_Object_in_DB.save()
                myAddressGroup = AddressGroup()
                myAddressGroup.save()
                myAddressGroup.object_group_members.set(object_group_members)
                myAddressGroup.Object_in_DB = my_Object_in_DB
                myAddressGroup.save()
                response['result'] = 'success'
                response['data'] = f'We made an Object Group called {object_name}'
                response['object_id'] = my_Object_in_DB.object_id #send back OBJ in database
                return HttpResponse(json.dumps(response), content_type='application/json')







@login_required
def createObject(request):
    action = 'CREATE'
    messages = []
    results = []
    if request.method == 'GET':
        if not THISISPROD : print(request.GET)
        form = CreateObjectForm(initial={'hidden_value': 0})
        form.hidden_value = 0
        if not THISISPROD : print(f' hidden value = {form.hidden_value}')
        messages.append({'type': 'success', 'message': f'Hi, Mohan Build Object with you?'})
        return render(request, 'FirewallRules/object_form.html', {'form': form, 'messages': messages, })
    else:
        if request.method == 'POST':
            form = CreateObjectForm(request.POST)
            # first time form being submitted.
            # sendSObjectgetObject, getLocationsDictv2
            if (form.is_valid()):
                myobject = Object()
                # 'object_name', 'object_type', 'object_value', 'object_location', 'object_fw', 'object_group_members', 'object_description', 'object_tag',
                myobject.object_name = form.cleaned_data['object_name']
                myobject.object_type = form.cleaned_data['object_type']
                object_value = form.cleaned_data['object_value']
                #if we have an ip address (not fqdn or adress-group) and it has no / then add /32 to make it a host
                if (object_value.find("/") < 0) and (form.cleaned_data['object_type'] == 'ip-netmask'):
                    object_value += "/32"
                myobject.object_value = object_value
                myobject.object_description = form.cleaned_data['object_description']

                myobject.object_location = form.cleaned_data['object_location']
                # if its on a FW might as well set that information up properly now

                if form.cleaned_data['object_location'] == 'FW':
                    location_dictionary_parent = Location.objects.filter(location_type='Parent')
                    location_dictionary_child = Location.objects.filter(location_type='Child')
                    location_response = findObjectLocation(object_ip=myobject.object_value,
                                                           location_dictionary_parent=location_dictionary_parent,
                                                           location_dictionary_child=location_dictionary_child)


                    myobject.object_firewall_interface = \
                    Firewall_Interface.objects.get(Firewall_Interface_id=location_response.get('interface_id'))
                    myobject.save()
                if myobject.object_type == 'address-group':

                    myaddressGroup = AddressGroup()
                    myaddressGroup.save()
                    myaddressGroup.Object_in_DB = myobject
                    myaddressGroup.object_group_members.set(form.cleaned_data[
                                                          'object_group_members'])
                    # reset the value if anythign was typed to be object_name to enforce uniquness
                    myobject.object_value = myobject.object_name
                    myaddressGroup.save()
                    myobject.save()
                    # set the object group members
                    myobject.object_group_members.set(form.cleaned_data[
                                                          'object_group_members'])  # many to many in case there was anything here before?
                else:
                    # its not an address group so in theory we shouldn't have values in object_group_members
                    myobject.save()
                    myobject.object_group_members.clear()

                for tag in form.cleaned_data['tags']:
                    myobject.tags.add(tag)

                # save the object?
                myobject.save()
                primary_key = Object.objects.get(object_name=myobject.object_name).object_id # there should be only one here
                return redirect('OBJECTDETAILS', pk=primary_key)
            else:
                if not THISISPROD : print(form.errors)
                for key in form.errors.keys():
                    if not THISISPROD : print(f'key: {key} - value:{form.errors[key]}')
                    messages.append({'type': 'error', 'message': f' {form.errors[key][0]}'})
                if not THISISPROD : print(messages)
                return render(request, 'FirewallRules/object_form.html',
                              {'form': form, 'messages': messages, 'action': action, })


@login_required
def updateOBJECT(request, pk):
    action = 'UPDATE'
    messages = []
    results = []
    myobject = get_object_or_404(Object, object_id=pk)
    form = None
    if myobject.object_type == 'address-group':
        address_group = AddressGroup.objects.filter(Object_in_DB = myobject)
        if len(address_group) > 0 :
            address_group = address_group[0]
            if not THISISPROD : print(f'found {address_group} in DB')
        else:
            address_group = None
        form = CreateAddressGroupForm(instance=address_group,
                                      data=request.POST or None, initial={'object_name': myobject.object_name})
        return render(request, 'FirewallRules/address_group_form.html',
                      {'form': form, 'messages': messages, 'action': action,'address_group_name' : myobject.object_name})
    else:
        form = CreateObjectForm(instance=myobject, data=request.POST or None)
    form.form_action = 'UPDATE'
    # print(f'view - object_group_members: { myobject.object_group_members.all() }')
    if request.method == 'GET':
        messages.append({'type': 'success', 'message': f'Loaded {myobject}'})
    if request.method == 'POST':
        if (form.is_valid()):
            # myobject = form.save(commit = False) #I dont need this i've already queried the DB above
            # 'object_name', 'object_type', 'object_value', 'object_location', 'object_fw', 'object_group_members', 'object_description', 'object_tag',
            myobject.object_name = form.cleaned_data['object_name']
            myobject.object_type = form.cleaned_data['object_type']
            object_value = form.cleaned_data['object_value']
            # if we have an ip address (not fqdn or adress-group) and it has no / then add /32 to make it a host
            if (object_value.find("/") < 0) and (form.cleaned_data['object_type'] == 'ip-netmask'):
                object_value += "/32"
            myobject.object_value = object_value
            myobject.object_description = form.cleaned_data['object_description']
            # myobject.object_tag = form.cleaned_data['tags']
            myobject.object_location = form.cleaned_data['object_location']
            # if its on a FW might as well set that information up properly now
            if not THISISPROD : print(f'form action is : {form.cleaned_data["form_action"]}')
            if form.cleaned_data['object_location'] == 'FW':
                location_dictionary_parent = Location.objects.filter(location_type='Parent')
                location_dictionary_child = Location.objects.filter(location_type='Child')
                location_response = findObjectLocation(object_ip=myobject.object_value,
                                                       location_dictionary_parent=location_dictionary_parent,
                                                       location_dictionary_child=location_dictionary_child)

                myobject.object_firewall_interface = \
                    Firewall_Interface.objects.get(Firewall_Interface_id=location_response.get('interface_id'))
                myobject.save()

            if myobject.object_type == 'address-group':
                # reset the value if anythign was typed to be object_name to enforce uniquness
                myaddressGroupQuery = AddressGroup.objects.filter(Object_in_DB = myobject)
                if len(myaddressGroupQuery) > 0:
                    myaddressGroup = myaddressGroupQuery[0]
                    myaddressGroup.object_group_members.set(form.cleaned_data['object_group_members'])
                    myaddressGroup.save()
                else:
                    myaddressGroup = AddressGroup()
                    myaddressGroup.save()
                    myaddressGroup.Object_in_DB = myobject
                    myaddressGroup.object_group_members.set(form.cleaned_data['object_group_members'])
                    myaddressGroup.save()
                myobject.object_value = myobject.object_name
                myobject.save()
                # set the object group members
                for obj in form.cleaned_data['object_group_members']:
                    myobject.object_group_members.add(obj)  # many to many in case there was anything here before?
            else:
                # its not an address group so in theory we shouldn't have values in object_group_members
                myobject.save()
                myobject.object_group_members.clear()

            tags_list = form.cleaned_data['tags']
            if len(tags_list) > 0:
                for tag in tags_list:
                    myobject.tags.add(tag)

            # save the object?
            myobject.save()
            messages.append({'type': 'success', 'message': f'Updated {myobject} ¯\_(ツ)_/¯'})
        else:
            print(form.errors)
            for key in form.errors.keys():
                if not THISISPROD : print(f'key: {key} - value:{form.errors[key]}')
                messages.append({'type': 'error', 'message': f' {form.errors[key][0]}'})
            print(messages)
    return render(request, 'FirewallRules/object_form.html', {'form': form, 'messages': messages, 'action': action, })


@login_required
def createSERVICE(request):
    action = 'CREATE'
    messages = []
    results = []
    if request.method == 'GET':
        print(request.GET)
        form = ServiceInstanceForm()
        messages.append({'type': 'success', 'message': f'Hi, Mohan Build Service with you?'})
        return render(request, 'FirewallRules/service_form.html', {'form': form, 'messages': messages, })
    else:
        if request.method == 'POST':
            form = ServiceInstanceForm(request.POST)
            # first time form being submitted.

            if (form.is_valid()):
                myService = Service()
                myService.service_name = form.cleaned_data['service_name']
                myService.service_protocol = form.cleaned_data['service_protocol']
                myService.service_dest_port = form.cleaned_data['service_dest_port']
                myService.service_description = form.cleaned_data['service_description']
                myService.save()
                myService.service_tag.set(form.cleaned_data['service_tag'])
                myService.save()

                # save the object?
                myService.save()
                primary_key = Service.objects.filter(service_name=myService.service_name)[
                    0].service_id  # there should be only one here
                return redirect('SERVICEDETAILS', pk=primary_key)
            else:
                if not THISISPROD : print(form.errors)
                for key in form.errors.keys():
                    if not THISISPROD : print(f'key: {key} - value:{form.errors[key]}')
                    messages.append({'type': 'error', 'message': f' {form.errors[key][0]}'})
                if not THISISPROD : print(messages)
                return render(request, 'FirewallRules/service_form.html',
                              {'form': form, 'messages': messages, 'action': action, })


@login_required
def updateSERVICE(request, pk):
    action = 'UPDATE'
    messages = []
    results = []
    myService = get_object_or_404(Service, service_id=pk)
    form = ServiceInstanceForm(instance=myService, data=request.POST or None)

    if request.method == 'GET':
        messages.append({'type': 'success', 'message': f'Loaded {myService}'})
        if '-DST' not in myService.service_name:
            messages.append({'type': 'error',
                             'message': f'DO NOT ATTEMPT TO EDIT THIS OBJECT - DO NOT SAVE GET OUT NOW - SPECIAL OBJECT DETECTED'})
    if request.method == 'POST':
        if (form.is_valid()):
            myService = form.save(commit=False)
            # 'object_name', 'object_type', 'object_value', 'object_location', 'object_fw', 'object_group_members', 'object_description', 'object_tag',
            myService.service_name = form.cleaned_data['service_name']
            myService.service_protocol = form.cleaned_data['service_protocol']
            myService.service_dest_port = form.cleaned_data['service_dest_port']
            myService.service_description = form.cleaned_data['service_description']
            myService.service_tag.set(form.cleaned_data['service_tag'])
            myService.save()
            messages.append({'type': 'success', 'message': f'Updated {myService} ¯\_(ツ)_/¯'})
        else:
            if not THISISPROD : print(form.errors)
            for key in form.errors.keys():
                if not THISISPROD : print(f'key: {key} - value:{form.errors[key]}')
                messages.append({'type': 'error', 'message': f' {form.errors[key][0]}'})
            if not THISISPROD : print(messages)
    return render(request, 'FirewallRules/service_form.html', {'form': form, 'messages': messages, 'action': action, })

@login_required
def searchPanoLogsupto5000SingleAddress(request):
    messages = []
    if request.method == 'GET':
        form = CheckTheLogsForm5000EntriesSingleAddress()
        messages.append({'type': 'success', 'message': 'loading a new form for searching'})
        messages.append({'type': 'success', 'message': 'Mohan is excited to dig ☜(⌒▽⌒)☞'})
    else:
        # we have a post here
        form = CheckTheLogsForm5000EntriesSingleAddress(request.POST)
        if form.is_valid():
            # I need to call the function below, i need celery to do it.. and i also need to keep track of the object some how ..
            source_address = form.cleaned_data['source_address']


            # obtain an API key:
            myAPIKey = panorestapi(panorama_server, pano_readonly_username, pano_readonly_password).apikey()
            if not THISISPROD : print(myAPIKey)

            # lets create a new task record?
            mytask = task()
            mytask.task_search_term = '(addr in {source_address})'.format(source_address=source_address)

            if not THISISPROD : print(mytask.task_search_term)
            mytask.job_id = get_job_id_SrcDstLogsv2(makestringhttpsafe(mytask.task_search_term), myAPIKey, 5000)
            mytask.db_created_by = request.user
            mytask.task_description = 'searchPanoLogs'
            mytask.myAPIKey = myAPIKey
            mytask.task_status = 'Not Started'
            mytask.save()
            myjob = get_job_data_fromPanorama.delay(myAPIKey, mytask.job_id, mytask.task_id)
            return redirect('VIEWMYTASKSLISTS')
        else:
            for key in form.errors.keys():
                if not THISISPROD : print(f'key: {key} - value:{form.errors[key]}')
                messages.append({'type': 'error', 'message': f' {form.errors[key][0]}'})
            print(messages)
    return render(request, 'FirewallRules/singleSourceSearchn5k.html', {'form': form, 'messages': messages, })

@login_required
def searchPanoLogs(request):
    messages = []
    if request.method == 'GET':
      form = CheckTheLogsForm(initial={'port_number': '0'})
      messages.append({'type': 'success', 'message': 'loading a new form for searching'})
      messages.append({'type': 'success', 'message': 'Mohan is excited to dig ☜(⌒▽⌒)☞'})
    else:
      #we have a post here
      form = CheckTheLogsForm(request.POST)
      if form.is_valid():
         #I need to call the function below, i need celery to do it.. and i also need to keep track of the object some how ..
         source_address = form.cleaned_data['source_address']
         destination_address= form.cleaned_data['destination_address']
         user_input_port_number =  form.cleaned_data['port_number']
         start_date = form.cleaned_data['start_date']
         if not THISISPROD : print(f'FORM DATA IS : {start_date}')
         port_number = ""
         #thank you Richard G - sanitizing Code for only integers now
         for char in user_input_port_number:
            if char.isdigit():
                port_number = port_number + char
         if port_number == "": #we ended up with no numbers (bad user ?)
             port_number = '0'

         #obtain an API key:
         myAPIKey = panorestapi(panorama_server, pano_readonly_username, pano_readonly_password).apikey()
         print(myAPIKey)
         #getSrcDstLogs(username, password, source, destination, port, myAPIKey)
         #lets create a new task record?
         mytask = task()
         if port_number is '0':
             mytask.task_search_term = f'(addr.src in {source_address}) and (addr.dst in {destination_address})'
         else:
             mytask.task_search_term = f'(addr.src in {source_address}) and (addr.dst in {destination_address}) and (port eq {port_number})'
         if start_date :
             date_string = f" and (time_generated geq '{start_date} 00:00:00')"
             mytask.task_search_term = mytask.task_search_term + date_string


         print(mytask.task_search_term)
         mytask.job_id = get_job_id_SrcDstLogsv2(makestringhttpsafe(mytask.task_search_term), myAPIKey,number_of_logs=300)
         mytask.db_created_by = request.user
         mytask.task_description = 'searchPanoLogs'
         mytask.myAPIKey = myAPIKey
         mytask.task_status = 'Not Started'
         mytask.save()
         myjob = get_job_data_fromPanorama.delay(myAPIKey, mytask.job_id, mytask.task_id)
         return redirect('VIEWMYTASKSLISTS')
      else:
           for key in form.errors.keys():
               if not THISISPROD : print(f'key: { key } - value:{ form.errors[key] }')
               messages.append({'type':'error', 'message':f' { form.errors[key][0] }'})
           print(messages)
    return render(request, 'FirewallRules/searchSrcDst_form.html',{'form':form,'messages':messages,})


@login_required
def MyTasksList(request):
    # returns the users requests
    mytaskList = task.objects.filter(db_created_by=request.user).order_by('-creation_date')
    return render(request, 'FirewallRules/tasks_list.html', {'mytaskList': mytaskList})


@login_required
def MyTaskDetails(request, pk):
    # returns the users requests
    messages = []
    mytask = task.objects.filter(task_id=pk)[0]
    if mytask.task_status != 'Completed':
        # send the user back to the task list
        mytaskList = task.objects.filter(db_created_by=request.user)
        messages.append({'type': 'warning', 'message': 'Not sure if you noticed but im not done yet'})
        return render(request, 'FirewallRules/tasks_list.html', {'mytaskList': mytaskList, 'messages': messages})
    else:

        if mytask.task_description == 'searchPanoLogs':
            return MyTaskDetailssearchPanoLogs(request, pk)
        if mytask.task_description == 'Firewall Rule Check':
            return MyTaskDetailFirewallflow(request, pk)


@login_required
def MyTaskDetailFirewallflow(request, pk):
    # Todo writeetter code?
    messages = []
    messages.append({'type': 'warning', 'message': 'The answers may shock you!'})

    mytask = task.objects.filter(task_id=pk)[0]
    if mytask.task_status != 'Completed':
        # send the user back to the task list
        mytaskList = task.objects.filter(db_created_by=request.user).order_by('-creation_date')
        messages.append({'type': 'warning', 'message': 'Not sure if you noticed but im not done yet'})
        return render(request, 'FirewallRules/tasks_list.html', {'mytaskList': mytaskList, 'messages': messages})
    else:
        results = json.loads(mytask.task_results)
        messages.append({'type': 'success', 'message': 'found something'})
        return render(request, 'FirewallRules/testFirewallFlow_details.html',
                      {'results': results, 'mytask': mytask, 'messages': messages})




@login_required
def MyTaskDetailssearchPanoLogs(request, pk):
    # returns the users requests
    messages = []
    mytask = task.objects.filter(task_id=pk)[0]
    if mytask.task_status != 'Completed':
        # send the user back to the task list
        mytaskList = task.objects.filter(db_created_by=request.user)
        messages.append({'type': 'warning', 'message': 'Not sure if you noticed but im not done yet'})
        return render(request, 'FirewallRules/tasks_list.html', {'mytaskList': mytaskList, 'messages': messages})

    root = ET.fromstring(mytask.task_results)
    result_list = []
    for entry in root.iterfind('result/log/logs/entry'):
        tempdictionary = {}
        tempdictionary['time_generated'] = entry.find('time_generated').text
        tempdictionary['src'] = entry.find('src').text
        tempdictionary['dst'] = entry.find('dst').text
        tempdictionary['rule'] = entry.find('rule').text
        tempdictionary['from'] = entry.find('from').text
        tempdictionary['to'] = entry.find('to').text
        tempdictionary['dport'] = entry.find('dport').text
        tempdictionary['proto'] = entry.find('proto').text
        tempdictionary['action'] = entry.find('action').text
        tempdictionary['session_end_reason'] = entry.find('session_end_reason').text
        tempdictionary['action_source'] = entry.find('action_source').text
        tempdictionary['app'] = entry.find('app').text
        tempdictionary['device_name'] = entry.find('device_name').text
        result_list.append(tempdictionary)
    return render(request, 'FirewallRules/PanoSearch_detail.html',
                  {'mytask': mytask, 'result_list': result_list, 'messages': messages})


@login_required
def ReRunSearchPanoLogs(request, pk):
    messages = []
    mytaskquery = task.objects.filter(task_id=pk)
    if len(mytaskquery) > 0:
        mytask = mytaskquery[0]
        # obtain an API key:
        myAPIKey = panorestapi(panorama_server, pano_readonly_username, pano_readonly_password).apikey()
        print(myAPIKey)
        # getSrcDstLogs(username, password, source, destination, port, myAPIKey)
        # lets create a new task record?
        print(mytask.task_search_term)
        mytask.job_id = get_job_id_SrcDstLogsv2(makestringhttpsafe(mytask.task_search_term),
                                                myAPIKey,
                                                number_of_logs=2500)
        mytask.db_created_by = request.user
        mytask.task_description = 'searchPanoLogs'
        mytask.myAPIKey = myAPIKey
        mytask.task_status = 'Not Started'
        mytask.save()
        myjob = get_job_data_fromPanorama.delay(myAPIKey, mytask.job_id, mytask.task_id)
        return redirect('VIEWMYTASKSLISTS')

@login_required
def testFirewallFlow(request):
    messages = []
    if request.method == 'POST':
        form = checkFirewallFlow(request.POST)
        if form.is_valid():
            newtask = task() #createa  enw task
            newtask.task_description = 'Firewall Rule Check'
            newtask.job_id = '0'
            newtask.db_created_by = request.user
            newtask.myAPIKey = None
            newtask.task_status= 'Not Started'
            newtask.task_search_term = None
            newtask.tasks_results = ""
            newtask.save()
            newtask_id = newtask.task_id
            print(form)
            pano_username = form.cleaned_data['pano_username']
            pano_password = form.cleaned_data['pano_password']
            test_source_Addresss = Object.objects.get(object_id=form.cleaned_data['source'])
            test_destination_address = Object.objects.get(object_id=form.cleaned_data['dest'])
            test_service = Service.objects.get(service_id=form.cleaned_data['service'])

            newtask.task_search_term = "{source_ip} go to {dest_ip} on service {service}".\
                format(source_ip = test_source_Addresss,
                       dest_ip = test_destination_address,
                       service = test_service)
            newtask.save()
            testFirewallRules.delay(username = pano_username,
                              password = pano_password,
                              task_id = newtask_id,
                              source_address_id = test_source_Addresss.object_id,
                              destination_address_id = test_destination_address.object_id,
                              service_id = test_service.service_id)
            return redirect('VIEWMYTASKSLISTS')
        else:
            form = checkFirewallFlow(request.POST)
            messages.append({'type': 'error', 'message': 'I wish this form had beter validation'})
    else:
        form = checkFirewallFlow()
        messages.append({'type': 'success', 'message': 'loading a new form for searching'})
        messages.append({'type': 'success', 'message': 'Mohan is excited to dig ☜(⌒▽⌒)☞'})
    return render(request, 'FirewallRules/testFirewallFlow_form.html', {'form': form, 'messages': messages, })


@login_required
def getAWSRoutingChange(request):
       return redirect('VIEWMYTASKSLISTS')




@login_required
def getPanoValueObjectNameAPI(request):
    pano_object_name = request.GET.get('pano_object_name')
    mypano = panorestapi(panorama_server, pano_readonly_username, pano_readonly_password)
    myapikey = mypano.getapikey(panorama_server, pano_readonly_username, pano_readonly_password)
    object_json_data = getallobjectswithtag(myapikey, panorama_server)
    my_object_dictionary = object_json_data.get('result', {}).get('entry',
                                                                  [])  # getme the entry dictionary stuff or return empty LIST
    matched_dictionary = {}
    messages = []
    if len(my_object_dictionary) > 0:
        for pano_object in my_object_dictionary:
            if (pano_object.get('@name') == pano_object_name):
                matched_dictionary['name'] = pano_object.get('@name')
                matched_dictionary['value'] = pano_object.get('ip-netmask', pano_object.get('fqdn'))
                matched_dictionary['description'] = pano_object.get('description')
                if pano_object.get('ip-netmask'):
                    matched_dictionary['type'] = 'ip-netmask'
                elif pano_object.get('fqdn'):
                    matched_dictionary['type'] = 'fqdn'
                else:
                    matched_dictionary['type'] = 'unsupported'
                # matched_dictionary['tag'] = pano_object.get('tag', {}).get('member')
                pano_tag_list = pano_object.get('tag', {}).get('member', [])
                tag_list = []
                #check my tags
                for pano_tag in pano_tag_list:
                    pano_tag_db_query = tag.objects.filter(tag_name = pano_tag)
                    if len(pano_tag_db_query)>0 :
                        tag_list.append(pano_tag_db_query[0])
                    else :
                        newtag = tag(tag_name = pano_tag)
                        tag_list.append(newtag)
                matched_dictionary['tag_id'] = [x.id for x in tag_list]
                matched_dictionary['tag_name'] = [x.tag_name for x in tag_list]
                matched_dictionary['tag_dictionary'] = dict(zip(matched_dictionary['tag_id'],matched_dictionary['tag_name']))
                if not THISISPROD : print(f'matched_dictionary is {matched_dictionary}')

                break
    else:
        messages.append(
            {'type': 'error', 'message': f'Mohan Failed in finding {pano_object_name} in {panorama_server}'})

    matched_dictionary['messages'] = messages
    return JsonResponse(matched_dictionary)



@login_required
def UpdateVlanDatabaseFromSwitch(request):
    '''
    this function will be used to process
    password = getpass()
    username = 'psabouri'
    hostname = 'bram-leaf-r13-1'
    connection=sendAPIRequeststoAristaSwitch(host,username,password)
    vlan_data_center = DataCenter.objects.get(datacenter_Name='Brampton')
    addVlansToDatabase(connection,vlan_data_center )

    '''
    messages = [] #create my message queue this is pretty colours
    if request.method == 'GET':

        form = UpdateVlanDatabaseFromSwitchForm()
        messages.append({'type': 'success', 'message': 'Synchronizing? was someone making Manual changes?'})
        messages.append({'type': 'success', 'message': 'Lets find out together! 乁( ⁰͡ Ĺ̯ ⁰͡ ) ㄏ'})

    else:
        # we have a post in theory?
        form = UpdateVlanDatabaseFromSwitchForm(request.POST)
        if form.is_valid():
            vlan_data_center = DataCenter.objects.get(datacenter_Name='Brampton')
            switch_name_to_pull = form.cleaned_data['switch_name_to_pull']
            switch_username = form.cleaned_data['switch_username']
            switch_password = form.cleaned_data['switch_password']

            connection = sendAPIRequeststoAristaSwitch(switch_name_to_pull, switch_username, switch_password)

            vlan_data_center = DataCenter.objects.get(datacenter_Name='Brampton')#switch.switch_location
            vlanlist = getVlansFromSwitch(connection)
            addVlansToDatabase(vlanlist, vlan_data_center)

            # task = redirectedbuildRulefromDBDirect.delay(ourChange.id, ourChange.Change_Number, pano_username,
            #                                              pano_password)
            # # send the user to change detail view page
            # #         return redirect('CHANGEDETAILS', pk = ourChange.id)
            return redirect('index')

        else:
            for key in form.errors.keys():
                if not THISISPROD : print(f'key: {key} - value:{form.errors[key]}')
                messages.append({'type': 'error', 'message': f' {form.errors[key][0]}'})
            print(messages)

    return render(request, 'DataCenter/updateVlaninfoFromSwitchtoDB.html',
                  {'form': form, 'messages': messages,})

@login_required
def UpdateTenantDatabaseFromSwitch(request):
    '''
    this function will be used to process
    password = getpass()
    username = 'nchandrababu'
    hostname = bram-leaf-r13-1

    connection=sendAPIRequeststoAristaSwitch(host,username,password)
    addTenantToDatabase(connection,vlan_data_center )

    '''
    messages = [] #create my message queue this is pretty colours
    if request.method == 'GET':

        form = UpdateTenantDatabaseFromSwitchForm()
        messages.append({'type': 'success', 'message': 'Synchronizing? was someone making Manual changes?'})
        messages.append({'type': 'success', 'message': 'Lets find out together! 乁( ⁰͡ Ĺ̯ ⁰͡ ) ㄏ'})

    else:
        # we have a post in theory?
        form = UpdateTenantDatabaseFromSwitchForm(request.POST)
        if form.is_valid():
            #vlan_data_center = DataCenter.objects.get(datacenter_Name='Brampton')
            switch_name_to_pull = form.cleaned_data['switch_name_to_pull']
            switch_username = form.cleaned_data['switch_username']
            switch_password = form.cleaned_data['switch_password']
            connection = sendAPIRequeststoAristaSwitch(switch_name_to_pull, switch_username, switch_password)

            #vlan_data_center = DataCenter.objects.get(datacenter_Name='Brampton')#switch.switch_location
            vlanlist = getVlansFromSwitch(connection)
            result_list  = getTenantsfromSWitch(connection)
            eapi = pyeapi.client.Node(connection)
            tenant_vlan_dictionary_list = getTenantandVlans(result_list)
            addTenantInfotoDatabase(tenant_vlan_dictionary_list)

            # task = redirectedbuildRulefromDBDirect.delay(ourChange.id, ourChange.Change_Number, pano_username,
            #                                              pano_password)
            # # send the user to change detail view page
            # #         return redirect('CHANGEDETAILS', pk = ourChange.id)
            # return redirect('CHANGELIST')

        else:
            for key in form.errors.keys():
                if not THISISPROD : print(f'key: {key} - value:{form.errors[key]}')
                messages.append({'type': 'error', 'message': f' {form.errors[key][0]}'})
            print(messages)

    return render(request, 'DataCenter/updateTenantinfoFromSwitchtoDB.html',
                  {'form': form, 'messages': messages,})

@login_required
def createIKEVPN(request):
    messages = []
    form = IKEVPNForm()
    if request.method == 'GET':
        form = IKEVPNForm()
        messages.append({'type': 'success', 'message': 'Enabling a partner?'})
        messages.append({'type': 'success', 'message': 'Mohan likes more VPN!'})
    else:
        #has to be  POST
        form = IKEVPNForm(request.POST)#get the data

        if form.is_valid():

            myIKEVPN = IKE_VPN()
            myIKEVPN.ike_gateway_name = form.cleaned_data.get('ike_gateway_name')#have to enforce unique name
            myIKEVPN.crypto_profile = form.cleaned_data.get('crypto_profile')
            myIKEVPN.ipsec_profile = form.cleaned_data.get('ipsec_profile')
            #myIKEVPN.tunnel_secZone = form.cleaned_data.get('tunnel_secZone') #this should be unique to VPN
            #myIKEVPN.tunnel_front_door = form.cleaned_data.get('tunnel_front_door')
            myIKEVPN.peer_outside_address = form.cleaned_data.get('peer_outside_address')
            pano_username = form.cleaned_data.get('pano_username')
            pano_password = form.cleaned_data.get('pano_password')
            pre_shared_key = form.cleaned_data.get('pre_shared_key')
            myIKEVPN.save()
            myIKEVPN = IKE_VPN.objects.get(ike_gateway_name = form.cleaned_data.get('ike_gateway_name'))
            myIKEVPN.tunnel_front_door = form.cleaned_data.get('tunnel_front_door')
            myIKEVPN.tunnel_interface = form.cleaned_data.get('tunnel_interface')
            myIKEVPN.save()
            vpn_id = myIKEVPN.id
            vpn_id_list = []
            vpn_id_list.append(vpn_id)
            buildikeVPN(vpn_id_list, pano_username, pano_password, pre_shared_key)
        else:
            if not THISISPROD : print(form.errors)
            for key in form.errors.keys():
                if not THISISPROD : print(f'key: {key} - value:{form.errors[key]}')
                messages.append({'type': 'error', 'message': f' {form.errors[key][0]}'})
            if not THISISPROD : print(messages)


    return render(request, 'FirewallRules/ike_vpn_form.html', {'form': form, 'messages': messages, })





@login_required
def EDLtoObjectGroupView(request):
    #EDLtoObjectGroup
    messages = []
    if request.method == 'GET':
        form = EDLtoObjectGroupForm()
        messages.append({'type': 'success', 'message': 'Doing the Needful Now'})
        messages.append({'type': 'success', 'message': 'Mohan is excited to prase ☜(⌒▽⌒)☞'})
    else:
        # we have a post here
        form = EDLtoObjectGroupForm(request.POST)
        if form.is_valid():
            # I need to call the function below, i need celery to do it.. and i also need to keep track of the object some how ..
            # source_address = form.cleaned_data['source_address']
            # return redirect('VIEWMYTASKSLISTS')
            commaSprtList = form.cleaned_data['commaSprtList'].split(",")
            object_group_name = form.cleaned_data['object_group_name']
            suggested_prepend_object_name = form.cleaned_data['suggested_prepend_object_name']
            location_name = 'INT' #form.cleaned_data['location_name'].location_name
            # object_group_name, suggested_prepend_object_name, commaSprtList, location_name)
            EDLtoObjectGroupFunction(object_group_name=object_group_name,
                                     suggested_prepend_object_name = suggested_prepend_object_name,
                                     commaSprtList=commaSprtList,
                                     location_name = location_name)
        else:
            for key in form.errors.keys():
                if not THISISPROD : print(f'key: {key} - value:{form.errors[key]}')
                messages.append({'type': 'error', 'message': f' {form.errors[key][0]}'})
            if not THISISPROD : print(messages)
    return render(request, 'FirewallRules/EDLtoObjectGroupView.html', {'form': form, 'messages': messages, })






