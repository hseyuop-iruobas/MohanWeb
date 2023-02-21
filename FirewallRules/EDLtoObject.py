from FirewallRules.models import Object, AddressGroup
from django.db import transaction
from celery import shared_task





         #generate an ID so we can add relationships
@shared_task
@transaction.atomic
def EDLtoObjectGroupFunction(object_group_name,suggested_prepend_object_name,commaSprtList, location_name):
        print(f'I got this stuff i dont know about you: {commaSprtList}')
        myobjectgroup = Object()
        myobjectgroup.object_name = object_group_name
        myobjectgroup.object_type = 'address-group'
        myobjectgroup.object_description = object_group_name
        myobjectgroup.object_value = object_group_name
        myobjectgroup.save()
        myAddressGroup = AddressGroup(Object_in_DB = myobjectgroup,)
        myAddressGroup.save()
        for ipaddress in commaSprtList:
            ipaddress = ipaddress.replace('"',"")
            ipaddress = ipaddress.replace('\r\n', "")
            object_query_list = Object.objects.filter(object_value__contains=ipaddress)
            if len(object_query_list)>0 :
                myobject = object_query_list[0]
                myAddressGroup.object_group_members.add(myobject)
            else:
                #create a  brand new object with all the right info
                #save that object FIRST so you get an ID
                #add it to the group member
                myobject = Object()
                myobject.object_location = location_name
                myobject.object_type = 'ip-netmask'
                myobject.object_value = ipaddress
                myobject.object_description = suggested_prepend_object_name + "_" + (str(ipaddress)).replace("/","_")
                myobject.object_name = suggested_prepend_object_name + "_" +(str(ipaddress)).replace("/","_")
                myobject.save()
                myAddressGroup.object_group_members.add(myobject)
                myAddressGroup.save()
        myobjectgroup.save()
        myAddressGroup.save()
        myobjects = myAddressGroup.object_group_members.all()
        print(f'address GRP: {myAddressGroup} - members: {myobjects}')
        myobjectgroup.object_value = hash(",".join([myobject.object_name for myobject in myobjects]))
        myobjectgroup.save()