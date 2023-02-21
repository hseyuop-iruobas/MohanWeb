from django.contrib import admin

# Register your models here.
from django.contrib import admin
from DataCenter.models import DataCenter, Vlan, Tenant, SNOWChangeTemplate, Switch
from DataCenter.forms import TenantForm
# from .buildvlans import buildmyVlans
import copy


# Register your models here.
@admin.register(DataCenter)
class DataCenterAdmin(admin.ModelAdmin):
    # object_type_dictionary = {'ip-netmask':'ip-netmask', 'address-group':'address-group', 'fqdn':'fqdn', 'special':'special'}
    list_display = ('datacenter_Name',)
    list_filter = ('datacenter_Name',)
    search_fields = ('datacenter_Name',)
    # filter_horizontal = ('object_group_members',)
    # autocomplete_fields = ('object_securityZone',)


@admin.register(Vlan)
class VlanAdmin(admin.ModelAdmin):
    # vlan_name
    list_display = ('vlan_number', 'vlan_name','vlan_datacenter')
    list_filter = ('vlan_datacenter',)
    search_fields = ('vlan_number', 'vlan_name',)



@admin.register(Switch)
class SwitchAdmin(admin.ModelAdmin):
    # vlan_name
    list_display = ('switch_name', 'switch_datacenter',)
    list_filter = ('switch_datacenter',)
    search_fields = ('switch_name',)

@admin.register(SNOWChangeTemplate)
class SnowChangeTemplates(admin.ModelAdmin):
    list_display = ('short_description',)


@admin.register(Tenant)
class TenantAdmin(admin.ModelAdmin):
    # vrf_name, vrf_bgp_bundle_name
    form = TenantForm
    list_display = ('vrf_name', 'vrf_bgp_bundle_name', 'vrf_rd_value',)
    list_filter = ('vrf_name', 'vrf_bgp_bundle_name', 'vrf_rd_value',)
    filter_horizontal = ('vrf_vlans',)
    search_fields = ('vrf_vlans', 'vrf_name', 'vrf_bgp_bundle_name')

    # def save_model(self, request, obj, form, change):
    #     print(f'the current LEN of vlan list is: { len(obj.vrf_vlans.all()) }')
    #     super().save_model(request, obj, form, change)
    #     print(f'Saving { obj.vrf_name }')
    #     mytenant = Tenant.objects.filter(vrf_name = obj.vrf_name)
    #     print(f'the NOW LEN of vlan list is: { len(mytenant[0].vrf_vlans.all()) }')
    #     #myobject_name = obj.object_name
    #     #myobject = Object.objects.filter(object_name = myobject_name)
    #     #myduplicate = Duplicates(object_name = myobject_name, current_db_value = myobject[0])
    #     #myduplicate.save()

    # def save_related(self, request, form, formsets, change):
    #     obj = form.instance
    #     tenant = obj.vrf_name
    #     currentlistofVlans = []
    #     temp_currentlistofVlans = (obj.vrf_vlans.all())
    #     arista_username = request.POST['arista_Switch_Username']
    #     arista_password = request.POST['arista_Switch_Password']
    #
    #     if arista_username and arista_password:  # only do this stuff if there is a user / pass
    #         for answer in temp_currentlistofVlans:
    #             tvlan = Vlan.objects.filter(vlan_name=answer.vlan_name)[0]
    #             print(f"tvlanis: {tvlan} as current list {temp_currentlistofVlans}")
    #             currentlistofVlans.append(tvlan)
    #
    #         super().save_related(request, form, formsets, change)
    #
    #         # print(f'the currentlistofVlans of vlan list is: { currentlistofVlans }')
    #         # print(f'Saving { obj.vrf_name }')
    #         mytenant = Tenant.objects.filter(vrf_name=obj.vrf_name)
    #         newlistofVlans = []
    #         newlistofVlans = (mytenant[0].vrf_vlans.all())
    #         print(f'the newlistofVlans of vlan list is: {newlistofVlans}')
    #         changes_dictionary = {'added': [], 'removed': []}
    #
    #         ##if it was in current and its not in now then it was removed
    #         ##if it was in current and its in now then nothing changed
    #         removed = []
    #         added = []
    #         for vlan in currentlistofVlans:
    #             found = False
    #             vlanName = copy.deepcopy(vlan.vlan_name)
    #             # print(f'checking vlan { vlan.vlan_name } in current list')
    #             for checking in newlistofVlans:
    #                 # print(f'against: { checking.vlan_name }')
    #                 if vlan.vlan_id == checking.vlan_id:
    #                     # we found a match
    #
    #                     # print(f'why set true: {vlan.vlan_id } == {checking.vlan_id}')
    #                     found = True
    #                     break  # no reason to keep checking right?
    #
    #             if not found:
    #                 # this vlan was removed so add it to the removed list.
    #                 removed.append(vlanName)
    #
    #         # if a vlan is in a list of new vlans but not the old list
    #         # then it was added
    #         # if its in both lists then nothing changed
    #         for vlan in newlistofVlans:
    #             found = False
    #             vlanName = copy.deepcopy(vlan.vlan_name)
    #             # print(f'checking vlan { vlan.vlan_name } in newlist')
    #             for checking in currentlistofVlans:
    #                 # print(f'against: { checking.vlan_name }')
    #                 if vlan.vlan_id == checking.vlan_id:
    #                     # we found a match
    #                     # print(f'setting TRue cause {vlan.vlan_id} == {checking.vlan_id}')
    #                     found = True
    #                     break  # no reason to keep checking right?
    #             if not found:
    #                 # this vlan was removed so add it to the removed list.
    #                 added.append(vlanName)
    #
    #         # print('change dictionary is:')
    #         changes_dictionary['added'] = added
    #         changes_dictionary['removed'] = removed
    #         print(changes_dictionary)
    #         print(f'on vrf/tenant {tenant} ')
    #         buildmyVlans(tenant=tenant, vlan_changes_dictionary=changes_dictionary, arista_username=arista_username,
    #                      arista_password=arista_password, vrf_exists_on_edge=obj.vrf_exists_on_edge)
    #
    #
    #     else:
    #         super().save_related(request, form, formsets, change)

    # def save_related(self, request, form, formsets, change):
    #     super(SearchandReplaceAdmin, self).save_related(request, form, formsets, change)
    #     print(f'form is: { form.instance }')
    #     user_request = form.instance
    #     newServer = user_request.newServer.all()
    #     currentServer = user_request.currentServer.all()[0]
    #     searchandReplaceMyRules(newServer, currentServer, user_request.id, request.POST['username'], request.POST['password'])


