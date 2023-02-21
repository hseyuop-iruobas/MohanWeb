from django.contrib import admin
from FirewallRules.models import (Object, secZone, Location,
                                  Firewall, Service, RuleInstance,
                                  ChangeForm, Change, FirewallRules,
                                  Duplicates, task, tag, IKE_VPN,AddressGroup)
from FirewallRules.models import device_group_model, firewall_template_model, routingBubble
from FirewallRules.models import InterfaceForm, VirtualRouter, Firewall_Interface
from DataCenter.buildvlans import createsubInterfaceonFirewall

admin.sites.AdminSite.site_header = "Automation through motion"
admin.sites.AdminSite.site_title = "Mohan Verbose"


@admin.register(AddressGroup)
class AddressGroupAdmin(admin.ModelAdmin):
    model = AddressGroup
    list_display = ('Object_in_DB','id', )
    list_filter = ('Object_in_DB',)
    filter_horizontal = ('object_group_members',)




@admin.register(device_group_model)
class DeviceGroupAdmin(admin.ModelAdmin):
    model = device_group_model

@admin.register(firewall_template_model)
class TemplateAdmin(admin.ModelAdmin):
    model = firewall_template_model


@admin.register(VirtualRouter)
class VRAdmin(admin.ModelAdmin):
    model = VirtualRouter
    list_display = ('id', 'virtual_router_name','virtual_router_firewall')
    list_filter = ('virtual_router_name','virtual_router_firewall')
    search_fields = ('id', 'virtual_router_name','virtual_router_firewall')


@admin.register(tag)
class taskAdmin(admin.ModelAdmin):
    model = tag
    list_display = ('tag_name',)


@admin.register(task)
class taskAdmin(admin.ModelAdmin):
    model = task
    list_display = ('task_search_term', 'task_id', 'db_created_by', 'task_description')
    filter_horizontal = ('sub_tasks',)



class FirewallRulesInstance(admin.TabularInline):
    model = FirewallRules
    field_order = ['devicegroup', 'source_zone', 'destination_zone']
    max_num = 1
    readonly_fields = ('pushed_to_firewall','isShared',
    'devicegroup', 'source_zone', 'destination_zone',
    'log_setting', 'profile_group_name', 'operation')
    exclude = (
    'action', 'log_at_session_end', 'log_at_session_start', 'profile_type', 'type',
    'operations',)





@admin.register(Object)
class ObjectAdmin(admin.ModelAdmin):
    # object_type_dictionary = {'ip-netmask':'ip-netmask', 'address-group':'address-group', 'fqdn':'fqdn', 'special':'special'}
    list_display = ('object_name', 'object_type', 'object_location')
    list_filter = ('object_type', 'object_location',)
    search_fields = ('object_name', 'object_type', 'object_value')
    filter_horizontal = ('object_group_members',)
    autocomplete_fields = ('object_firewall_interface',)

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        print(f'creating duplicate record {obj.object_name}')
        myobject_name = obj.object_name
        myobject = Object.objects.filter(object_name=myobject_name)
        myduplicate = Duplicates(object_name=myobject_name, current_db_value=myobject[0], object_value=obj.object_value)
        myduplicate.save()





@admin.register(secZone)
class SecZoneAdmin(admin.ModelAdmin):

    list_display = ('security_zone_name', 'security_zone_firewall', )
    list_filter =  ('security_zone_name', 'security_zone_firewall', )
    search_fields =  ('security_zone_name',  )



@admin.register(routingBubble)
class routingBubbleAdmin(admin.ModelAdmin):
    list_display = ('routingBubble_id', 'routingBubble_name', 'routingBubble_firewall','routingBubble_inside_interface')
    list_filter =  ('routingBubble_id', 'routingBubble_name', 'routingBubble_firewall', 'routingBubble_inside_interface')
    autocomplete_fields  = ('routingBubble_inside_interface',)
    filter_horizontal = ('routingBubble_virtualrouters',)

@admin.register(Firewall_Interface)
class Firewall_InterfaceAdmin(admin.ModelAdmin):
    form = InterfaceForm
    list_display = ('Firewall_Interface_id','Firewall_Interface_name', 'Firewall_Interface_vlan', 'Firewall_Interface_security_zone', 'Firewall_Interface_value',)
    list_filter = ('is_inside_interface','is_RFC_1918','is_vpn','Firewall_Interface_virtual_router',)
    search_fields = ('Firewall_Interface_name', 'Firewall_Interface_value', 'Firewall_Interface_description')
    autocomplete_fields = ('Firewall_Interface_vlan','Firewall_Interface_security_zone')
    fieldsets = (
        ('Mandatory:', {
            'fields': (
            'Firewall_Interface_name', 'Firewall_Interface_vlan', 'Firewall_Interface_tag', 'Firewall_Interface_description', 'Firewall_Interface_value', 'Firewall_Interface_virtual_router',
            'Firewall_Interface_security_zone', 'Firewall_Interface_management_profile', 'is_inside_interface', 'is_RFC_1918', 'is_vpn'),
        }),
        ('Optional to Run Play:', {
            'classes': ('collapse', 'open'),
            'fields': ('username', 'password', 'runplay')
        })
    )

    def save_related(self, request, form, formsets, change):
        super(Firewall_InterfaceAdmin, self).save_related(request, form, formsets, change)
        # below evaluate if someone clicked the 'run' play and then do something about it
        if ('runplay' in request.POST.keys()) and request.POST['runplay'] == 'on':
            myfirewallInterface = form.instance
            myfirewallInterface_django = Firewall_Interface.objects.filter(Firewall_Interface_name=myfirewallInterface.Firewall_Interface_name,
                                                            Firewall_Interface_value=myfirewallInterface.Firewall_Interface_value)[0]
            print(
                f'found security zone {myfirewallInterface_django.Firewall_Interface_id} '
                f', {myfirewallInterface_django.Firewall_Interface_name} and value '
                f'{myfirewallInterface_django.Firewall_Interface_value} ')
            print(f"status of runplay is {request.POST['runplay']}")
            createsubInterfaceonFirewall(request.POST['username'], request.POST['password'],
                                         myfirewallInterface_django.Firewall_Interface_id)
        else:
            print(f"status of runplay is not clicked")


@admin.register(Location)
class LocationAdmin(admin.ModelAdmin):
    list_display = ('location_name', 'location_description','location_type',)
    list_filter = ('location_type',)
    filter_horizontal = ('location_path','location_parents')
    search_fields = ('location_name',)  # 'location_parents')


@admin.register(Firewall)
class FirewallAdmin(admin.ModelAdmin):
    list_display = ('firewall_Name', 'firewall_device_group_name', 'firewall_ID', 'firewall_vsys', 'firewall_datacenter')
    list_filter = ('firewall_ID', 'firewall_Name', 'firewall_device_group_name', 'firewall_template_name')
    search_fields = ('firewall_Name', 'firewall_ID')


@admin.register(Service)
class ServicesAdmin(admin.ModelAdmin):
    list_display = ('service_protocol', 'service_dest_port', 'service_name')
    list_filter = ('service_protocol', 'service_dest_port', 'service_name', 'service_type')
    search_fields = ('service_protocol', 'service_dest_port', 'service_name',)
    #filter_horizontal = ('service_type',)


@admin.register(RuleInstance)
class RuleInstanceAdmin(admin.ModelAdmin):
    list_display = ('rule_name', 'creation_date', 'db_created_by')
    list_filter = ('rule_name', 'creation_date', 'db_created_by')
    search_fields = ('id', 'rule_name', 'rule_description',)
    filter_horizontal = ('source', 'dest', 'service')
    autocomplete_fields = ('source', 'dest', 'service')
    readonly_fields = ('db_created_by','schedule_end_date')
    fieldsets = (
        ('Mandatory:', {
            'fields': ('id', 'rule_name', 'rule_description')
        }),
        ('Rule base: (Also Mandatory)', {

            'fields': ('source', 'dest', 'service'),
        }),
        ('Optional:', {
            'classes': ('collapse', 'open'),
            'fields': ('application', 'source_user',
                       'catagory_name','urls',
                       'rule_location',),
        }),
        ('Schedule:', {
            'classes': ('collapse', 'open'),
            'fields': ('rule_duration', 'start_date','schedule_end_date'),
        }), ('Created by:', {
            'classes': ('collapse', 'open'),
            'fields': ('db_created_by',),
        })
    )
    #
    inlines = [FirewallRulesInstance]
    actions=['really_delete_selected']

    def get_actions(self, request):
        actions = super(RuleInstanceAdmin, self).get_actions(request)
        del actions['delete_selected']
        return actions

    def really_delete_selected(self, request, queryset):
        for obj in queryset:
            #get a list of all firewall rules attached to this object
            FirewallRulesQuery = FirewallRules.objects.filter(rule_instance = obj)
            for firewallrule in FirewallRulesQuery:
                firewallrule.delete()
            obj.delete()

        if queryset.count() == 1:
            message_bit = f"1 Ruleinstance entry was and {FirewallRulesQuery.count()} firewallrules were also deleted"
        else:
            message_bit = "%s Ruleinstance entries were" % queryset.count()
        self.message_user(request, "%s successfully deleted." % message_bit)

    really_delete_selected.short_description = "Delete selected entries & associated Rules"

    def save_model(self, request, obj, form, change):
        print('documenting user: ' + str(request.user))
        obj.created_by = str(request.user)
        obj.db_created_by = request.user
        print('schedule is:')
        print(obj.rule_duration)
        print('date object is:')
        print(obj.start_date)
        super().save_model(request, obj, form, change)


class ChangesAdmin(admin.ModelAdmin):
    form = ChangeForm
    filter_horizontal = ('Requests',)
    list_display = ('Change_Number', 'creation_date')
    list_filter = ('Change_Number', 'creation_date', 'created_by')
    search_fields = ('Change_Number', 'creation_date')
    fieldsets = (
        ('Mandatory', {
            'fields': ('Change_Number', 'Requests', 'pano_username', 'pano_password', 'change_status')
        }),

    )

admin.site.register(Change, ChangesAdmin)



@admin.register(Duplicates)
class DuplicatesAdmin(admin.ModelAdmin):
    autocomplete_fields = ('current_db_value',)
    search_fields = ('object_name', 'object_value',)

@admin.register(IKE_VPN)
class IKE_VPNAdmin(admin.ModelAdmin):
    autocomplete_fields = ('tunnel_interface','tunnel_front_door')
    search_fields = ('ike_gateway_name', 'peer_outside_address',)

