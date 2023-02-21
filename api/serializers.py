from rest_framework import serializers
from FirewallRules.models import Object, Firewall_Interface, Service, FirewallRules, RuleInstance, Change, tag, secZone
from FirewallRules.models import device_group_model, firewall_template_model,Firewall,VirtualRouter,Location, routingBubble

class Object_Serializer(serializers.ModelSerializer):
    class Meta:
        model = Object
        fields = ['object_id','object_name','object_description','object_value','tags','object_type','object_location','object_group_members',]

class tag_Serializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = tag
        fields = ['tag_name','id']


class Firewall_Interface_Serializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Firewall_Interface
        fields = ['Firewall_Interface_id','Firewall_Interface_name',
                  'Firewall_Interface_tag','Firewall_Interface_description','Firewall_Interface_virtual_router',
                  'Firewall_Interface_security_zone','Firewall_Interface_value',
                  'Firewall_Interface_management_profile','is_inside_interface','is_RFC_1918','is_vpn',]#'Firewall_Interface_vlan',


class Service_Serializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Service
        fields = ['service_protocol','service_name','service_tag','service_description',
                  'service_id','service_dest_port','service_type','service_group_members',]


class FirewallRules_Serializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = FirewallRules
        fields = ['id','action',
                  'creation_date','destination_zone','devicegroup','log_at_session_end','log_at_session_start',
                  'log_setting','operation','profile_group_name','profile_type','rule_instance','source_zone',
                  'start_date','isShared','pushed_to_firewall']


class RuleInstance_Serializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = RuleInstance
        fields = ['id','source','dest','service','application','rule_name','rule_description',
                  'source_user','urls','creation_date','rule_duration',
                  'start_date',]


class Change_Serializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Change
        fields = ['Requests','Change_Number','creation_date','created_by','change_status',]

class secZone_Serializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = secZone
        fields = ['security_zone_name','security_zone_firewall','id']

class device_group_model_Serializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = device_group_model
        fields = ['device_group_name',]


class firewall_template_model_Serializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = firewall_template_model
        fields = ['firewall_template_name',]


class Firewall_Serializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Firewall
        fields = ['firewall_Name','firewall_Description','firewall_device_group_name','firewall_template_name','firewall_ID','firewall_vsys','firewall_mgt_ip',]

class VirtualRouter_Serializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = VirtualRouter
        fields = ['virtual_router_name','virtual_router_description','virtual_router_firewall',]


class Location_Serializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Location
        fields = ['location_name','location_description',
                  'location_networks','location_path',
                  'location_id','location_parents','location_type',
                  'location_classification_type',]

class routingBubble_Serializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = routingBubble
        fields = ['routingBubble_id','routingBubble_name',
                  'routingBubble_firewall','routingBubble_inside_interface',
                  'routingBubble_virtualrouters',]