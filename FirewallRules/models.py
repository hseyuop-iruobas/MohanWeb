from django.contrib.auth.models import User

# Create your models here.
from django.db import models
from django.forms import ModelForm, PasswordInput
from django import forms
from django.utils.timezone import now

from django.urls import reverse
from DataCenter.models import DataCenter, Vlan

# Create your models here.


class tag(models.Model):
    tag_name = models.CharField(max_length=200, help_text='name of object usually FQDN_IPADDRESS', null=True,
                                blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['tag_name'], name='tag name has to be unique')]

    def __str__(self):
        return (self.tag_name)


class device_group_model(models.Model):
    device_group_name = models.CharField(max_length=32, help_text='Name of device_group', )

    def __str__(self):
        return self.device_group_name

    def getName(self):
        return self.device_group_name


class firewall_template_model(models.Model):
    firewall_template_name = models.CharField(max_length=32, help_text='Name of template')

    def __str__(self):
        return self.firewall_template_name

    def getName(self):
        return self.firewall_template_name


class Firewall(models.Model):
    "my Firewall Class"
    firewall_Name = models.CharField(max_length=32, help_text='Device Group Name in panorama')
    firewall_Description = models.CharField(max_length=140, help_text='Description of Firewall', null=True, blank=True)

    firewall_device_group_name = models.ForeignKey(device_group_model, on_delete=models.SET_NULL, null=True,
                                                   blank=True, )

    firewall_template_name = models.ForeignKey(firewall_template_model, on_delete=models.SET_NULL, null=True,
                                               blank=True, )
    firewall_ID = models.AutoField(help_text='internal Usage', primary_key=True, db_column='firewall_ID')
    firewall_datacenter = models.ForeignKey(DataCenter, on_delete=models.SET_NULL, null=True, blank=True,
                                            db_column='which DC or location')
    firewall_vsys = models.CharField(max_length=32, help_text='vSYS name Case Sensitive!!!!!', null=True, blank=True)
    firewall_mgt_ip = models.CharField(max_length=32, help_text='IP address or Fqdn of Primary FW', null=True,
                                       blank=True)

    class Meta:
        ordering = ['-firewall_ID']

    def getPanoramaTemplate(self):
        return self.firewall_template_name.getName()

    def getName(self):
        return self.firewall_Name

    def getDescription(self):
        return self.firewall_Description

    def getID(self):
        return self.firewall_ID

    def getPolicyGroup(self):
        return self.firewall_device_group_name.getName()

    def __str__(self):
        return self.firewall_Name

    def get_absolute_url(self):
        return reverse('model-detail-view', args=[str(self.id)])


###############################################
class VirtualRouter(models.Model):
    virtual_router_name = models.CharField(max_length=32, help_text='VR_Name')
    virtual_router_description = models.CharField(max_length=100, help_text='Description of the VR')
    virtual_router_firewall = models.ForeignKey(Firewall, on_delete=models.SET_NULL, null=True, blank=True, )

    def __str__(self):
        return (f'{self.virtual_router_firewall.firewall_Name}--{self.virtual_router_name}')


###############################################


class secZone(models.Model):
    security_zone_name = models.CharField(max_length=32, help_text='Name of Security Zone')
    security_zone_firewall = models.ForeignKey(Firewall, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        myzonefirewall_name= 'Shared'
        if self.security_zone_firewall != None:
            myzonefirewall_name = self.security_zone_firewall
        return (f'{self.security_zone_name} -- {myzonefirewall_name}')


###############################################
Location_type_choices = (('Parent', "Parent"), ('Child', 'Child'))
location_classification_choices = (('special', 'special'), ('normal', 'normal'))


class Location(models.Model):
    class Meta:
        ordering = ['-location_name']

    location_name = models.CharField(max_length=80, help_text='Name of Location')
    location_description = models.CharField(max_length=130, help_text='Description if any', null=True, blank=True)
    location_networks = models.CharField(max_length=3000, help_text='CIDR of networks in this location', null=True,
                                         blank=True)

    location_path = models.ManyToManyField(secZone, help_text='Security Zones in Path to here', null=True,
                                           blank=True)
    location_id = models.AutoField(help_text='internal Usage', primary_key=True, db_column='location_id')
    location_parents = models.ManyToManyField('self', related_name='Location_parent', help_text='used to add superpath',
                                              null=True, blank=True)

    location_type = models.CharField(max_length=32, choices=Location_type_choices,
                                     help_text='MUST BE PARENT OR CHILD',
                                     default='Parent')
    location_classification_type = models.CharField(max_length=32, choices=location_classification_choices,
                                                    help_text='consult manual to use special', default='normal')

    def getName(self):
        return self.location_name

    def getDescription(self):
        return self.location_description

    def getclassification(self):
        return self.location_classification_type

    def location_parent(self):
        return self.location_parents

    def getID(self):
        return self.location_ID

    def __str__(self):
        return self.location_name


###############################################

from FirewallRules.vars import interface_management_profile_choices


class Firewall_Interface(models.Model):
    Firewall_Interface_id = models.AutoField(help_text='internal Usage', db_column='seczone_id', primary_key=True)
    Firewall_Interface_name = models.CharField(max_length=32, help_text='Nex: ae2.239 or ethernet 1/1')
    Firewall_Interface_vlan = models.ForeignKey(Vlan, on_delete=models.SET_NULL, null=True, blank=True, )
    Firewall_Interface_tag = models.CharField(max_length=32, help_text='Tag if applicable', null=True, blank=True)
    Firewall_Interface_description = models.CharField(max_length=140, help_text='Description', null=True, blank=True)
    Firewall_Interface_virtual_router = models.ForeignKey(VirtualRouter, on_delete=models.SET_NULL, null=True,
                                                          blank=True)
    Firewall_Interface_security_zone = models.ForeignKey(secZone, on_delete=models.SET_NULL, null=True,
                                                         blank=True, )
    Firewall_Interface_value = models.CharField(max_length=140,
                                                help_text='IP address of SUBNET and MASK served from behind the interface ex 10.218.1.`/24',
                                                null=True, blank=True)
    Firewall_Interface_management_profile = models.CharField(max_length=32,
                                                             choices=interface_management_profile_choices,
                                                             help_text='HAS TO BE [ping or https-ssh-ping-snmp ] default is ping',
                                                             null=True, blank=True, default='ping')
    is_inside_interface = models.BooleanField(help_text='is this the inside of the firewall?', null=True, blank=True,
                                              default=False)
    is_RFC_1918 = models.BooleanField(help_text='dont set used for any interface special read doc', null=True,
                                      blank=True, default=False)
    # will be used to narrow down a list of available interfaces to build VPN
    is_vpn = models.BooleanField(help_text='dont set used for any interface special read doc', null=True, blank=True,
                                 default=False)

    def getName(self):
        return self.Firewall_Interface_name

    def getDescription(self):
        return self.Firewall_Interface_description

    def getValue(self):
        return self.Firewall_Interface_value

    def getTag(self):
        return self.Firewall_Interface_tag

    def getID(self):
        return self.Firewall_Interface_id

    def getfwID(self):
        return self.Firewall_Interface_virtual_router.virtual_router_firewall.firewall_ID

    def getfwInterface(self):
        return self.Firewall_Interface_name
    def getfullname(self):
        return self.Firewall_Interface_name + "_" + self.Firewall_Interface_value

    def __str__(self):
        returnstring = self.Firewall_Interface_name + "_" + self.Firewall_Interface_value
        return returnstring


class InterfaceForm(ModelForm):
    username = forms.CharField(help_text='your username', required=False)
    password = forms.CharField(widget=PasswordInput(), help_text='your password', required=False)
    runplay = forms.BooleanField(required=False, initial=False)

    class Meta:
        model = Firewall_Interface
        fields = ['Firewall_Interface_name', 'Firewall_Interface_vlan', 'Firewall_Interface_tag',
                  'Firewall_Interface_description', 'Firewall_Interface_value', 'Firewall_Interface_virtual_router',
                  'Firewall_Interface_security_zone', 'Firewall_Interface_management_profile', 'is_inside_interface',
                  'is_RFC_1918', 'is_vpn']

    def __str__(self):
        returnstring = self.Firewall_Interface_name + "_" + self.Firewall_Interface_value
        return returnstring


class routingBubble(models.Model):
    routingBubble_id = models.AutoField(primary_key=True, )
    routingBubble_name = models.CharField(max_length=32, help_text='Device Group Name in panorama')
    routingBubble_firewall = models.ForeignKey(Firewall, on_delete=models.SET_NULL, null=True, blank=True, )
    routingBubble_inside_interface = models.ForeignKey(Firewall_Interface, on_delete=models.SET_NULL, null=True,
                                                       blank=True, )
    routingBubble_virtualrouters = models.ManyToManyField(VirtualRouter)

    def getName(self):
        return self.routingBubble_name

    def getID(self):
        return self.routingBubble_id

    def __str__(self):
        return f'{self.routingBubble_id}_{self.routingBubble_name}_{self.routingBubble_firewall.firewall_Name}'


class moveSecurityZone(models.Model):
    securityZonetoMove = models.ForeignKey(secZone, on_delete=models.SET_NULL, null=True, blank=True,
                                           db_column='seczone_fwid')

    class Meta:
        verbose_name_plural = 'Move Security Zone from VIC to BRM Auto'


class moveSecurityZoneForm(ModelForm):
    username = forms.CharField(help_text='your username', required=False)
    password = forms.CharField(widget=PasswordInput(), help_text='your password', required=False)

    class Meta:
        model = moveSecurityZone
        fields = ['securityZonetoMove', ]
        verbose_name_plural = 'Move Security Zone from VIC to BRM Auto'

    def __str__(self):
        returnstring = self.seczone_name + "_" + self.seczone_value
        return returnstring


from FirewallRules.vars import service_protocol_choices


class Service(models.Model):
    # Services

    service_type_choices = (('service', 'service'), ('service-group', 'service-group'))

    class Meta:
        ordering = ['-service_name']
        db_table = 'Services'
        constraints = [models.UniqueConstraint(fields=['service_name'], name='unique name')]

    service_protocol = models.CharField(max_length=10, choices=service_protocol_choices, default='TCP')
    service_name = models.CharField(max_length=140, help_text='Name of service ex: TCP-DST-443')
    service_tag = models.ManyToManyField('tag', related_name='tags_for_service',
                                         help_text='tags',null = True, blank = True )
    service_description = models.CharField(max_length=140, help_text='Description of service - not required', null=True,
                                           blank=True)
    service_id = models.AutoField(db_column='service_id', primary_key=True)
    service_dest_port = models.CharField(max_length=140, help_text='port ex: 443 or 443-445')
    service_type = models.CharField(max_length=32, choices=service_type_choices,
                                    help_text='HAS TO BE [service or service-group]', null=True, blank=True,
                                    default='service')
    service_group_members = models.ManyToManyField('self', related_name='service_group_members',
                                                   help_text='Used for Service-Group Members', null=True, blank=True, )

    def __str__(self):
        return self.service_name


def CompileLocations():
    # intheory pulls a list of locations:
    # it should include FW, INT, CORE, and all my other locations
    # first get a list of all locations:
    myStaticLocations = [('FW', 'On a Firewall'), ('INT', 'Internet'), ('CORE', 'Not Behind a Firewall')]
    locations = Location.objects.all()
    for location in locations:
        temptupple = (location.getName(), location.getName())
        myStaticLocations.append(temptupple)
    return myStaticLocations


from FirewallRules.vars import object_type_choices


class Object(models.Model):
    # [('FW', 'On a Firewall'), ('INT', 'Internet'), ('CORE', 'Not Behind a Firewall')]#
    object_location_choices = CompileLocations()

    object_id = models.AutoField(help_text='internal Usage', primary_key=True, db_column='object_id')
    object_name = models.CharField(max_length=200, help_text='name of object usually FQDN_IPADDRESS', null=True,
                                   blank=True)
    object_description = models.CharField(max_length=4000, help_text='description of object', null=True, blank=True)
    object_value = models.CharField(max_length=4000, help_text='ip address, fqdn, groups', null=True, blank=True)
    object_tag = models.CharField(max_length=32, help_text='Tag', null=True, blank=True)
    object_type = models.CharField(max_length=32, choices=object_type_choices,
                                   help_text='HAS TO BE [ip-netmask, address-group, fqdn, special]', null=True,
                                   blank=True, default='ip-netmask')

    object_location = models.CharField(max_length=32, choices=object_location_choices,
                                       help_text='FW,INT,CORE,AWS,Blank if not sure', null=True, blank=True)
    object_firewall_interface = models.ForeignKey(Firewall_Interface, on_delete=models.SET_NULL,
                                                  help_text='If you know, you know',
                                                  null=True, blank=True, db_column='object_Firewall_Interface')
    object_group_members = models.ManyToManyField('self', related_name='object_group_members',
                                                  help_text='Used for Object-Group Members', null=True, blank=True, )
    tags = models.ManyToManyField(tag, related_name='tags', help_text='used for taging of objects', null=True,
                                  blank=True, )

    class Meta:
        ordering = ['-object_name']
        constraints = [models.UniqueConstraint(fields=['object_value'], name='unique value')]

    def getLocation(self):
        return self.object_location

    def getName(self):
        return self.object_name

    def getDescription(self):
        return self.object_description

    def getValue(self):
        return self.object_value

    def getTag(self):
        mytags = self.tags.all()
        return_data = []
        for mytag in mytags:
            # need to make these string so yaml writes it good for ansible play
            return_data.append(f"'{mytag.tag_name}'")
        return ",".join(return_data)

    def getID(self):
        return self.object_ID

    def getObjectType(self):
        return self.object_type

    def getObjectFW(self):
        return self.object_fw

    def getOBJDictionary(self):
        object_dict = {}
        object_dict['object_name'] = self.object_name
        object_dict['object_description'] = self.object_description
        object_dict['object_value'] = self.object_value
        # ive to do some stupid stuff here so the yaml file is written correctly
        # first make a list so i can edit stuff
        object_dict['object_tag'] = self.getTag()
        object_dict['object_type'] = self.object_type
        object_dict['object_id'] = self.object_id
        object_dict['object_location'] = self.object_location
        return object_dict

    def __str__(self):
        return self.object_name


class AddressGroup(models.Model):
    '''
        this model exists so i can have object-groups or address-groups in fucking piece
        the self relation doesn't work well for some reason i dont know what im doing, and its
        causing the DB to create a two way relationtoitself which is causing the unpack function to fail bad
        so now we have a model that relates back to the object model and i just have to refactor a bunch of code
    '''

    object_group_members = models.ManyToManyField(Object, related_name='address_group_members',
                                                  help_text='Used for Object-Group Members', null=True, blank=True, )
    Object_in_DB = models.ForeignKey(Object, related_name='object_in_database',
                                                  help_text='Used one to one with the object in DB',
                                     on_delete=models.SET_NULL, null=True,)
    def __str__(self):
        return self.Object_in_DB.object_name

class Duplicates(models.Model):
    # i was going to build a static list, but hey database which means i'll let sql do the sorting and lookups
    # but yes horrible horrible idea .. im sorry to the future readers of this code
    # in theory the name should be unique because each object has only ONE unique value in the current database which i just figured should be a relation!

    object_name = models.CharField(max_length=200, help_text='name of object usually FQDN_IPADDRESS', null=True,
                                   blank=True)
    current_db_value = models.ForeignKey(Object, null=True, related_name="current_db_value",
                                         db_column='current_db_value', on_delete=models.CASCADE)
    object_value = models.CharField(max_length=200, help_text='name of object usually FQDN_IPADDRESS', null=True,
                                    blank=True)
    object_tag = models.CharField(max_length=200, help_text='name of object usually FQDN_IPADDRESS', null=True,
                                  blank=True)

    class Meta:
        ordering = ['-object_name']
        verbose_name_plural = "Dupliactes"

    def getName(self):
        return self.object_name

    def __str__(self):
        return (self.object_name)




class SearchandReplace(models.Model):
    id = models.CharField(max_length=30, primary_key=True, help_text='RITM#')
    currentServer = models.ManyToManyField(Object, null=True, blank=True,
                                           help_text="the server you want to replicate the rules of",
                                           related_name="currentServer")
    newServer = models.ManyToManyField(Object, null=True, blank=True, help_text="the server you want to replicated for",
                                       related_name="newServer")

    class meta:
        verbose_name_plural = 'Search_and_Replace'

    def __str__(self):
        new_Server = "____"
        current_server = '___'

        if self.currentServer.all():
            current_server = ",".join([x.object_name for x in self.currentServer.all()])

        if self.newServer.all():
            new_Server = ",".join([x.object_name for x in self.newServer.all()])

        return (('{current_server} migration to {new_Server}').format(current_server=current_server,
                                                                      new_Server=new_Server))


from FirewallRules.vars import (scheduleChoice,
                                rule_location_Choice)
class RuleInstance(models.Model):
    ruleinstance_primarykey = models.AutoField(help_text='internal Usage', primary_key=True, )
    id = models.CharField(max_length=100, help_text='RITM#')
    source = models.ManyToManyField(Object, null=True, related_name="source_address", db_column='object_id')
    dest = models.ManyToManyField(Object, null=True, related_name="dest_address", db_column='object_id')
    service = models.ManyToManyField(Service, null=True)
    application = models.TextField(help_text='match exactly what panorama shows, comma separated', null=True, blank=True)
    rule_name = models.CharField(max_length=100, help_text='ex.RITMxxxxx-source-dest-protocol', default='CHG')
    rule_description = models.CharField(max_length=300, help_text='Rule Description - Max 100 Chars',
                                        default='permits some app')
    source_user = models.CharField(max_length=1000, help_text='users', default='any')
    urls = models.TextField(help_text='URL', null=True, blank=True, default='')
    creation_date = models.DateField(auto_now=True)
    created_by = models.CharField(max_length=130, default=' ')
    rule_duration = models.CharField(max_length=10, choices=scheduleChoice, default='0')
    rule_location = models.CharField(max_length=20, choices=rule_location_Choice, default='pre-rulebase')
    start_date = models.DateTimeField(default=now, blank=True)
    db_created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    catagory_name = models.CharField(max_length=100,null=True, blank=True, help_text='Name of the URL cat if different from RITM.ID')
    schedule_end_date = models.DateTimeField(blank=True, null=True, help_text = 'filled in if there is a schedule set')
    profile_group_name = models.CharField(max_length=100, help_text='profile_group_name', default='Alert', blank=True)
    isInUse = models.BooleanField(help_text='is the database working on this', default=False)
    class Meta:
        ordering = ['-id']
        constraints = [models.UniqueConstraint(fields=['id'], name='RuleInstance id has to be unique')]

    def __str__(self):
        return self.id

    def save(self, *args, **kwargs):
        super(RuleInstance, self).save(*args, **kwargs)




from FirewallRules.vars import change_status_choices


class Change(models.Model):
    Requests = models.ManyToManyField(RuleInstance)
    Change_Number = models.CharField(max_length=30, help_text='ex. CHG0000000', default='CHG Number')
    creation_date = models.DateField(auto_now=True)
    created_by = models.CharField(max_length=130, default=' ')
    db_created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    change_status = models.CharField(max_length=20, choices=change_status_choices, default='Not Started')

    def __str__(self):
        return self.Change_Number


class ChangeForm(ModelForm):
    pano_username = forms.CharField(max_length=30, help_text='your Panorama Username')
    pano_password = forms.CharField(widget=PasswordInput(), help_text='your Panorama Password')

    class Meta:
        # abstract = True
        model = Change
        fields = ['Requests', 'Change_Number', 'change_status']
        ordering = ['creation_date']

    def __str__(self):
        return self.Change_Number


class FirewallRules(models.Model):
    action = models.CharField(max_length=100, help_text='action(allow, drop, reset)', default='allow')
    name_on_the_firewall = models.CharField(max_length=200, help_text='name of the rule on the firewall', blank=True, null=True)
    creation_date = models.DateField(auto_now=True)
    destination_zone = models.ManyToManyField(secZone, null=True, blank=True,
                                              related_name='firewall_rule_destination_zone')
    devicegroup = models.ForeignKey(Firewall, on_delete=models.SET_NULL, null=True, blank=True,
                                    related_name='device_group')
    log_at_session_end = models.CharField(max_length=2, help_text='0/1', default='0',null=True, blank=True,)
    log_at_session_start = models.CharField(max_length=2, help_text='0/1', default='0',null=True, blank=True,)
    log_setting = models.CharField(max_length=100, help_text='users', default='any',null=True, blank=True,)
    operation = models.CharField(max_length=100, help_text='allow/drop/reset', default='allow',null=True, blank=True,)
    profile_group_name = models.CharField(max_length=100, help_text='profile_group_name', default='ALERT',null=True, blank=True,)
    profile_type = models.CharField(max_length=100, help_text='users', default='any')
    rule_instance = models.ForeignKey(RuleInstance, on_delete=models.SET_NULL, null=True, blank=True,
                                      related_name='rule_instance')
    source_zone = models.ManyToManyField(secZone, null=True, blank=True, related_name='firewall_rule_source_zone')
    start_date = models.DateField(auto_now=True)
    type = models.CharField(max_length=100, help_text='users', default='any',null=True, blank=True,)
    isShared = models.BooleanField(help_text='is this a shared policy?', null=True, blank=True, default=False)
    pushed_to_firewall = models.BooleanField(help_text='is it presnet on firewall?', null=True, blank=True,
                                             default=False)
    tags = models.ManyToManyField(tag,related_name='firewall_rule_tags')


    class Meta:
        verbose_name_plural = "FirewallRules"
        ordering = ['creation_date']

    def __str__(self):
        return (f'{self.devicegroup} - {self.rule_instance}')



class task(models.Model):
    task_status = models.CharField(max_length=100, null=True, blank=True)
    task_search_term = models.CharField(max_length=1000, null=True, blank=True)
    task_id = models.AutoField(help_text='internal Usage', primary_key=True, )
    db_created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    creation_date = models.DateField(auto_now=True)
    job_id = models.CharField(max_length=100)
    task_description = models.CharField(max_length=100)
    myAPIKey = models.CharField(max_length=1000, null=True, blank=True)
    task_results = models.TextField(null=True, blank=True)
    sub_tasks = models.ManyToManyField('self', related_name='sub_tasks', help_text='Used for holding sub_tasks',
                                       null=True, blank=True, )
    task_rule_for_firewall = models.ManyToManyField(RuleInstance, related_name='sub_tasks', help_text='Used for holding sub_tasks',
                                       null=True, blank=True, )

class IKE_VPN(models.Model):

    ike_gateway_name = models.CharField(max_length=100, null=True, blank=True,
                                        help_text='name of gateway. ex: appian_vpn_test')
    crypto_profile = models.CharField(max_length=100, null=True, blank=True,
                                      help_text='name of IKE crypto profile in Pano', default='IKE-V2-PROFILE')
    ipsec_profile = models.CharField(max_length=100, null=True, blank=True,
                                     help_text='name of IPSEC profile in Panorama', default='IPSEC-PROFILE')
    tunnel_interface = models.ForeignKey(Firewall_Interface, on_delete=models.SET_NULL, null=True, blank=True,
                                       related_name='tunnel_interface')
    tunnel_front_door = models.ForeignKey(Firewall_Interface, on_delete=models.SET_NULL, null=True, blank=True,
                                          related_name='tunnel_source_interface')
    peer_outside_address = models.CharField(max_length=100, null=True, blank=True, help_text='IP address of endpoint')

    def __str__(self):
        return self.ike_gateway_name
