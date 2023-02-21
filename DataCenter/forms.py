from django_select2 import forms as s2forms
from django.forms.widgets import PasswordInput
from FirewallRules.models import (RuleInstance,Change, Object,
                                  Service, IKE_VPN,
                                  AddressGroup)
from DataCenter.models import (Tenant,)
from django import forms
import ipaddress
#####################################################################################
'''
    widgets go here!
'''
class objectwidget(s2forms.ModelSelect2MultipleWidget):
   search_fields = ["object_name__icontains", "object_value__icontains",]



class RITMwidget(s2forms.ModelSelect2MultipleWidget):
   search_fields = ["id__icontains", "rule_name__icontains",]


class LocationWidget(s2forms.ModelSelect2MultipleWidget):
   search_fields = ["id__icontains", "location_name__icontains",]

class secZoneWidget(s2forms.ModelSelect2Widget):
   search_fields = ["seczone_name__icontains", ]

class Firewall_InterfaceWidget(s2forms.ModelSelect2Widget):
   search_fields = ["Firewall_Interface_name__icontains", "Firewall_Interface_value__icontains"]


class stagsWidget(s2forms.ModelSelect2MultipleWidget):
   search_fields = ["tag_name__icontains",]


class servicewidget(s2forms.ModelSelect2MultipleWidget):
   search_fields = ["service_name__icontains", "service_dest_port__icontains",]

class DateInputWidget(forms.DateInput):
     input_type = 'date'

##################################################################


'''
    FirewallRUle app forms go here cause im lazy and dont want to import from Firewallrules.forms
'''

class RuleInstanceForm(forms.ModelForm):
   '''
      this form is used to capture the necessary fields needed to build a Ruleinstance manually
      it provides ability to use the select2 widgets for quick lookups
   '''

   class Meta:
      model = RuleInstance
      fields = ['id', 'rule_name', 'rule_description',
                'source', 'dest', 'service',
                'application', 'source_user', 'urls',
                'rule_duration', 'start_date',
                ]

      widgets = {"source": objectwidget,
                 "dest": objectwidget,
                 "service": servicewidget,
                 'start_date': DateInputWidget,
                 'rule_duration': s2forms.Select2Widget,
                 'rule_name': forms.TextInput(attrs={'maxlength': '60', }),
                 'id': forms.TextInput(attrs={'maxlength': '14', }), #RITMxxx is 10 digits; we may append -xxx
                 }

   def clean(self):
      '''
         clean function needed to ensure that both source AND dest are not set to RFC1918 or any thats BAD!
         those conditions would basically create a allow any any rule that is not cool
      '''
      cleaned_data = super().clean()
      source_list = cleaned_data.get('source')
      dest_list = cleaned_data.get('dest')
      source_any = False
      dest_any = False
      for source in source_list:
         if source.object_name in ('RFC_1918', 'any'):
            source_any = True
            break
      for destination in dest_list:
         if destination.object_name in ('RFC_1918', 'any'):
            dest_any = True
            break
      if source_any and dest_any:
         #seems like we are dealing with an idiot, call them that and throw an error!
         raise forms.ValidationError(
            'please turn in your badge. You want any any? my programmer told me to make fun of you')
      return cleaned_data

class ChangeInstanceFormv2(forms.ModelForm):

    class Meta:
        model = Change
        fields = ['Change_Number', 'Requests']
        widgets = {'Requests': RITMwidget, }


    def __init__(self, *args, **kwargs):
        super(ChangeInstanceFormv2, self).__init__(*args, **kwargs)
        self.fields['Change_Number'].required = False


class ChangeInstancePushForm(forms.ModelForm):
    pano_username = forms.CharField(max_length=30, help_text='your Panorama Username')
    pano_password = forms.CharField(widget=PasswordInput(), help_text='your Panorama Password')

    class Meta:
        model = Change
        fields = ['Change_Number', 'pano_username', 'pano_password', 'Requests']
        widgets = {'Requests': RITMwidget, }

    def __init__(self, *args, **kwargs):
        super(ChangeInstancePushForm, self).__init__(*args, **kwargs)
        self.fields['Change_Number'].required = False


####################OBJECT FORM ##########################
class CreateObjectForm(forms.ModelForm):
    ''' used to create objects front end'''
    object_description = forms.CharField(widget=forms.TextInput(attrs={'id': 'object_description'}))
    object_name = forms.CharField(widget=forms.TextInput(attrs={'id': 'object_name'}))
    form_action = forms.CharField(widget=forms.TextInput(), required=False)

    class Meta:
        model = Object
        fields = ['object_name', 'object_type', 'object_value', 'object_location', 'object_group_members',
                  'object_description', 'tags', 'object_firewall_interface']
        widgets = {'object_group_members': objectwidget, 'object_type': s2forms.Select2Widget,
                   'object_location': s2forms.Select2Widget, 'object_fw': s2forms.Select2Widget,
                   'object_firewall_interface': Firewall_InterfaceWidget, 'tags': stagsWidget}


class CreateAddressGroupForm(forms.ModelForm):
    object_name = forms.CharField(widget=forms.TextInput(attrs={'id': 'object_name'}))


    class Meta:
        model = AddressGroup
        fields = ['Object_in_DB','object_group_members']
        widgets = {'object_group_members': objectwidget,}

    def __init__(self, *args, **kwargs):
        super(CreateAddressGroupForm, self).__init__(*args, **kwargs)
        self.fields['Object_in_DB'].required = False


###### Service Form #######

class ServiceInstanceForm(forms.ModelForm):
   class Meta:
       model = Service
       fields = ['service_name', 'service_protocol', 'service_dest_port', 'service_description', 'service_tag']
       widgets = {'service_protocol':s2forms.Select2Widget,}


####pano logging stuff that takes in some data and makes pano query possible

class CheckTheLogsForm5000EntriesSingleAddress(forms.Form):
    source_address = forms.CharField(widget=forms.TextInput())


class CheckTheLogsForm(forms.Form):
    source_address = forms.CharField(widget=forms.TextInput())
    destination_address = forms.CharField(widget=forms.TextInput())
    port_number = forms.CharField(widget=forms.TextInput())
    start_date = forms.DateField(widget=DateInputWidget())

    def __init__(self, *args, **kwargs):
        super(CheckTheLogsForm, self).__init__(*args, **kwargs)
        self.fields['start_date'].required = False

    class Meta:
        widgets = {'start_date': DateInputWidget()}

    def clean_source_address(self):
        source_address = self.cleaned_data.get('source_address')
        if source_address is None:
            raise forms.ValidationError('Hi, I need both source AND destination to work')
        else:
            try:
                v4source_address = ipaddress.IPv4Network(source_address)
                return source_address
            except (ipaddress.AddressValueError):
                raise forms.ValidationError('Whatever you put in source was not ipv4')

    def clean_destination_address(self):
        destination_address = self.cleaned_data.get('destination_address')
        if destination_address is None:
            raise forms.ValidationError('Hi, I need both source AND destination to work')
        else:
            try:
                v4source_address = ipaddress.IPv4Network(destination_address)
                return destination_address
            except (ipaddress.AddressValueError):
                raise forms.ValidationError('Whatever you put in destination was not ipv4')

    def clean_port_number(self):
        port_number = self.cleaned_data.get('port_number')
        if port_number is None:
            return None
        else:
            return port_number

#this one is funwe make direct api calls using this form's data...
class replicateRulesForm(forms.Form):
    request_label = forms.CharField(max_length=30, help_text='ex:RITM000')
    current_server = forms.CharField(widget=s2forms.ModelSelect2Widget(
        model=Object,
        search_fields=['object_name__icontains', 'object_value__icontains'], ))

    target_servers = forms.CharField(widget=s2forms.ModelSelect2Widget(
        model = Object,
        search_fields=['object_name__icontains', 'object_value__icontains'],))




class checkFirewallFlow(forms.Form):

    pano_username = forms.CharField(max_length=30, help_text='your Panorama Username')
    pano_password = forms.CharField(widget=PasswordInput(), help_text='your Panorama Password')
    source = forms.CharField(widget=s2forms.ModelSelect2Widget(
        model = Object,
        search_fields=['object_name__icontains', 'object_value__icontains'],
        queryset=Object.objects.filter(object_type='ip-netmask')),
        )
    dest = forms.CharField(widget=s2forms.ModelSelect2Widget(
        model=Object,
        search_fields=['object_name__icontains', 'object_value__icontains'],
        queryset=Object.objects.filter(object_type='ip-netmask')),
    )
    service = forms.CharField(widget=s2forms.ModelSelect2Widget(
        model=Service,
        search_fields=['service_name__icontains', 'service_dest_port__icontains'],
        queryset=Service.objects.filter(service_name__contains='-DST-')),
    )

class UpdateVlanDatabaseFromSwitchForm(forms.Form):
    switch_name_to_pull = forms.CharField(max_length=30, help_text='bram-leaf-r13-1')
    switch_username = forms.CharField(max_length=30, help_text='your ISE authenticated SWITCH Username')
    switch_password = forms.CharField(widget=PasswordInput(), help_text='your ISE authenticated SWITCH Password')

class UpdateTenantDatabaseFromSwitchForm(forms.Form):
    switch_name_to_pull = forms.CharField(max_length=30, help_text='bram-leaf-r13-1')
    switch_username = forms.CharField(max_length=30, help_text='your ISE authenticated SWITCH Username')
    switch_password = forms.CharField(widget=PasswordInput(), help_text='your ISE authenticated SWITCH Password')

class TenantForm(forms.ModelForm):
    arista_Switch_Username = forms.CharField(required=False)
    arista_Switch_Password = forms.CharField(widget=PasswordInput(), help_text='users passwrod', required=False)

    class Meta:
        # abstract = True
        model = Tenant
        fields = ['vrf_name', 'vrf_rd_value', 'vrf_bgp_bundle_name', 'vrf_vlans', 'vrf_exists_on_edge', ]

    def __str__(self):
        return self.vrf_name


#############################
class IKEVPNForm(forms.ModelForm):

    pano_username = forms.CharField(max_length = 30, help_text='your Panorama Username')
    pano_password = forms.CharField(widget = PasswordInput(), help_text = 'your Panorama Password')
    pre_shared_key = forms.CharField(max_length= 60, help_text='Agreed Upon Shared Key')

    class Meta:
        model = IKE_VPN
        fields = '__all__'
        widgets = {'tunnel_interface':Firewall_InterfaceWidget,'tunnel_front_door':Firewall_InterfaceWidget,}

    def __init__(self, *args, **kwargs):
        super(IKEVPNForm, self).__init__(*args, **kwargs)
        self.fields['pano_username'].required = False
        self.fields['pano_password'].required = False
        self.fields['pre_shared_key'].required = False

    def clean_ike_gateway_name(self):
        gateway_name = self.cleaned_data.get('ike_gateway_name')
        if len(IKE_VPN.objects.filter(ike_gateway_name=gateway_name))>0:
            raise forms.ValidationError('Set unique name please (－‸ლ)')
        else:
            return gateway_name



    def clean_tunnel_secZone(self):
        print(self.cleaned_data.get('tunnel_secZone'))
        return self.cleaned_data.get('tunnel_secZone')

############################################
class EDLtoObjectGroupForm(forms.Form):
    commaSprtList = forms.CharField(label="the IP list *",
                                        widget=forms.Textarea())
    object_group_name = forms.CharField(label="Object Group Name",)
    suggested_prepend_object_name = forms.CharField(label="ex: Azure_AD", )