from django.db import models

class DataCenter(models.Model):
    datacenter_Name = models.CharField(max_length=32, help_text='Name of the datacenter')
    datacenter_location = models.CharField(max_length=32, help_text='Location / address')

    def getName(self):
        return self.datacenter_Name

    def __str__(self):
        return self.datacenter_Name


class Vlan(models.Model):
    vlan_name = models.CharField(max_length=32, help_text='Name of the vlan')
    vlan_datacenter = models.ForeignKey(DataCenter, null=True, related_name="vlan_datacenter",
                                        db_column='vlan_datacenter', on_delete=models.CASCADE)
    vlan_number = models.IntegerField()


    def getDictionary(self):
        dict = {}
        dict['vlan_name'] = self.vlan_name
        dict['vlan_number'] = self.vlan_number
        dict['vlan_datacenter'] = self.vlan_datacenter.id
        return dict

    def __str__(self):
        if self.vlan_datacenter:
            return f'{self.vlan_name}_{self.vlan_number}_{self.vlan_datacenter.datacenter_Name}'
        else:
            return f'{self.vlan_name}_{self.vlan_number}_NO-DC-Assigned-FIX'

    def getName(self):
        return self.vlan_name

    def getID(self):
        return self.vlan_number

class Switch(models.Model):
    switch_name = models.CharField(max_length=100, help_text='ex. BRM-LEAF-R13-1')
    switch_datacenter = models.ForeignKey(DataCenter, null=True, related_name="switch_datcenter",
                                        db_column='switch_datacenter', on_delete=models.CASCADE)

    def __str__(self):
        return self.switch_name


class Tenant(models.Model):
    vrf_name = models.CharField(max_length=32, help_text='tenant/vrf name')
    vrf_rd_value = models.CharField(max_length=32, help_text='tenant/vrf rd value')
    vrf_bgp_bundle_name = models.CharField(max_length=32, help_text='tenant/vrf BGP Bundle name')
    vrf_vlans = models.ManyToManyField(Vlan, null=True, blank=True, help_text="vlans that belong to this tenant/vrf",
                                       related_name="vrf_vlans")
    vrf_exists_on_edge = models.BooleanField(help_text='should this be built on the EDGE nodes?', default=False)

    class Meta:
        ordering = ['vrf_name']

    def getDictionary_vlanID(self):
        dict = {}
        dict['vrf_name'] = self.vrf_name
        dict['vrf_rd_value'] = self.vrf_rd_value
        dict['vrf_bgp_bundle_name'] = self.vrf_bgp_bundle_name
        vlan_list = []
        for vlan in self.vrf_vlans.all():
            vlan_list.append(str(vlan.getID()))

        dict['vrf_vlans'] = ",".join(vlan_list)
        return dict

    def getName(self):
        return self.vrf_name

    def __str__(self):
        return self.vrf_name





class SNOWChangeTemplate(models.Model):
    short_description = models.CharField(max_length=80, help_text='Short Description')
    category = models.CharField(max_length=80, help_text='Change Template Name here')
    assignment_group = models.CharField(max_length=80, help_text='assignment group')
    type = models.CharField(max_length=80, help_text='Starndard, emergency, etc')
    priority = models.CharField(max_length=80, help_text='High, Med, Low, etc')
    impact = models.CharField(max_length=80, help_text='YUGE, Minor, etc')
    u_failure_likelihood = models.CharField(max_length=80, help_text='High, Low, etc')
    cmdb_ci = models.CharField(max_length=80, help_text='Eventually maybe a CMDB_CI')
    description = models.CharField(max_length=4000, help_text='description - the detailed stuff')
    business_service = models.CharField(max_length=4000, help_text='description - the detailed stuff',
                                        default='Network Services')
    u_purpose_goal = models.CharField(max_length=80, help_text='Purpose of the Change')
    justification = models.CharField(max_length=80, help_text='Justification - this will get appended with RITM#s')
    u_environment_applied = models.CharField(max_length=80, help_text='environments this applies to')
    u_implemented_test = models.BooleanField(help_text='Yes/No')
    u_test_by_qa = models.BooleanField(help_text='Yes/No')

    u_result_of_request = models.BooleanField(help_text='Yes/No', default=True)
    u_request_item = models.CharField(max_length=80, help_text='environments this applies to', default="RITM0000000")
    u_impact_business_unit = models.CharField(max_length=4000, help_text='description - the detailed stuff',
                                              default='No Impact')
    u_impact_member = models.CharField(max_length=4000, help_text='description - the detailed stuff',
                                       default='No impact')

    u_tested_by_business = models.BooleanField(max_length=32, help_text='Yes/No')
    u_detailed_sadd = models.BooleanField(max_length=32, help_text='Yes/No')
    u_downstream_apps_services = models.BooleanField(max_length=32, help_text='Yes/No')
    u_service_desk_support_req = models.BooleanField(max_length=32, help_text='Yes/No')
    u_tested_by_qa = models.BooleanField(max_length=32, help_text='Yes/No')
    u_prod_support_req = models.BooleanField(max_length=32, help_text='Yes/No')
    risk_impact_analysis = models.BooleanField(max_length=32, help_text='Yes/No')
    u_affect_bcp_services = models.BooleanField(max_length=32, help_text='Yes/No')
    u_take_system_offline = models.BooleanField(max_length=32, help_text='Yes/No')
    u_could_extend_overnight = models.BooleanField(max_length=32, help_text='Yes/No')
    u_system_server_reboot_required = models.BooleanField(max_length=32, help_text='Yes/No')
    u_non_member_impact = models.CharField(max_length=80, help_text='ex: Network Services')
    u_cyber_security_risk = models.CharField(max_length=80, help_text="the Cyber's risk")
    test_plan = models.CharField(max_length=80, help_text='Ze plan for Test')
    implementation_plan = models.CharField(max_length=80, help_text='Ze Implementation Plan')
    u_production_validation = models.CharField(max_length=80, help_text='Validatoin Plan')

    u_rollback_tested = models.BooleanField(max_length=32, help_text='Yes/No')
    backout_plan = models.CharField(max_length=80, help_text='Roll the chnage back how?')
    u_tech_review_attach = models.BooleanField(max_length=32, help_text='Yes/No')
    u_known_issues = models.BooleanField(max_length=32, help_text='Yes/No')
    u_technical_approvers = models.CharField(max_length=80, help_text="approver's name")
    u_technical_approver_Freeze = models.CharField(max_length=80, help_text="addital freeze approver's name",
                                                   default="someone cool")

    def __str__(self):
        return self.short_description

# class Interfaces(models.Model):
#    interface_