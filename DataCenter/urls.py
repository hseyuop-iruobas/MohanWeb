from django.urls import path, include
from DataCenter import views



#shared views across all
urlpatterns = [
    path('', views.index, name='index'),
    path('search/', views.searchboxresult, name='SEARCHRESULT'),
    path('search/<str:searched>', views.searchboxresult_geturl, name='SEARCHRESULTGET'),
    path('search/and/replace', views.searchAndReplaceView, name='SEARCHANDREPLACEVIEW'),
    path('search/and/replace/object', views.searchObjectResAPI, name='SEARCHOBJECTGETRULES'),
    path("select2/", include("django_select2.urls")),
    path("ajax/getLocations", views.getLocations, name = 'AJAXGetLOCATIONSFULLLIST'),
    path("ajax/getDataCenters", views.getDataCenters, name = 'AJAXGetDATACENTERSFULLLIST'),
    path("ajax/getFirewalls", views.getFirewallsDataCenter, name = 'AJAXGetFirewalls_DC_Specific'),
    path("ajax/getoutsideinterfaces", views.getoutsideinterfaces, name = 'AJAXGetOUTSIDEINTERFACE_FW_SPECIFIC'),
    path("ajax/gettunnelinterfaces", views.gettunnelinterfaces, name='AJAXGetTunnelInterfaces_FW_SPECIFIC'),
]
#DataCenter URLS
urlpatterns += [path('vlans/', views.VlanListView.as_view(), name='VLANLIST'),
    path('vlans/<int:pk>', views.VlanDetailView.as_view(), name = 'VLANDETAILS'),
    path('vlan_table/', views.vlanTableView, name = 'VLANTABLEVIEW'),
    path('vlandatacenter/<int:data_center_id>/', views.vlanTableViewDataCenter, name='VLANTABLEDATACENTER'),
    path('change/log/<int:pk>', views.getchangeLog, name = 'GETCHANGELOGJSON'),
    path('updatemydatabasefromswitch/',views.UpdateVlanDatabaseFromSwitch, name='UPDATEVNDATABASEFROMSWITCH'),
    path('tenants/', views.TenantListView.as_view(), name='TENANTLIST'),
    path('tenants/<int:pk>', views.TenantDetailView.as_view(), name = 'TENANTDETAILS'),
]

#########################################
#FirewallRules Related items


###RITM
urlpatterns +=[
path('RITM/', views.RITMListView.as_view(), name = 'RITMLIST'),
path('RITM/<str:pk>', views.RITMDetailView.as_view(), name = 'RITMDetails'),
path('RITM/Create/', views.createRITM, name = 'RITMCreate'),
path('RITM/Update/<str:pk>', views.updateRITM, name = 'RITMupdate'),
path('RITM/merge/', views.mergeRuleInstances, name = 'MERGERULEINSTANCES'),
path('RITM/clone/', views.cloneRuleInstance, name = 'CLONETHERULES'),
path('RITM/replicate/', views.replicateRuleInstance, name = 'REPLICATERULES'),
]
###Change
urlpatterns +=[
path('change/', views.ChangeListView, name = 'CHANGELIST'),
path('change/create/', views.createCHANGEGeneralForm, name = 'CHANGECreate'),
path('change/create/firewall', views.FirewallcreateCHANGE, name = 'CHANGECreateFirewall'),
path('change/create/location_vpn', views.LocationVPNcreateCHANGE, name = 'CHANGECreateLocationVPN'),
path('change/<int:pk>', views.ChangeDetailView.as_view(), name = 'CHANGEDETAILS'),
path('change/update/<int:pk>', views.UpdateChange, name='CHANGEUpdate'),
path('change/checksnowstatus/<int:pk>', views.checksnowstatus, name = 'CHECKSNOWSTATUS'),

]

####Object

urlpatterns +=[
    path('object/create/address', views.createObject, name='OBJECTCreate'),
    path('object/create/addressgroup', views.createAddressGroup, name='OBJECTCreateAddressGroup'),
    path('object/create/addressgroup/<int:pk>', views.AddressGroupViewDetail, name='GETADDRESSGROUPDETAIL'),
    path('object/update/<int:pk>', views.updateOBJECT, name='OBJECTupdate'),
    path('object/', views.ObjectListView.as_view(), name='OBJECTLIST'),
    path('object/<int:pk>', views.ObjectDetailView.as_view(), name='OBJECTDETAILS'),
    path('object/panoobject/<str:pano_object_name>', views.getPanoObjectDetail, name='GETPANOOBJECTNAME'),
    path('object/panoobjectgroup/<str:pano_object_name>', views.getPanoObjectGroupDetail,
         name='GETPANOOBJECTGROUPNAME'),
    path('api/object/pano/', views.getPanoValueObjectNameAPI, name='GETPANOVALUEOBJECTNAMEAPI'),
    path('api/objectgroup/pano/', views.getPanoValueObjectGroupNameView, name='GETPANOVALUEOBJECTGROUPNAMEVIEW'),
    path('api/update/pano/', views.pushObjectfromDBtoPanoama, name='PUSHOBJECTFROMDBTOPANORAMA'),
    path('object/guestobjectlocation/', views.guessObjectLocation, name='GUESSOBJECTLOCATION')
]



#####services
urlpatterns +=[
    path('service/', views.ServiceListView.as_view(), name='SERVICELIST'),
    path('service/<int:pk>', views.ServiceDetailView.as_view(), name='SERVICEDETAILS'),
    path('service/create/', views.createSERVICE, name='SERVICECreate'),
    path('service/update/<int:pk>', views.updateSERVICE, name='SERVICEupdate'),
    ]

####################################

#query related items
urlpatterns +=[
    path('searchlogs/new', views.searchPanoLogs, name = 'NEWSEARCHLOG'),
    path('searchlogsover9000/new', views.searchPanoLogsupto5000SingleAddress, name = 'NEWSEARCHLOGover90000'),
    path('mytasks/', views.MyTasksList, name = 'VIEWMYTASKSLISTS'),
    path('mytasks/<int:pk>', views.MyTaskDetails, name = 'MYTASKDETAILS'),
    path('searchlogs/rerun/<int:pk>', views.ReRunSearchPanoLogs, name = 'RERUNSEARCHLOG'),
    path('WhenDidDCUGoDown/', views.getAWSRoutingChange, name = 'WHENDIDDCUGODOWN'),
    path('TestFlow/', views.testFirewallFlow, name = 'TESTFIREWALLFLOW'),
    path('vpn/create', views.createIKEVPN, name='CREATEVPN'),
    path('EDLtoObjectGroup/create', views.EDLtoObjectGroupView, name='EDLTOObJECTGROUPVIEW'),
]
