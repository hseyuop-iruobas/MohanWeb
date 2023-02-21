from django.urls import path, include, re_path
from rest_framework import routers
from api.views import *


router = routers.DefaultRouter()
router.register(r'ObjectViewSet', Object_ViewSet)
router.register(r'Firewall_InterfacesViewSet', Firewall_Interface_ViewSet)
router.register(r'ServicesViewSet', Service_ViewSet)
router.register(r'FirewallRulesViewSet', FirewallRules_ViewSet)
router.register(r'RuleInstanceViewSet', RuleInstance_ViewSet)
router.register(r'ChangesViewSet', Change_ViewSet)
router.register(r'tagsViewSet', tag_ViewSet)
router.register(r'secZonesViewSet', secZone_ViewSet)
router.register(r'locationsViewSet', Location_ViewSet)
router.register(r'routingBubblesViewSet', routingBubble_ViewSet)
router.register(r'devicegroupsViewSet', device_group_ViewSet)
router.register(r'FirewallsViewSet', Firewall_ViewSet)
router.register(r'VirtualRoutersViewSet', VirtualRouter_ViewSet)
router.register(r'templatesViewSet', firewall_template_model_serializer_ViewSet)



urlpatterns = [
    path('', include(router.urls)),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('objects/', ObjectList.as_view(),name="OBJECTLISTAPI"),
    path('object/<str:pk>/', ObjectDetail.as_view()),
    path('firewall_interfaces/', Firewall_InterfaceList.as_view(), name="FIREWALL_INTERFACELIST_API"),
    path('firewall_interface/<str:pk>/', Firewall_InterfaceDetail.as_view()),
    path('services/', ServiceList.as_view(), name="SERVICE_API"),
    path('service/<str:pk>/', ServiceDetail.as_view()),
    path('FirewallRules/', FirewallRulesList.as_view(), name="FIREWALLRULES_API"),
    path('FirewallRule/<str:pk>/', FirewallRulesDetail.as_view()),
    path('RuleInstances/', RuleInstanceList.as_view(), name="RULEINSTANCES_API"),
    path('RuleInstance/<str:pk>/', RuleInstanceDetail.as_view()),
    path('Changes/', ChangeList.as_view(), name="CHANGE_API"),
    path('Change/<str:pk>/', ChangeDetail.as_view()),
    path('tags/', tagList.as_view(), name="TAG_API"),
    path('tag/<str:pk>/', tagDetail.as_view()),
    path('secZones/', secZoneList.as_view(), name="SECZONE_API"),
    path('secZone/<str:pk>/', secZoneDetail.as_view()),
    path('Locations/', LocationList.as_view(), name="LOCATION_API"),
    path('Location/<str:pk>/', LocationDetail.as_view()),



]
