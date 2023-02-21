

# Create your views here.
#
from django.shortcuts import render
from rest_framework import status
from rest_framework import viewsets
from rest_framework import permissions
from FirewallRules.models import Object, Firewall_Interface, Service, FirewallRules, RuleInstance, Change, tag, secZone, Location
from FirewallRules.models import routingBubble, device_group_model, Firewall
from api.serializers import Object_Serializer, FirewallRules_Serializer, Firewall_Interface_Serializer
from api.serializers import Service_Serializer, RuleInstance_Serializer, Change_Serializer
from api.serializers import tag_Serializer,Location_Serializer,routingBubble_Serializer
from api.serializers import secZone_Serializer,device_group_model_Serializer,firewall_template_model_Serializer
from api.serializers import Firewall_Serializer, VirtualRouter_Serializer, VirtualRouter,firewall_template_model
from rest_framework import mixins
from rest_framework import generics
from rest_framework.response import Response
from rest_framework.decorators import api_view
from django.contrib.auth.mixins import LoginRequiredMixin
# Create your views here.


##############################
'''viewsets build in registers under /api/api'''
class Location_ViewSet(viewsets.ModelViewSet):
    """
    API END PINT AT ALLOWS OBJECTS TO BE EDITED AND VIEWED
    """
    queryset = Location.objects.all()
    serializer_class = Location_Serializer
    permission_classes = [permissions.IsAuthenticated]


class routingBubble_ViewSet(viewsets.ModelViewSet):
    """
    API END PINT AT ALLOWS OBJECTS TO BE EDITED AND VIEWED
    """
    queryset = routingBubble.objects.all()
    serializer_class = routingBubble_Serializer
    permission_classes = [permissions.IsAuthenticated]


class device_group_ViewSet(viewsets.ModelViewSet):
    """
    API END PINT AT ALLOWS OBJECTS TO BE EDITED AND VIEWED
    """
    queryset = device_group_model.objects.all()
    serializer_class = device_group_model_Serializer
    permission_classes = [permissions.IsAuthenticated]




class Firewall_ViewSet(viewsets.ModelViewSet):
    """
    API END PINT AT ALLOWS OBJECTS TO BE EDITED AND VIEWED
    """
    queryset = Firewall.objects.all()
    serializer_class = Firewall_Serializer
    permission_classes = [permissions.IsAuthenticated]


class VirtualRouter_ViewSet(viewsets.ModelViewSet):
    """
    API END PINT AT ALLOWS OBJECTS TO BE EDITED AND VIEWED
    """
    queryset = VirtualRouter.objects.all()
    serializer_class = VirtualRouter_Serializer
    permission_classes = [permissions.IsAuthenticated]



class firewall_template_model_serializer_ViewSet(viewsets.ModelViewSet):
    """
    API END PINT AT ALLOWS OBJECTS TO BE EDITED AND VIEWED
    """
    queryset = firewall_template_model.objects.all()
    serializer_class = firewall_template_model_Serializer
    permission_classes = [permissions.IsAuthenticated]




class Object_ViewSet(viewsets.ModelViewSet):
    """
    API END PINT AT ALLOWS OBJECTS TO BE EDITED AND VIEWED
    """
    queryset = Object.objects.all()
    serializer_class = Object_Serializer
    permission_classes = [permissions.IsAuthenticated]


class Firewall_Interface_ViewSet(viewsets.ModelViewSet):
    """
    API END PINT AT ALLOWS OBJECTS TO BE EDITED AND VIEWED
    """
    queryset = Firewall_Interface.objects.all()
    serializer_class = Firewall_Interface_Serializer
    permission_classes = [permissions.IsAuthenticated]


class Service_ViewSet(viewsets.ModelViewSet):
    """
    API END PINT AT ALLOWS OBJECTS TO BE EDITED AND VIEWED
    """
    queryset = Service.objects.all()
    serializer_class = Service_Serializer
    permission_classes = [permissions.IsAuthenticated]


class FirewallRules_ViewSet(viewsets.ModelViewSet):
    """
    API END PINT AT ALLOWS OBJECTS TO BE EDITED AND VIEWED
    """
    queryset = FirewallRules.objects.all()
    serializer_class = FirewallRules_Serializer
    permission_classes = [permissions.IsAuthenticated]


class RuleInstance_ViewSet(viewsets.ModelViewSet):
    """
    API END PINT AT ALLOWS OBJECTS TO BE EDITED AND VIEWED
    """
    queryset = RuleInstance.objects.all()
    serializer_class = RuleInstance_Serializer
    permission_classes = [permissions.IsAuthenticated]


class Change_ViewSet(viewsets.ModelViewSet):
    """
    API END PINT AT ALLOWS OBJECTS TO BE EDITED AND VIEWED
    """
    queryset = Change.objects.all()
    serializer_class = Change_Serializer
    permission_classes = [permissions.IsAuthenticated]


class tag_ViewSet(viewsets.ModelViewSet):
    """
    API END PINT AT ALLOWS OBJECTS TO BE EDITED AND VIEWED
    """
    queryset = tag.objects.all()
    serializer_class = tag_Serializer
    permission_classes = [permissions.IsAuthenticated]

class secZone_ViewSet(viewsets.ModelViewSet):
    """
    API END PINT AT ALLOWS OBJECTS TO BE EDITED AND VIEWED
    """
    queryset = secZone.objects.all()
    serializer_class = secZone_Serializer
    permission_classes = [permissions.IsAuthenticated]

##############################################
'''better api views using classes and mixins!'''
class ObjectList(LoginRequiredMixin,mixins.ListModelMixin,
                  mixins.CreateModelMixin,
                  generics.GenericAPIView):
    queryset = Object.objects.all()
    serializer_class = Object_Serializer

    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)


class ObjectDetail(LoginRequiredMixin,mixins.RetrieveModelMixin,
                    mixins.UpdateModelMixin,
                    mixins.DestroyModelMixin,
                    generics.GenericAPIView):
    queryset = Object.objects.all()
    serializer_class = Object_Serializer

    def get(self, request, *args, **kwargs):
        return self.retrieve(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        '''
            to delete something we should create a change (?) and not delete here

        '''
        return Response('NOTYET BUDDY')
        # return self.destroy(request, *args, **kwargs)

#######################################
class Firewall_InterfaceList(LoginRequiredMixin,mixins.ListModelMixin,
                  mixins.CreateModelMixin,
                  generics.GenericAPIView):
    queryset = Firewall_Interface.objects.all()
    serializer_class = Firewall_Interface_Serializer

    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)


class Firewall_InterfaceDetail(LoginRequiredMixin,mixins.RetrieveModelMixin,
                    mixins.UpdateModelMixin,
                    mixins.DestroyModelMixin,
                    generics.GenericAPIView):
    queryset = Firewall_Interface.objects.all()
    serializer_class = Firewall_Interface_Serializer

    def get(self, request, *args, **kwargs):
        return self.retrieve(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        '''
            to delete something we should create a change (?) and not delete here

        '''
        return Response('NOTYET BUDDY')
        # return self.destroy(request, *args, **kwargs)

##########################################################
class ServiceList(LoginRequiredMixin,mixins.ListModelMixin,
                  mixins.CreateModelMixin,
                  generics.GenericAPIView):
    queryset = Service.objects.all()
    serializer_class = Service_Serializer

    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)


class ServiceDetail(LoginRequiredMixin,mixins.RetrieveModelMixin,
                    mixins.UpdateModelMixin,
                    mixins.DestroyModelMixin,
                    generics.GenericAPIView):
    queryset = Service.objects.all()
    serializer_class = Service_Serializer

    def get(self, request, *args, **kwargs):
        return self.retrieve(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        '''
            to delete something we should create a change (?) and not delete here

        '''
        return Response('NOTYET BUDDY')
        # return self.destroy(request, *args, **kwargs)

###########################################################################

class FirewallRulesList(LoginRequiredMixin,mixins.ListModelMixin,
                  mixins.CreateModelMixin,
                  generics.GenericAPIView):
    queryset = FirewallRules.objects.all()
    serializer_class = FirewallRules_Serializer

    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)


class FirewallRulesDetail(LoginRequiredMixin,mixins.RetrieveModelMixin,
                    mixins.UpdateModelMixin,
                    mixins.DestroyModelMixin,
                    generics.GenericAPIView):
    queryset = FirewallRules.objects.all()
    serializer_class = FirewallRules_Serializer

    def get(self, request, *args, **kwargs):
        return self.retrieve(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        '''
            to delete something we should create a change (?) and not delete here

        '''
        return Response('NOTYET BUDDY')
        # return self.destroy(request, *args, **kwargs)

###################################################################################

class RuleInstanceList(LoginRequiredMixin,mixins.ListModelMixin,
                  mixins.CreateModelMixin,
                  generics.GenericAPIView):
    queryset = RuleInstance.objects.all()
    serializer_class = RuleInstance_Serializer

    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)


class RuleInstanceDetail(LoginRequiredMixin,mixins.RetrieveModelMixin,
                    mixins.UpdateModelMixin,
                    mixins.DestroyModelMixin,
                    generics.GenericAPIView):
    queryset = RuleInstance.objects.all()
    serializer_class = RuleInstance_Serializer

    def get(self, request, *args, **kwargs):
        return self.retrieve(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        '''
            to delete something we should create a change (?) and not delete here

        '''
        return Response('NOTYET BUDDY')
        # return self.destroy(request, *args, **kwargs)

######################################################################################

class ChangeList(LoginRequiredMixin,mixins.ListModelMixin,
                  mixins.CreateModelMixin,
                  generics.GenericAPIView):
    queryset = Change.objects.all()
    serializer_class = Change_Serializer

    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)


class ChangeDetail(LoginRequiredMixin,mixins.RetrieveModelMixin,
                    mixins.UpdateModelMixin,
                    mixins.DestroyModelMixin,
                    generics.GenericAPIView):
    queryset = Change.objects.all()
    serializer_class = Change_Serializer

    def get(self, request, *args, **kwargs):
        return self.retrieve(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        '''
            to delete something we should create a change (?) and not delete here

        '''
        return Response('NOTYET BUDDY')
        # return self.destroy(request, *args, **kwargs)

##############################################################################################

class tagList(LoginRequiredMixin,mixins.ListModelMixin,
                  mixins.CreateModelMixin,
                  generics.GenericAPIView):
    queryset = tag.objects.all()
    serializer_class = tag_Serializer

    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)


class tagDetail(LoginRequiredMixin,mixins.RetrieveModelMixin,
                    mixins.UpdateModelMixin,
                    mixins.DestroyModelMixin,
                    generics.GenericAPIView):
    queryset = tag.objects.all()
    serializer_class = tag_Serializer

    def get(self, request, *args, **kwargs):
        return self.retrieve(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        '''
            to delete something we should create a change (?) and not delete here

        '''
        return Response('NOTYET BUDDY')
        # return self.destroy(request, *args, **kwargs)

###############################################################################
class secZoneList(LoginRequiredMixin,mixins.ListModelMixin,
                  mixins.CreateModelMixin,
                  generics.GenericAPIView):
    queryset = secZone.objects.all()
    serializer_class = secZone_Serializer

    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)


class secZoneDetail(LoginRequiredMixin,mixins.RetrieveModelMixin,
                    mixins.UpdateModelMixin,
                    mixins.DestroyModelMixin,
                    generics.GenericAPIView):
    queryset = secZone.objects.all()
    serializer_class = secZone_Serializer

    def get(self, request, *args, **kwargs):
        return self.retrieve(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        '''
            to delete something we should create a change (?) and not delete here

        '''
        return Response('NOTYET BUDDY')
        # return self.destroy(request, *args, **kwargs)

###############################################################################
class LocationList(LoginRequiredMixin,mixins.ListModelMixin,
                  mixins.CreateModelMixin,
                  generics.GenericAPIView):
    queryset = Location.objects.all()
    serializer_class = Location_Serializer

    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)


class LocationDetail(LoginRequiredMixin,mixins.RetrieveModelMixin,
                    mixins.UpdateModelMixin,
                    mixins.DestroyModelMixin,
                    generics.GenericAPIView):
    queryset = Location.objects.all()
    serializer_class = Location_Serializer

    def get(self, request, *args, **kwargs):
        return self.retrieve(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        '''
            to delete something we should create a change (?) and not delete here

        '''
        return Response('NOTYET BUDDY')
        # return self.destroy(request, *args, **kwargs)