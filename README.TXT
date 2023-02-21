*** MACHINE OPTIMIZATION HUMAN AUTOMATED NETWORKING - Web based django app ***
###
# note that you need REDIST and CELERY installed. in dev you can run these using celery -A MohanWeb worker ... 
# however if you decide to go down the prod/webserver/celery/redist thing.. read up some links.. 
# Following guide assumes that you ahve already populated the following information into Mohan's database:
# DataCenters, Switches, Device_group_models, Tempaltes_models, Firewalls
# FirewallRules/vars.py needs to be filled out too!
# use the admin page after doing your first migration, super user creation to add them in 
# then and only THEN will the scripts below work
# i found this one very useful:
# https://docs.celeryq.dev/en/stable/getting-started/first-steps-with-celery.html
###

#####################
There is a sample database loaded here. Assuming you are already running celery/redis
either use administrator/Cisco12345 to login to admin/front end
or just run the command 'python3 manage.py createsuperuser' and make a new one
#####################
######
#Before you start running anything:
#fill out FirewallRules/vars.py ; read through all of it and fill as much as you can.
#go to FirewallRUles/tools.py; change Line 29 from "mystatics = staticVariables() to mystatics = None"
#the above edit needs to be put back to normal once the tables and databases are in place;
#then run:
python3 manage.py makemigrations; python3 manage.py migrate; python3 manage.py createsuperuser


#now you are in theory ready to load the database:

python3 manage.py shell

#Mohan build:
#start with giving it your username and password.. its OK .. trust it.. 
#also once again assuming you have filled out the items above. 

from DataCenter.models import *
from FirewallRules.models import *
from getpass import getpass
from FirewallRules.populateDBFirewallsFromPano import *
username = '' #your username?
password = getpass() #your password


####IF YOU have arista switches OTHERWISE SKIP and GO TO NEXT Section "get the pano stuff"
#synchronize vlan and tenant database with switches
switches = Switch.objects.all()
for switch in switches:
   synchronizeVlanDBFromAristaSwitch(switch, username, password)
   synchronizeTenantDBFromAristaSwitch(switch, username,password)
   
######################## NEW SECTION ##############
###### get the pano stuff now



from FirewallRules.vars import panorama_server
from FirewallRules.tools import panorestapi
myapikey = panorestapi(panorama_server, username, password).apikey()

#start with services 
service_list = getallservices(myapikey, panorama_server)
synchronizeDBServices(service_list)


#now do the VRs
myFirewalls = Firewall.objects.all()
for firewall in myFirewalls:
   #key is good for 5 minutes some operations might take longer! so get new key every time
   myapikey = panorestapi(panorama_server, username, password).apikey()
   addVirtualRoutersSpecifyFWList(myapikey, [firewall])   

#### DELETE extra VRs... if you have firewalls with multiple VSYS you need to worry about this
for firewall in myFirewalls:
   #key is good for 5 minutes some operations might take longer! so get new key every time
   myapikey = panorestapi(panorama_server, username, password).apikey()
   addSecurityZones(myapikey, [firewall])

#### Delete DUPLICATE security zones.. I dont know why this is happening but i suspect the multiple VR is the issue in my config and how Pano responds back to security zones queries and maybe multiple VRs+VSyS?
### oddly enough possibly deleting the extra VRs in the prev step resolved the duplicate thing (?)_ 

####BEFORE GOING FURTHER YOU NEED TO ENTER LOCATIONS / VPN SITES, ETC 
##########################
########################
## in admin page 
## correct/ set your locations / paths 
## ONLY WHEN YOU have SETUP your FULL NETWORK (firewalls, interfaces, security zones, locations (VPNs, redundant paths, etc..)
##### create objects: 'RFC_1918', 'RFC_1918_CORE' and 'any' with type: SPECIAL.
##### create a security zone called "any" with NO firewalls or devices attached to it. This will be used for 'shared' policies.
##### create a security zone called "any" for EACH firewall you have. This will be used for RFC_1918_COREs in theory. 
## GO TO NEXT section where you load objects. If you mess up the above, delete all objects AND object groups and start over. 

myapikey = panorestapi(panorama_server, username, password).apikey()
object_list = getallobjectswithtag(myapikey, panorama_server)
synchronizeDB(object_list)

#get all the object groups
myapikey = panorestapi(panorama_server, username, password).apikey()
object_group_data = getallobjectGroupswithtag(myapikey, panorama_server)
synchronizeDBObjectGroup(object_group_data)

#consolidate tags
consolidatetags()
consolidatetagsDB()

#####now finish up the config in Admin page for your various routing_bubble needs.
#####Configure inside interface flag on Firewall_Interfaces; these are the ones pointing to inside of your network 
#####and in theory you should be good to go 


###############
In theory you are now done, and once you run the server 
python3 manage.py runserver 0.0.0.0:31338 

you can reach it by going to:
0.0.0.0:31338/admin (for admin page)
0.0.0.0:31338/datacenter (for front end)
0.0.0.0:31338/api (for api search/)
