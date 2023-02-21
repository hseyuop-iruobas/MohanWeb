#does exactly what you think it does

import http.client
import ssl
import xmltodict
from prettytable import PrettyTable

from . models import task
from . vars import panorama_server
import time
from celery import shared_task

 
##########Lets build some functions:
def openConnSendReq(myFW,request):
   conn = http.client.HTTPSConnection(myFW,context=ssl._create_unverified_context())
   conn.request("GET", request)
   r1 = conn.getresponse()
   data = r1.read()
   #test echo the results here
   #print(data)
   myXMLdata = xmltodict.parse(data)
   return(myXMLdata)



def RAWopenConnSendReq(myFW,request):
   conn = http.client.HTTPSConnection(myFW,context=ssl._create_unverified_context())
   conn.request("GET", request)
   r1 = conn.getresponse()
   data = r1.read().decode("utf-8")
   #test echo the results here
   #print(data)
   return(data)   

def giveTableHug(someLIST):
   ###################Prints a table    
   someLIST_Table = PrettyTable(someLIST[0].keys())
   #
   for rule in someLIST:
     someLIST_Table.add_row(rule.values())
   
   print(someLIST_Table)


def get_job_id_RoutingChange(safe_search_term, myAPIKey, firewall): 
    errorlist = []
    print(f'checking {panorama_server} for logs')
    #### now we have key we can rule world! da?
    #niet we first make job
    #generate request for log
    request = "/api/?key="+myAPIKey+"&type=log&log-type=system&nlogs=20&query="+safe_search_term
    print(f'sending : {request}')
    myXMLdata = openConnSendReq(firewall,request)
    print(f'this should dhave my xml data ************************************')
    print(myXMLdata)
    jobID = myXMLdata['response']['result']['job']
    return jobID



@shared_task
def get_job_data_from_device(myAPIKey, task_id):
       parenttask = task.objects.filter(task_id = task_id)[0]
       parenttask.task_status = 'Started'
       parenttask.save()
       parenttask = task.objects.filter(task_id = task_id)[0]
       taskslists = parenttask.sub_tasks.all()
       for mytask in taskslists:
           print(f'found the following task {task}')
           ###now we have job id we rule world? da?
           #niet we made job now we get job
           #generate request to obtain the job we made above

           print(f'job id is: {mytask.job_id}')
           request = "/api/?key="+myAPIKey+"&type=log&action=get&job-id="+str(mytask.job_id)
           time.sleep(30)
           myXMLdata = RAWopenConnSendReq(mytask.task_search_term,request)
           mytask.task_results = (myXMLdata) #the response adds a B and a tilt thing removing those
           mytask.save()
       
       parenttask.task_status = 'Completed'
       parenttask.save()







def get_job_id_ReSrcDstLogs(safe_search_term, myAPIKey): 
    errorlist = []
    print(f'checking {panorama_server} for logs')
    #### now we have key we can rule world! da?
    #niet we first make job
    #generate request for log
    request = "/api/?key="+myAPIKey+"&type=log&log-type=traffic&nlogs=100&query="+safe_search_term
    print(f'sending : {request}')
    myXMLdata = openConnSendReq(panorama_server,request)
    print(f'this should dhave my xml data ************************************')
    print(myXMLdata)
    jobID = myXMLdata['response']['result']['job']
    return jobID


def get_job_id_SrcDstLogsv2(search_term, myAPIKey, number_of_logs):
    errorlist = []
    print(f'checking {panorama_server} for logs')
    #### now we have key we can rule world! da?
    # niet we first make job
    # generate request for log
    request = "/api/?key=" + myAPIKey + "&type=log&&nlogs={number_of_logs}&log-type=traffic&query={search_term}".format(search_term = search_term, number_of_logs=number_of_logs)
    print(f'sending : {request}')
    myXMLdata = openConnSendReq(panorama_server, request)
    print(f'this should dhave my xml data ************************************')
    print(myXMLdata)
    jobID = ""
    try:
        jobID = myXMLdata['response']['result']['job']
    except KeyError:
        jobID = "error"

    return jobID






def get_job_id_SrcDstLogs(source, destination, port, myAPIKey): 
    errorlist = []
    print(f'checking {panorama_server} for logs')
    #### now we have key we can rule world! da?
    #niet we first make job
    #generate request for log
    if port is '0':
       request = "/api/?key="+myAPIKey+"&type=log&log-type=traffic&query=(addr.src%20in%20"+source+")%20and%20(addr.dst%20in%20"+ destination +")"
    else:
       request = "/api/?key="+myAPIKey+"&type=log&log-type=traffic&query=(addr.src%20in%20"+source+")%20and%20(addr.dst%20in%20"+ destination +")%20and%20(port%20eq%20"+port+")"
    print(f'sending : {request}')
    myXMLdata = openConnSendReq(panorama_server,request)
    print(f'this should dhave my xml data ************************************')
    print(myXMLdata)
    jobID = ""
    try:
       jobID = myXMLdata['response']['result']['job']
    except KeyError:
        jobID = "error"
    
    return jobID

@shared_task
def get_job_data_fromPanorama(myAPIKey, jobID, task_id):
       mytask = task.objects.filter(task_id = task_id)[0]
       print(f'found the following task {task}')
       ###now we have job id we rule world? da?
       #niet we made job now we get job
       #generate request to obtain the job we made above
       mytask.task_status = 'Started'
       mytask.save()
       mytask = task.objects.filter(task_id = task_id)[0]
       print(f'job id is: {jobID}')
       if 'error' in jobID:
           mytask.task_results = "Error Occuree"
           mytask.save()
           mytask.task_status = 'Completed'
       else:
            request = "/api/?key="+myAPIKey+"&type=log&action=get&job-id="+jobID
            time.sleep(30)
            myXMLdata = RAWopenConnSendReq(panorama_server,request)
       
            mytask.task_results = (myXMLdata) #the response adds a B and a tilt thing removing those
            mytask.task_status = 'Completed'
            mytask.save()


