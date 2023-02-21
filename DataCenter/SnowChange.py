from FirewallRules.vars import getSNOW_baseURL, getSNOW_STD_Table_Location
import requests
#from .models import SNOWChangeTemplate

import json
from celery import shared_task



class SNOWChange:
    SNOWChange_Approved = False
    SNOWChange_Completed = False

    def __init(self):
        self.SNOWChange_Approved = False
        self.SNOWChange_Completed = False



    # function builds a standard change with specific templates
    def buildStandardNetworkautomatedChange(self, SNOW_Username, SNOW_Password, Person_Name, mysnowTemplateDictionary):
        # build a URL that combines our base with the STD table
        url = getSNOW_baseURL() + getSNOW_STD_Table_Location()
        headers = {"Content-Type": "application/json", "Accept": "application/json"}

        # get our STD template into a dictionary


        # add the missing values that are dependant on when we do this :
        #Mohan / SQL is changing our Yes/No to False/True so lets go change them back ?
        for key in mysnowTemplateDictionary.keys():
            if mysnowTemplateDictionary[key] == False :
                mysnowTemplateDictionary[key] = 'No'
            if mysnowTemplateDictionary[key] == True:
                mysnowTemplateDictionary[key] = 'Yes'

        print(f'********************************'
              f'sending following dictionary:'
              f'{mysnowTemplateDictionary}'
              f'\r\n******************************')
        response = requests.post(url,
                                 auth=(SNOW_Username, SNOW_Password),
                                 headers=headers,
                                 data=json.dumps(mysnowTemplateDictionary))
        results = response.json()  # get the dictionary back here now
        print(results)
        if response.status_code == 200 or 201:
            return results['result']['number']  # send ChangeNumber Back
        else:
            print('We did not succeed in creating change')
            print(f'status code was: {response.status_code}')
            print(response.text)
            return False  # send False Back

    def getChangeSYSID(self, changenumber, SNOW_Username, SNOW_Password):
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json",
                   }
        getModelsURL = '/api/sn_chg_rest/change/standard'
        sysparam = '?number={changenumber}'.format(changenumber=changenumber)
        url = getSNOW_baseURL() + getModelsURL + sysparam
        payload = {}
        #response = requests.request("GET", url, headers=headers, data=payload)
        response = requests.get(url, auth=(SNOW_Username, SNOW_Password), headers=headers)
        results = response.json()
        #print(response.text)
        print(results)
        #replacing results['result'][0]['sys_id']['value'] that throws a keyrror with something
        #that returns None
        sysID = results.get('result',[{}])[0].get('sys_id',{}).get('value')
        return sysID

    # retruns a list of task IDs or None
    def gettaskLIST(self, change_sys_id, SNOW_Username, SNOW_Password):

        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        getModelsURL = 'api/sn_chg_rest/change/{change_sys_id}/task'.format(change_sys_id=change_sys_id)
        sysparam = ''
        url = getSNOW_baseURL() + getModelsURL + sysparam
        response = requests.get(url, auth=(SNOW_Username, SNOW_Password), headers=headers)
        results = response.json()
        tasks_list = []
        if response.status_code == 200 or 201:
            for task in results['result']:
                task_dict ={}
                task_dict['sys_id'] = task.get('sys_id',{}).get('value')
                task_dict['number'] = task['number']['value']
                task_dict['state'] = task['state']['display_value']
                task_dict['name'] = task['short_description']['value']
                tasks_list.append(task_dict)
            return tasks_list
        else:
            print("We had problems")
            print(response.text)
            return None

    # returns true if it approved it .. returns false if it failed at something
    @shared_task
    def approveChange(self, change_sys_id, SNOW_Username, SNOW_Password):
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        getModelsURL = 'api/sn_chg_rest/change/{change_sys_id}/approvals'.format(change_sys_id=change_sys_id)
        sysparam = ''
        url = getSNOW_baseURL() + getModelsURL + sysparam
        data = json.dumps({'state': 'approved'})
        response = requests.patch(url, auth=(SNOW_Username, SNOW_Password), headers=headers, data=data)

        if response.status_code == 200 or 201:
            return True
        else:
            print("We had problems")
            print(response.text)
            return False

    #returns True when closed, otherwise it will spit out response and retrun False
    def CloseThisTask(self, change_sys_id, this_task_sys_id, SNOW_Username, SNOW_Password):
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        getModelsURL = 'api/sn_chg_rest/change/{change_sys_id}/task/{this_task_sys_id}'.format(
            change_sys_id=change_sys_id,
            this_task_sys_id=this_task_sys_id
        )
        sysparam = ''
        url = getSNOW_baseURL() + getModelsURL + sysparam
        data = json.dumps({"state": "closed"})
        response = requests.patch(url, auth=(SNOW_Username, SNOW_Password), headers=headers, data=data)

        if response.status_code == 200 or 201:
            return True
        else:
            print("We had problems")
            print(response.text)
            return False

    # returns true if it closed it .. returns false if it failed at something
    def closeChange(self, change_sys_id, SNOW_Username, SNOW_Password, data):
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        getModelsURL = 'api/sn_chg_rest/change/standard/{change_sys_id}'.format(change_sys_id=change_sys_id)
        sysparam = ''
        url = getSNOW_baseURL() + getModelsURL + sysparam
        json_data = json.dumps(data)
        response = requests.patch(url, auth=(SNOW_Username, SNOW_Password), headers=headers, data=json_data)
        results = response.json()
        tasks_list = []
        if response.status_code == 200 or 201:
            return True
        else:
            print("We had problems")
            print(response.text)
            return False



    # returns true if it approved it .. returns false if it failed at something
    def attachdocxFileChanage(self, change_sys_id, SNOW_Username, SNOW_Password, file_name, file_location):
        headers = {"Content-Type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                   "Accept": "application/json"}
        getModelsURL = 'api/now/attachment/file?table_name=change_request&table_sys_id={change_sys_id}&file_name={file_name}'.format(
            change_sys_id=change_sys_id, file_name=file_name)
        sysparam = ''
        url = getSNOW_baseURL() + getModelsURL + sysparam
        print("**opening file {file_name}".format(file_name = file_location))
        data = open(file_location, 'rb').read()
        response = requests.post(url, auth=(SNOW_Username, SNOW_Password), headers=headers, data=data)
        if response.status_code == 200 or 201:
            return True
        else:
            print("We had problems")
            print(response.text)
            return False



