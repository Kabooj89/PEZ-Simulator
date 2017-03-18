'''
Created on Apr 6, 2016

@author: mohammed Kabajah

Summary
=====================
Useful utilities for Pez Simulator.
'''

import logging
import json
from utilities.simulators.pez.pez_constant import PezCommands,PezFIles
import utilities.mgmt_utils as mgmt_utils
import utilities.connection_handler.connections as connect_utils


def _preparePezConfg(object_type='file',object_data=PezFIles.PEZ_CONFG_FILE):#file, string,dict
    '''
    Function to PEZ configuration object to readable object<json> .

    Parameters
    ----------
    object_type: file,str,dict
    object_data: file name  , string of PEZ configuration , dict contained PEZ configuration.

    Returns
    -------
        pez_configuration_template: dictionary contains PEZ template
        PEZ_VARIABLE= list contains all the changeable parameters inside PEZ object

    '''
    mgmt_utils.log_func_details(object_type=object_type,object_data=object_data)
    PEZ_VARIABLE = []
    print ("[*] start preparing the Pez Config template...")
    if object_type == "file":
        pez_configuration_template=mgmt_utils.readJson(object_data,'file')
    elif object_type == "str":
        pez_configuration_template=mgmt_utils.readJson(object_data,'str')
    elif object_type == "dict":
        pez_configuration_template=mgmt_utils.readJson(object_data,'dict')
    else:
        logging.error("not supported format: %s"%object_type)
        raise Exception ("not supported format: %s"%object_type)

    for key_level1, value_level1 in pez_configuration_template.items():
        if "$$" in value_level1:
            PEZ_VARIABLE.append(key_level1)
        elif isinstance(value_level1, dict):
            for key_level2,value_level2 in value_level1.items():
                print("type of variable - : %s -%s"%(type(value_level2),value_level2))
                if "$$" in str(value_level2) and not isinstance(value_level2, dict):
                    PEZ_VARIABLE.append("%s:%s"%(key_level1,key_level2))
                elif isinstance(value_level2, dict):
                    for key_level3, value_level3 in value_level2.items():
                        if "$$" in str(value_level3):
                            PEZ_VARIABLE.append("%s:%s:%s" % (key_level1, key_level2,key_level3))

                        elif isinstance(value_level3, list):
                            if "$$" in str (value_level3[0]):
                                PEZ_VARIABLE.append("%s:%s:%s" % (key_level1, key_level2, key_level3))

    return pez_configuration_template,PEZ_VARIABLE

def changeVariableInPezConfig(object_type,object_data, variable_to_change_by_level, new_value, log=False, enforcement = False ):
    '''
    Function to modify the changeable parameters in the PEZ configuration object .

    Parameters
    ----------
     object_type: file,str,dict ( type of the pez template object)
    object_data: file name  , string of PEZ configuration , dict contained PEZ configuration.
    variable_to_change_by_level: the path to the variable to be change seperated with ":" ex. stress:num_clients"
    new_value : the new value to placed with certain parameters
    log: to print the all configuration after change to debug purpose

    Returns
    -------
        pez_configuration_dict: dictionary contains all changes
    '''

    mgmt_utils.log_func_details(object_type=object_type,object_data=object_data, variable_to_change_by_level=variable_to_change_by_level, new_value=new_value)

    pez_configuration_dict,changable_variable_list=_preparePezConfg(object_type,object_data)
    if log:
        print("The Dictionary of the PEZ Template is:")
        mgmt_utils.JsonPrint(pez_configuration_dict)
        print("The changeable configuration list that show which parameters is changeable:")
        mgmt_utils.JsonPrint(changable_variable_list)

    print("checking if the variable to change is exist in the changeable list")
    if variable_to_change_by_level not in changable_variable_list and not enforcement :
        logging.error("variable <%s> not located in list of changeable " %variable_to_change_by_level)
        raise Exception("variable <%s> not located in list of changeable " %variable_to_change_by_level)
    elif variable_to_change_by_level not in changable_variable_list and enforcement:
        logging.info("the variable <%s> not located in permission variable but the ENFOR")

    else:
        variable_level= variable_to_change_by_level.split(":")
        print("list : %s"%variable_level)
        if (len(variable_level)==1):           pez_configuration_dict[variable_to_change_by_level]= new_value
        elif (len(variable_level)==2):
            pez_configuration_dict[variable_level[0]][variable_level[1]]= new_value
        elif (len(variable_level)==3):
            pez_configuration_dict[variable_level[0]][variable_level[1]][variable_level[2]]= new_value
        else:
            print("not supported level, please add this level to use it")
            raise Exception("not supported level, please add this level to use it")

    if log:
        print("The Dictionary of the PEZ Template after new changes is:")
        mgmt_utils.JsonPrint(pez_configuration_dict)
    return pez_configuration_dict


def changeMultipleVariablesInPizConfig(object_type,object_data, dict_of_changes, log, enforcment= False):
    '''
    Function to modify the multiple changeable parameters in the PEZ configuration object, can change multiple changes at once.

    Parameters
    ----------
    object_type: file,str,dict ( type of the pez template object)
    object_data: file name  , string of PEZ configuration , dict contained PEZ configuration.
    dict_of_changes: dictionary that contains all the changes

    Returns
    -------
        pez_configuration_dict: dictionary contains all changes
    '''

    mgmt_utils.log_func_details(object_type=object_type,object_data=object_data, dict_of_changes=dict_of_changes,log=log)
    print ("[*] start changing multiple changes in the pez configuration object...")
    pez_configuration_dict,changable_variable_list=_preparePezConfg(object_type,object_data)
    if log:
        print("The Dictionary which contains all changes is:")
        mgmt_utils.JsonPrint(dict_of_changes)
        mgmt_utils.log_separator()
        print("The Dictionary of the PEZ Template is:")
        mgmt_utils.JsonPrint(pez_configuration_dict)
        mgmt_utils.log_separator()

    print("The changeable configuration list that show which parameters is changeable is:")
    mgmt_utils.JsonPrint(changable_variable_list)
    mgmt_utils.log_separator()
    for parameter,value in dict_of_changes.items():
        print ("start working on the parametere : %s to give it the value: %s"%(parameter,value))
        if parameter not in changable_variable_list and not enforcment :
            logging.error("variable <%s> not located in list of changeable " %parameter)
            raise Exception ("variable <%s> not located in list of changeable " %parameter)
            break
        else:
            variable_level= parameter.split(":")
            if (len(variable_level)==1):
                if not enforcment and "+$$" in pez_configuration_dict[parameter]:
                    url_value=urlReplacemnt(pez_configuration_dict[parameter],value)
                    pez_configuration_dict[parameter]= url_value
                else:
                    pez_configuration_dict[parameter]= value

            elif (len(variable_level)==2):
                if "+$$" in pez_configuration_dict[variable_level[0]][variable_level[1]] :
                    url_value=urlReplacemnt(pez_configuration_dict[variable_level[0]][variable_level[1]],value)
                    if isinstance( pez_configuration_dict[variable_level[0]][variable_level[1]], list):
                        pez_configuration_dict[variable_level[0]][variable_level[1]] = [url_value]
                    else:
                        pez_configuration_dict[variable_level[0]][variable_level[1]]= url_value
                else:
                    if isinstance(pez_configuration_dict[variable_level[0]][variable_level[1]], list):
                        pez_configuration_dict[variable_level[0]].update({[variable_level[1]]: [value] })
                    else:
                        pez_configuration_dict[variable_level[0]].update({[variable_level[1]]: value})

            elif (len(variable_level)==3):
                if "+$$" in pez_configuration_dict[variable_level[0]][variable_level[1]][variable_level[2]]:
                    url_value=urlReplacemnt(pez_configuration_dict[variable_level[0]][variable_level[1]][variable_level[2]],value)
                    if isinstance(pez_configuration_dict[variable_level[0]][variable_level[1]][variable_level[2]], list):
                        pez_configuration_dict[variable_level[0]][variable_level[1]][variable_level[2]] = [url_value]
                    else:
                        pez_configuration_dict[variable_level[0]][variable_level[1]][variable_level[2]]= url_value

                else:
                    if isinstance(pez_configuration_dict[variable_level[0]][variable_level[1]][variable_level[2]],
                                  list):
                        pez_configuration_dict[variable_level[0]][variable_level[1]][variable_level[2]] = [value]
                    else:
                        pez_configuration_dict[variable_level[0]][variable_level[1]][variable_level[2]] = value

            else:
                logging.error("not supported level, please add this level to use it")
                raise Exception ("not supported level, please add this level to use it")
    return pez_configuration_dict


def urlReplacemnt(url_string,value):
    '''
    functions to change certain string in urls in PEZ configuration
    '''
    url_list = url_string.split("+")
    new_url=url_list[0]+value+url_list[2]
    print("the url after modification is: %s "%new_url)
    return new_url


def dumpConfigurationFile(device=None,pez_configuration_dict={},local_path="/tmp/pez.py",remote_path="/tmp/pez.py",
                                 username_remote="root",password="lab123"):
    '''
        Function to modify the multiple changeable parameters in the PEZ configuration object, can change multiple changes at once.

        Parameters
        ----------
        object_type: file,str,dict
        object_data: file name  , string of PEZ configuration , dict contained PEZ configuration.
        dict_of_changes: dictionary that contains all the changes

        Returns
        -------
            pez_configuration_dict: dictionary contains all changes
    '''
    mgmt_utils.log_func_details(device=device,pez_configuration_dict=pez_configuration_dict, local_path=local_path, remote_path=remote_path,
                                username_remote=username_remote,password=password)
    print("[*] Start dumping the PEZ configuration object inside file ...")
    print("the full path where the data will be dumped locally is : <%s> "%local_path)
    print ("the data will be dumped is the following:")
    mgmt_utils.log_separator()
    mgmt_utils.JsonPrint(pez_configuration_dict)
    mgmt_utils.log_separator()
    with open(local_path, "w") as text_file:
        text_file.write(json.dumps(pez_configuration_dict, indent=3))
    print("data saved on local device successfully!")
    if device:
        print ("[*] start moving the configuration file to remote device with ip: %s"%device)
        if not mgmt_utils.sendFileUsingSsh(device=device,username=username_remote,password=password, localpath=local_path,remotepath=remote_path):
            logging.error("file not dumped on remote device <%s>!"%device)
            return False
        else:
            print ("all data dumped on remote device <%s> successfully!"%device)
    return True

def runPezCommand(device=None,username="root",password="lab123",pez_config_file_path="/tmp/pez.py"):
    '''
        Function to modify the multiple changeable parameters in the PEZ configuration object, can change multiple changes at once.

        Parameters
        ----------
        device: type(str) if you provide ip the command will run remotely on that ip if not it will run locally
        pez_config_file_path: type(str) the path for the pez configuration file

        Returns
        -------
            boolean if the process passed or not
    '''
    mgmt_utils.log_func_details(device=device,pez_config_file_path=pez_config_file_path)
    print ("[*] start applying PEZ command on Device: %s"%device)
    print("commmand to be run is: ")
    print ("Command 1- %s" %PezCommands.PEZ_GO_TO_PEZ_DIR_CMD)
    print ("Command 2- %s" %PezCommands.COMPILE_CONFG_FILE_PEZ_CMD)
    PEZ_CMD_PIPE=PezCommands.PEZ_GO_TO_PEZ_DIR_CMD+";"+ PezCommands.COMPILE_CONFG_FILE_PEZ_CMD+" %s"%pez_config_file_path

    print("starting applying the commands to run the PEZ simulator with new configurations")
    _,std_out,stderr,exit_status=connect_utils.ssh_cmd_full_output(ip=device,user=username,key=password,cmd=PEZ_CMD_PIPE)
    if exit_status == 0:
        print("all the commands passed correctly!! Output: <%s>"%std_out)
        return True
    else:
        logging.error("error applying the following command : %s with following stderr: %s"%(PEZ_CMD_PIPE,stderr))
        return False



if __name__ == "__main__":
    changes={"stress:repeat":1,
             "stress:num_clients":5,
             "stress:num_tasks":5,
             "radius:host":"10.126.107.232",
             "radius:secret":"cisco",
             "radius:attributes:User-Name":"autouser1",
             "radius:attributes:User-Password":"Cisco123",
             "radius:attributes:NAS-IP-Address":"173.39.24.222",
             "radius:attributes:kabooj": "fuck"
             }
    # command to change multipe changes Once
    pez_configuration_dict=changeMultipleVariablesInPizConfig("file",PezFIles.PEZ_CONFG_FILE,changes,True)
    mgmt_utils.JsonPrint(pez_configuration_dict)
    #command to dump the configuration file to remote or local device
    #if not dumpConfigurationFile(device="10.56.51.172",pez_configuration_dict=pez_configuration_dict,username_remote="root", password="lab123", local_path="/tmp/pez.py",remote_path="/tmp/pez.py"):
    #    raise Exception ("Error dumping configuration file into given device")
    # command to run pez command on remote/local device
    #if not runPezCommand(device="10.56.51.172",pez_config_file_path="/tmp/pez.py"):
    #   raise Exception("Error in applying PEZ command on the given Device")
    #print ("the main system is to operate the remaning opetation to got the maxumum from the whole system if the main is te the
    #is that what you want exactly the words for hossam is the best thing to think aout it


