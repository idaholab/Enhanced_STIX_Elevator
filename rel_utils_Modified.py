# -*- coding: utf-8 -*-
"""
Created on Sun Jan 30 22:35:41 2022

@author: tzhao1
"""

#import statements for dependencies

from stix2.workbench import *
from stix2 import parse
from stix2 import parse_observable
from stix.core import STIXPackage
from stix.core import ttps
from stix.common import *
import numpy as np


def extract_json_ID(obj, type_of_obj_json):
    #input: dictionary json, obj, and dictionary of objects: type_of_obj
    #purpose: to extract the JSON ID's for each type of object in the JSON file
    #output: ID from json
    ID_list=[]
   
    for i in range(0,len(list(obj["objects"]))): 
      if obj["objects"][i]["type"]==str(type_of_obj_json):
        ID_list.append(obj["objects"][i]["id"])
        ID_list=list(map(lambda x: x.replace(str(type_of_obj_json)+'--',''),ID_list))
    return (sorted(set(ID_list)))
        
def extract_relationship(obj):
#input: obj: the json file as a dictionary, ID: given ID of object, type_of_obj: the dictionary that contains the type of object
#purpose: to check for relationships with the given ID
#output: list of relationship ID's
    source_list= []
    source_type = []
    target_list= []
    target_type = []
    
    json_full_list=[]
    json_full_type=[]
    for i in range(0,len(list(obj["objects"]))):
            for key, value in obj["objects"][i].items():

               if value=="relationship":
                   source_ref_temp= obj["objects"][i]["source_ref"]
                   source_type.append(source_ref_temp.split('--')[0])
                   source_list.append(source_ref_temp.split('--')[1])
                   
                   target_ref_temp=obj["objects"][i]["target_ref"]
                   target_type.append(target_ref_temp.split('--')[0])
                   target_list.append(target_ref_temp.split('--')[1])
               else:
                 break
    for k in range(0,len(source_list)):
        json_full_list.append([source_list[k],target_list[k]])
        json_full_type.append([source_type[k],target_type[k]])
 
    return [json_full_list,json_full_type], [source_type, source_list], [target_type, target_list]

###XML###
#dict_generator is used to flatten a dictionary into a list 
def dict_generator(indict, pre=None):
    pre = pre[:] if pre else []
    if isinstance(indict, dict):
        for key, value in indict.items():
            if isinstance(value, dict):
                for d in dict_generator(value, pre + [key]):
                    yield d
            elif isinstance(value, list) or isinstance(value, tuple):
                for v in value:
                    for d in dict_generator(v, pre + [key]):
                        yield d
            else:
                yield pre + [key, value]
    else:
        yield pre + [indict]

def xml_extract_ID(abcd, list_of_xml):
  #input: xml, and a list of xml objects
  #output:a list of ID's and theirs objects in the XML, accounts for both CISA and NCCIC objects
     id_list_temp=[]
     id_list=[]
     id_type=[]
     id_type_list=[]
     
     idref_list_temp=[]
     idref_list=[]
     idref_type=[]
     idref_type_list=[]
     
     full_list=[]
     for count, value in enumerate(abcd):
      for i in value:
          for k in range(0,len(list_of_xml)):
            if str(i).startswith("NCCIC:" +str(list_of_xml[k])) and str(list_of_xml[k]).lower() in str(value[0]).lower():
                id_list_temp.append(str(i))
                
                id_list_temp=list(map(lambda x: x.replace("NCCIC:"+str(list_of_xml[k])+"-",''),id_list_temp))
                
                if str(list_of_xml[k])=='ttp':                    
                    ttp_type = find_ttp_type(abcd,count) 
                    id_type.append(ttp_type)
                else:
                    id_type.append(str(list_of_xml[k]))
                
                key, key_type = find_idref(abcd,list_of_xml[k],count)
                
                idref_list_temp.append(key)
                idref_type.append(key_type)
    
     for k in range(0,len(id_list_temp)):
            if len(idref_list_temp[k])!=0:
                ref_temp = idref_list_temp[k]
                type_temp = idref_type[k]
                for i in range(0,len(ref_temp)):
                    id_list.append(id_list_temp[k])
                    id_type_list.append(id_type[k])
                    idref_list.append(ref_temp[i])
                    idref_type_list.append(type_temp[i])
                                        
     for k in range(0,len(id_list)):
        full_list.append([id_list[k],idref_list[k]])
        
     return full_list, [id_list,id_type_list], [idref_list,idref_type_list] 

def find_idref(abcd,xml_k,count):
    #input: full obj: abcd, an xml object,  its position in the nested table
    #output: all idrefs and their objects for an object in xml
    #for ttp: type with more than one object (e.g., either malware or infrastructure), we store all the related objects 
    idref_list=[]
    idref_type = []
    abcd_list = list(abcd)
    for i in range(count+1,len(abcd_list)):
        if xml_k == str('indicator'): 
            if 'timestamp' in str(abcd_list[i]):
                for k in range(i+1,len(abcd_list)):
                    if str(xml_k).lower() in str(abcd_list[k][0]).lower():
                        
                        if str(abcd_list[k][1])=='observable' and str(abcd_list[k][2])=='id':
                            idref_temp = '-'.join(str(abcd_list[k][-1:])[1:-2].split('-')[1:])                           
                            idref_type.append(str(abcd_list[k][-1:])[1:-2].split('-')[0].split(':')[1])
                            idref_list.append(idref_temp)
                        
                        if 'idref' in str(abcd_list[k]):
                            idref_temp = '-'.join(str(abcd_list[k][-1:])[1:-2].split('-')[1:])    
                            if str('ttp') in str(abcd_list[k][-1]):
                                v_type = find_ttp_ref_type(abcd, idref_temp)
                                if v_type is not None:
                                    idref_type.append(v_type[0])
                            else:
                                idref_type.append(str(abcd_list[k][-1:])[1:-2].split('-')[0].split(':')[1])                            
                            idref_list.append(idref_temp)
                           
                        if str(abcd_list[k][-1:][0]).startswith("NCCIC:" +str(xml_k)) and str(xml_k).lower() in str(abcd_list[k][0]).lower():  
                            return idref_list, idref_type
                    else:
                        return idref_list, idref_type
                    
        elif xml_k=='incident':
            if 'timestamp' in str(abcd_list[i]):
                for k in range(i+1,len(abcd_list)):
                    if str(xml_k).lower() in str(abcd_list[k][0]).lower():
                        
                        if 'idref' in str(abcd_list[k]):
                            idref_temp = '-'.join(str(abcd_list[k][-1:])[1:-2].split('-')[1:])                           
                            
                            if str('ttp') in str(abcd_list[k][-1]):
                                v_type = find_ttp_ref_type(abcd, idref_temp)
                                if v_type is not None:                                                      
                                    idref_type.append(v_type[0])
                            else:
                                idref_type.append(str(abcd_list[k][-1:])[1:-2].split('-')[0].split(':')[1])                            
                            idref_list.append(idref_temp)
                            
                        if str(abcd_list[k][-1:][0]).startswith("NCCIC:" +str(xml_k)) and str(xml_k).lower() in str(abcd_list[k][0]).lower():  
                            return idref_list, idref_type
                    else:
                        return idref_list, idref_type  
        elif xml_k=='ttp':
                for k in range(i+1,len(abcd_list)):
                    if str(xml_k).lower() in str(abcd_list[k][0]).lower():
                        
                        if str(abcd_list[k][2])=='behavior' and str(abcd_list[k][5])=='id':
                            idref_temp = '-'.join(str(abcd_list[k][-1:])[1:-2].split('-')[1:])                           
                            idref_type.append(str(abcd_list[k][-1:])[1:-2].split('-')[0].split(':')[1])
                            idref_list.append(idref_temp)
                        
                        if 'idref' in str(abcd_list[k]):
                            idref_temp = '-'.join(str(abcd_list[k][-1:])[1:-2].split('-')[1:])
                            if str('ttp') in str(abcd_list[k][-1]):
                                v_type = find_ttp_ref_type(abcd, idref_temp)                                                      
                                if v_type is not None:                                                      
                                    idref_type.append(v_type[0])
                            else:
                                idref_type.append(str(abcd_list[k][-1:])[1:-2].split('-')[0].split(':')[1])                            
                            idref_list.append(idref_temp)
                           
                        if str(abcd_list[k][-1:][0]).startswith("NCCIC:" +str(xml_k)) and str(xml_k).lower() in str(abcd_list[k][0]).lower():                         
                            return idref_list, idref_type
                    else:
                        return idref_list, idref_type            
            
        elif xml_k=='Observable':
            ############## Start: Added by Bryan ################
            if 'timestamp' in str(abcd_list[i]):
                for k in range(i+1,len(abcd_list)):
                    if str(xml_k).lower() in str(abcd_list[k][0]).lower():
                        
                        if 'idref' in str(abcd_list[k]):
                            idref_temp = '-'.join(str(abcd_list[k][-1:])[1:-2].split('-')[1:])                           
                            
                            if str('ttp') in str(abcd_list[k][-1]):
                                v_type = find_ttp_ref_type(abcd, idref_temp)
                                if v_type is not None:                                                      
                                    idref_type.append(v_type[0])
                            else:
                                idref_type.append(str(abcd_list[k][-1:])[1:-2].split('-')[0].split(':')[1])                            
                            idref_list.append(idref_temp)
                            
                        if str(abcd_list[k][-1:][0]).startswith("NCCIC:" +str(xml_k)) and str(xml_k).lower() in str(abcd_list[k][0]).lower():  
                            return idref_list, idref_type
                    else:
                        return idref_list, idref_type  
            ############## End: Added by Bryan ################
            ### 05/10 update: finding elements in an Observation by "Object" and "ID" instead of "description"
            
            if 'object' and 'id' in str(abcd_list[i]):
                for k in range(i,len(abcd_list)):
                    if str(xml_k).lower() in str(abcd_list[k][0]).lower():
                        
                        if str(abcd_list[k][2])=='object' and str(abcd_list[k][3])=='id':
                            idref_temp = '-'.join(str(abcd_list[k][-1:])[1:-2].split('-')[1:])                           
                            idref_type.append(str(abcd_list[k][-1:])[1:-2].split('-')[0].split(':')[1])
                            idref_list.append(idref_temp)
                        
                        if 'idref' in str(abcd_list[k]):
                            idref_temp = '-'.join(str(abcd_list[k][-1:])[1:-2].split('-')[1:])                           
                            if str('ttp') in str(abcd_list[k][-1]):
                                v_type = find_ttp_ref_type(abcd, idref_temp)                                                      
                                if v_type is not None:                                                      
                                    idref_type.append(v_type[0])
                            else:
                                idref_type.append(str(abcd_list[k][-1:])[1:-2].split('-')[0].split(':')[1])
                            idref_list.append(idref_temp)
                    
                        if str(abcd_list[k][-1:][0]).startswith("NCCIC:" +str(xml_k)) and str(xml_k).lower() in str(abcd_list[k][0]).lower():  
                            return idref_list, idref_type
                    else:
                         return idref_list, idref_type

def find_ttp_type(abcd,count):
    # function determines the object of a ttp
    ttp_type = []
    
    abcd_list = list(abcd)
    
    for i in range(count+1,len(abcd_list)):
        if i != len(abcd_list)-1:     
            if 'behavior' in str(abcd_list[i]):
                index =  abcd_list[i].index('behavior')
                if abcd_list[i][index+1].startswith('malware'):
                    if ttp_type.count(str('malware'))==0:
                        ttp_type.append(str('malware'))
            elif 'resources' in str(abcd_list[i]): 
                index =  abcd_list[i].index('resources')
                if abcd_list[i][index+1].startswith('infrastructure'):
                    if ttp_type.count(str('infrastructure'))==0:
                        ttp_type.append(str('infrastructure'))
            elif str(abcd_list[i][-1:][0]).startswith("NCCIC:" +str('ttp')):
                return ttp_type 
        else:
            return ttp_type 

def find_ttp_ref_type(abcd,idref):
    # function determines the object of a ttp if this ttp is an idref in the xml
    for count, value in enumerate(abcd):
        for i in value:
            if 'NCCIC:ttp-' + str(idref) in str(i) and str('ttp') in str(value[0]).lower():
                ttp_ref_type = find_ttp_type(abcd,count)   
                return ttp_ref_type
                
                        
               
     
###RELATIONSHIP_CREATION####
from stix2 import parse
from stix2 import parse_observable
from stix2 import Relationship
import pandas as pd
###Object DICTIONARY: stix1 to stix2 
objects = {1: {'stix1': 'Campaign', 'stix2': 'campaign'},
           2: {'stix1': 'Course_Of_Action', 'stix2': 'course-of-action'},
           3: {'stix1': 'Vulnerability', 'stix2': 'vulnerability'},
           4: {'stix1': 'Weakness', 'stix2': 'Weakness'},
           5: {'stix1': 'Configuration', 'stix2': 'Configuration'},
           6: {'stix1': 'Incident', 'stix2': 'incident'},
           7: {'stix1': 'Indicator', 'stix2': 'indicator'},
           8: {'stix1': 'Information_Source', 'stix2': 'location'},
           9: {'stix1': 'CIQIdentity3_0Instance', 'stix2': 'location'},
           10: {'stix1': 'Address', 'stix2': 'location'},
           11: {'stix1': 'Report', 'stix2': 'report'},
           12: {'stix1': 'Observable', 'stix2': 'observed-data'},
           13: {'stix1': 'Package', 'stix2': 'bundle'},
           14: {'stix1': 'Threat Actor', 'stix2': 'threat-actor'},
           15: {'stix1': 'Attack_Pattern', 'stix2': 'attack-pattern'},
           16: {'stix1': 'Infrastructure', 'stix2': 'infrastructure'},
           17: {'stix1': 'Malware', 'stix2': 'malware'},
           18: {'stix1': 'Persona', 'stix2': 'Persona'},
           19: {'stix1': 'Tool', 'stix2': 'tool'},  
           20: {'stix1': 'Victim_Targeting', 'stix2': 'identity'},  
           21: {'stix1': 'File', 'stix2': 'file'}, 
           ################ Start: Added by Bryan #################  
           22: {'stix1': 'WinExecutableFile', 'stix2': 'file'},
           23: {'stix1': 'Artifact', 'stix2': 'observed-data'},
           ################ Stop: Added by Bryan ##################
    }

def create_relationship(obj,xml_ids,xml_idrefs,diff_ids,relationships):
    # create all the missing relationthip
    # output the pairs of ID and IDref whose relationship type are not in relationship.csv
    
    source_ID = xml_ids[0]
    source_type = xml_ids[1]
    
    target_ID = xml_idrefs[0]
    target_type = xml_idrefs[1]
        
    source_read = relationships['Source'].tolist()
    target_read = relationships['Target'].tolist()
    type_read = relationships['Type'].tolist()
    
    source_rel = []
    target_rel = []
    source_target_type = []
    #remove unicode \xa0 when converting Dataframe to a list
    for h in range(0,len(source_read)):
        source_rel.append(source_read[h].replace(u'\xa0', u' '))
        target_rel.append(target_read[h].replace(u'\xa0', u' '))
        source_target_type.append(type_read[h].replace(u'\xa0', u' '))
        
    relationship_list = []
    undefined_list = []
    source_objects = []
    target_objects = []
    for k in range(0,len(diff_ids)):
        source_index = source_ID.index(str(diff_ids[k][0]))
        target_index = target_ID.index(str(diff_ids[k][1]))
               
        if isinstance(source_type[source_index],list):
            xml_source_type = source_type[source_index][0]
        else:
            xml_source_type = source_type[source_index]
        
        if isinstance(target_type[target_index],list):
            xml_target_type = target_type[target_index][0]
        else:
            xml_target_type = target_type[target_index]
        
        source_types = [v for k,v in objects.items() if v['stix1']==str(xml_source_type).capitalize()]
        ################## Start: Changes by Bryan ########################
        #target_types = [v for k,v in objects.items() if v['stix1']==str(xml_target_type).capitalize()]
        target_types = [v for k,v in objects.items() if v['stix1']==str(xml_target_type).capitalize() or v['stix1']==str(xml_target_type)]
        ################## End: Changes by Bryan ##########################
        
        ### 05/10 update: if target_types are not found in Object DICTIONARY, skip and print it.
        ### one can add them to Object DICTIONARY if necessary.
        if len(target_types) ==0:
            print('Target_types not in Objests:', xml_target_type, sep='\n', end='\n')
        else:
            stix2_source_type = source_types[0]['stix2']
            stix2_target_type = target_types[0]['stix2']

            
            relationship_type = find_relationship_type(source_rel,target_rel,stix2_source_type,stix2_target_type,source_target_type)
            source_ref = str(stix2_source_type)+'--'+str(source_ID[source_index])
            target_ref = str(stix2_target_type)+'--'+str(target_ID[target_index])
            
            
            source_objectCreation, source_defined = create_object(obj,stix2_source_type,source_ref)
            target_objectCreation, target_defined = create_object(obj,stix2_target_type,target_ref)  
            
            if  'No object found' in target_objectCreation:
                print('Object not defined', target_objectCreation, sep='\n',end='\n')
            elif 'No object found' in source_objectCreation:
                print('Object not defined', target_objectCreation, sep='\n',end='\n')
            else:
                source_objects.append(source_objectCreation)
                target_objects.append(target_objectCreation)
               
            
            
            if relationship_type and source_defined and target_defined:            
                duplicates=0
                
                
                relationship = Relationship(relationship_type = relationship_type,source_ref=source_ref,target_ref=target_ref)
                relationship_temp = relationship.serialize(pretty=True)
                if len(relationship_list)==0:
                    relationship_list.append(relationship_temp)
                else:
                    for j in relationship_list:
                        if source_ref in j and target_ref in j:
                            duplicates+=1
                            print('Duplicated IDs:', source_ref, target_ref, sep='\n', end='\n')
                            
                    if duplicates==0:
                        relationship_list.append(relationship_temp)
                            
            else:
                duplicates_undefined=0
                if len(undefined_list)==0:
                    undefined_list.append([source_ref,target_ref])
                else:
                    for j in undefined_list:
                        if source_ref in j and target_ref in j:
                            duplicates_undefined+=1
                            print('Duplicated IDs:', source_ref, target_ref, sep='\n', end='\n')
                            
                    if duplicates_undefined==0:
                        undefined_list.append([source_ref,target_ref])
                     
   
    return relationship_list,undefined_list, source_objects, target_objects
        
    
def find_relationship_type(source_rel,target_rel,stix2_source_type,stix2_target_type,source_target_type):
    relationship_type = []
    for v in range(0,len(source_rel)):
        if str(stix2_source_type) in source_rel[v] and str(stix2_target_type) in target_rel[v]:                
            if len(source_target_type[v])>1:
                relationship_type = source_target_type[v].split(',')[0]
            else:
                 relationship_type = source_target_type[v] 
            
    if relationship_type:
        return relationship_type
    else:
        return []
            
# import stix2 tools to create json objects
# additional stix2 tools can be imported based on requirements
from stix2 import (AttackPattern, Campaign, Incident, Identity, Indicator, Infrastructure, 
                   Malware, ThreatActor,ObservedData)

def create_object(obj, type_of_obj_json,obj_id):
    #input: dictionary json, obj, and dictionary of objects: type_of_obj
    #purpose: to extract the JSON ID's for each type of object in the JSON file
    #output: json object 
    objectNofound = []
    if type_of_obj_json == str('indicator'):
        objectCreation = Indicator(id=str(obj_id),pattern='ipvr4:000',pattern_type='stix2.1')
    elif type_of_obj_json==str('malware'):
        objectCreation = Malware(id=str(obj_id),is_family=False)
    elif type_of_obj_json==str('campaign'):
        objectCreation = Campaign(id=str(obj_id),name='nameCampaign')
    elif type_of_obj_json==str('attack-pattern'):
        objectCreation = AttackPattern(id=str(obj_id),name='nameAttack')
    elif type_of_obj_json==str('infrastructure'):
        objectCreation = Infrastructure(id=str(obj_id),name='nameIns')
    elif type_of_obj_json==str('threat-actor'):
        objectCreation = ThreatActor(id=str(obj_id),name='nameThreat')
    elif type_of_obj_json==str('observed-data'):
        objectCreation = ObservedData(id=str(obj_id),
                                      first_observed='2022-06-03T17:12:55.594Z', 
                                      last_observed='2022-06-04T17:12:55.594Z',
                                      object_refs = 'markings--027a4291-d4a9-490b-9107-800abaea4c8c',
                                      number_observed = 1,
                                      allow_custom=True)
        
    else:
        objectNofound = str('No object found:' + obj_id)
    if len(objectNofound)!=0:
        return objectNofound, False
    else:
        return objectCreation.serialize(pretty=True), True

        


