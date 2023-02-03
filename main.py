####STARTS####
#main runner file for relationship script code
#import dependencies and functions from other file: rel_utils
from rel_utils_Modified import xml_extract_ID
#from rel_utils import sighting_check
from rel_utils_Modified import extract_relationship
from rel_utils_Modified import extract_json_ID
from rel_utils_Modified import dict_generator
#from rel_utils import create_sighting
#from rel_utils import extract_json_type
from rel_utils_Modified import create_relationship

import numpy as np
from stix2 import parse
from stix2 import parse_observable
from stix.core import STIXPackage
from stix.core import ttps
from stix.common import *
import pprint 
from nested_lookup import nested_lookup
import pandas as pd

# flags
# flag=input('Check type = ')
flag = 'relationship'
#input xml file for parsing, as "fn"
fn= "hyperbro.xml"
stix_package = STIXPackage.from_xml(fn) 
testing=stix.common.related.GenericRelationship.to_dict(stix_package)
#input json file for parsing, as "file_handle"
file_handle = open("hyperbro.json") #specify file path
##functionality-> allow user to input the json in the main
obj = parse(file_handle, allow_custom=True)
abcd_test = dict_generator(testing)
abcd=list(dict_generator(testing))
list_for_json=["attack-pattern", "indicator", "campaign", "identity", "infrastructure", "course-of-action", "malware","report", "threat-actor", "observable", "vulnerability", "tool"  ]

list_of_xml = ['indicator','ttp','Observable','incident']
#for NCCIC objects
#generates list of XML object _ID's
xml_full_list,ID_list,IDref_list = xml_extract_ID(abcd, list_of_xml)
xml_ID_list = ID_list[0]
xml_ID_type_list = ID_list[1]
xml_ref_list = IDref_list[0]
xml_ref_type_list = IDref_list[1]
 
#extract relationships from json
json_full_list,sources,targets =extract_relationship(obj)

json_source_type = sources[0]
json_source_list = sources[1]
json_target_type = targets[0]
json_target_list = targets[1]

# check if IDs in xml are in json 
# IDs are in xml but not in json
ID_diff_list = np.setdiff1d(xml_ID_list, json_source_list)
# IDs are in both xml and json
ID_same_list = np.intersect1d(xml_ID_list, json_source_list)

# for IDs not in json, we list all the orignal IDs and IDrefs in xml
ref_diff_list = []    
for k in range(0,len(ID_diff_list)):
    ref_diff_index = [i for i, j in enumerate(xml_ID_list) if j == ID_diff_list[k]]
    for h in range(0,len(ref_diff_index)):      
        ref_diff_list.append([str(ID_diff_list[k]),xml_ref_list[ref_diff_index[h]]])
# for IDs in both json and xml, returns a list if they are not in pair 
ref_same_list = []
for k in range(0,len(ID_same_list)):
    xml_same_index = [i for i, j in enumerate(xml_ID_list) if j == ID_same_list[k]]
    json_same_index = [i for i, j in enumerate(json_source_list) if j == ID_same_list[k]]
    
    xml_same_temp = [xml_ref_list[xml_same_index[h]] for h in range(0,len(xml_same_index))]
    json_same_temp = [json_target_list[json_same_index[h]] for h in range(0,len(json_same_index))]
    
    for g in range(0,len(xml_same_temp)):
        idref_same_index = [i for i, j in enumerate(json_same_temp) if j!=xml_same_temp[g]]
        if len(idref_same_index)==len(json_same_temp):
            # for h in range(0,len(idref_same_index)):
                ref_same_list.append([str(ID_same_list[k]),xml_same_temp[g]])
# all IDs = ref_diff + ref_same
for k in range(0,len(ref_same_list)):
    ref_diff_list.append(ref_same_list[k])

# print('Mismatched relationship:', ref_diff_list, sep='\n', end='\n')                

# read relationship tables
relationships = pd.read_csv('./relationship.csv')
# create missing and undefined relationships, and associated objects
relationship_list,undefined_relationship, source_objects, target_objects = create_relationship(obj,ID_list,IDref_list,ref_diff_list,relationships)
# remove duplicate objects in sources and targets
all_objects = target_objects+source_objects

all_unique_objects=[]
for n,i in enumerate(all_objects):
    duplicates=0
    for j in all_unique_objects:
        if len(i.split('\n'))>8:
            
            if i.split('\n')[3].split(':')[1] in j and i.split('\n')[10] in j:
                duplicates+=1
                print('Duplicated IDs:', i.split('\n')[3].split(':')[1],i.split('\n')[10], sep='\n', end='\n')
        else:
            if i.split('\n')[3].split(':')[1] in j :
                duplicates+=1
                print('Duplicated IDs:', i.split('\n')[3].split(':')[1], sep='\n', end='\n')
    if duplicates==0:
        all_unique_objects.append(i)


# print('Added relationship:', relationship_list, sep='\n', end='\n')
# print('Undefined:', undefined_relationship, sep='\n', end='\n')

# write text files
with open('ref_diff_list.txt', 'w') as fdiff:
    for index in ref_diff_list:
        fdiff.write(str(index))
        fdiff.write(',\n')
    fdiff.close()
    
with open('source_objects.txt', 'w') as fsource:
    for index in source_objects:
        fsource.write(str(index))
        fsource.write(',\n')
    fsource.close()

with open('target_objects.txt', 'w') as ftarget:
    for index in target_objects:
        ftarget.write(str(index))
        ftarget.write(',\n')
    ftarget.close()

with open('missing_objects.txt', 'w') as funique:
    for index in all_unique_objects:
        funique.write(str(index))
        funique.write(',\n')
    funique.close()           
    
with open('missing_relationships.txt','w') as frel:
    for index in relationship_list:
        frel.write(str(index))
        frel.write(',\n')
    frel.close()

with open('undefined_relationship.txt','w') as fun:
    for index in undefined_relationship:
        fun.write(str(index))
        fun.write(',\n')
    fun.close()
    




