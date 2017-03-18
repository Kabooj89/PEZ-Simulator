'''
@summary: this file contains all the constants related to the PEZ simulator.
@author: Mohammad Kabajah
@date: 23/4/2016
'''

class PezCommands():
    PEZ_GO_TO_PEZ_DIR_CMD="cd /opt/pez/pez-0.3.13" #location to PEZ.py file
    COMPILE_CONFG_FILE_PEZ_CMD= "python pez.py -c"

class PezFIles():
    PEZ_CONFG_FILE = "pez_confg.py" #PEZ configuration template must be located in the same package
