from loguru import logger
from aegis_config import settings
from collections import defaultdict
import os
from time import gmtime, strftime
import csv

CURTIME = strftime("%Y-%m-%d-%H_%M_%S", gmtime())
BASEDIR = os.path.relpath(f"{CURTIME}", os.getcwd())

TOTALTOKENS = 0


def prepare():
    os.makedirs(f"{CURTIME}", exist_ok=False)
    logger.add(f"{BASEDIR}/{CURTIME}.log", enqueue=True)
    logger.info(f"{CURTIME}")
    logger.info(f"{settings['model']}")
    global CVEITEMS
    logger.info(f"CVEITEMS have {len(CVEITEMS)} cve items")


CVEITEMS = defaultdict()

with open('cvesw.csv') as file:
    csvFile = csv.DictReader(file)
    for lines in csvFile:
        cveid = lines['CVE ID']
        if not cveid:
            continue
        CVEITEMS[cveid] = lines

ALREADYCVEITEMS = set()


def alreadyProcessed():
    #
    current_dir = os.getcwd()

    #
    folders = [f for f in os.listdir(current_dir) if os.path.isdir(
        os.path.join(current_dir, f))]

    #  "2024"
    target_folders = [f for f in folders if f.startswith('saved')]

    global ALREADYCVEITEMS

    # ，
    for folder in target_folders:
        folder_path = os.path.join(current_dir, folder)
        subfolders = [sf for sf in os.listdir(
            folder_path) if os.path.isdir(os.path.join(folder_path, sf))]

        for subfolder in subfolders:
            ALREADYCVEITEMS.add(subfolder.strip())

    logger.info(f"{len(ALREADYCVEITEMS)} cve items already processed, they are {
                ALREADYCVEITEMS}")

    for item in CVEITEMS.keys():
        if item not in ALREADYCVEITEMS:
            # logger.info(f"{item} not processed")
            pass


def getGeneratePrompt0(cveid: str):
    try:
        cveitem = CVEITEMS[cveid]
    except:
        logger.error(f"{cveid} not found")

    cvedesc = str(cveitem['Description'])
    if cvedesc == "":
        cvedesc = "None"
    cvepatch = str(cveitem['Patch'])
    if cvepatch == "":
        cvepatch = "None"
    cvepoc = str(cveitem['POC'])
    if cvepoc == "":
        cvepoc = "None"
    cvewriteup = str(cveitem['Writeup'])
    if cvewriteup == "":
        cvewriteup = "None"

    baseprompt = str(settings['BPFProgramGenerationPrompt'])

    baseprompt = baseprompt.replace("[[CVE-ID]]", cveid)
    baseprompt = baseprompt.replace("[[CVE-DESCRIPTION]]", cvedesc)

    # logger.debug(cvepatch)
    baseprompt = baseprompt.replace("[[CVE-PATCH]]", cvepatch)
    if cvepoc == "None" and cvewriteup == "None":
        tmp = "None"
    elif cvepoc == "None":
        tmp = cvewriteup
    elif cvewriteup == "None":
        tmp = cvepoc
    else:
        tmp = cvepoc + '\n' + cvewriteup

    baseprompt = baseprompt.replace("[[CVE-POC]]", tmp)

    return baseprompt


def getFuncNamePrompt0(cveid: str):
    try:
        cveitem = CVEITEMS[cveid]
    except:
        logger.error(f"{cveid} not found")

    cvedesc = str(cveitem['Description'])
    if cvedesc == "":
        logger.error(f"{cveid} Description is empty")
        raise Exception
    cvepatch = str(cveitem['Patch'])
    if cvepatch == "":
        cvepatch = "None"

    baseprompt = str(settings['FunctionNameExtractionPrompt'])
    baseprompt = baseprompt.replace("[[CVE-ID]]", cveid)
    baseprompt = baseprompt.replace("[[CVE-DESCRIPTION]]", cvedesc)
    baseprompt = baseprompt.replace("[[CVE-PATCH]]", cvepatch)

    return baseprompt


def getAnalyzePatchPromptV1(cveid: str):
    try:
        cveitem = CVEITEMS[cveid]
    except:
        logger.error(f"{cveid} not found")

    cvedesc = str(cveitem['Description'])
    if cvedesc == "":
        logger.error(f"{cveid} Description is empty")
        raise Exception

    cvepatch = str(cveitem['Patch'])
    if cvepatch == "":
        logger.error(f"{cveid} Patch is empty")
        raise Exception

    baseprompt = str(settings['PatchVulnerabilityInsightPrompt'])
    baseprompt = baseprompt.replace("[[CVE-ID]]", cveid)
    baseprompt = baseprompt.replace("[[CVE-DESCRIPTION]]", cvedesc)
    baseprompt = baseprompt.replace("[[CVE-PATCH]]", cvepatch)

    return baseprompt


def getAnalyzePoCPrompt0(cveid: str):
    try:
        cveitem = CVEITEMS[cveid]
    except:
        logger.error(f"{cveid} not found")

    cvedesc = str(cveitem['Description'])
    if cvedesc == "":
        cvedesc = "None"

    cvepoc = str(cveitem['POC'])
    if cvepoc == "":
        cvepoc = "None"
    cvewriteup = str(cveitem['Writeup'])
    if cvewriteup == "":
        cvewriteup = "None"

    baseprompt = str(settings['ProofOfConceptAnalysisPrompt'])

    baseprompt = baseprompt.replace("[[CVE-ID]]", cveid)
    baseprompt = baseprompt.replace("[[CVE-DESCRIPTION]]", cvedesc)

    if cvepoc == "None" and cvewriteup == "None":
        tmp = "None"
        logger.error(f"{cveid} POC and Writeup is empty")
        raise Exception
    elif cvepoc == "None":
        tmp = cvewriteup
    elif cvewriteup == "None":
        tmp = cvepoc
    else:
        tmp = cvepoc + '\n' + cvewriteup

    baseprompt = baseprompt.replace("[[CVE-POC]]", tmp)

    # [[AST-INFO]]
    from tools.struct_analyzer import ast_analyse
    astanalys = ast_analyse(cvepoc)
    if not astanalys or len(astanalys) == 0:
        logger.debug(f"{cveid} AST analysis failed:\n{cvepoc}\n{cvewriteup}")
    logger.info(f"{cveid} AST analysis result:\n{astanalys}")
    baseprompt = baseprompt.replace("[[AST-INFO]]", astanalys)

    return baseprompt


def getDebugPrompt0(cveid: str):
    try:
        cveitem = CVEITEMS[cveid]
    except:
        logger.error(f"{cveid} not found")

    cvedesc = str(cveitem['Description'])
    if cvedesc == "":
        cvedesc = "None"
    cvepatch = str(cveitem['Patch'])
    if cvepatch == "":
        cvepatch = "None"
    cvepoc = str(cveitem['POC'])
    if cvepoc == "":
        cvepoc = "None"
    cvewriteup = str(cveitem['Writeup'])
    if cvewriteup == "":
        cvewriteup = "None"

    baseprompt = str(settings['BPFProgramDebuggingAssistantPrompt'])

    baseprompt = baseprompt.replace("[[CVE-ID]]", cveid)
    baseprompt = baseprompt.replace("[[CVE-DESCRIPTION]]", cvedesc)

    # logger.debug(cvepatch)
    baseprompt = baseprompt.replace("[[CVE-PATCH]]", cvepatch)
    if cvepoc == "None" and cvewriteup == "None":
        tmp = "None"
    elif cvepoc == "None":
        tmp = cvewriteup
    elif cvewriteup == "None":
        tmp = cvepoc
    else:
        tmp = cvepoc + '\n' + cvewriteup

    baseprompt = baseprompt.replace("[[CVE-POC]]", tmp)

    return baseprompt
