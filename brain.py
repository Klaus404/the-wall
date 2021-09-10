import os
import glob
import shutil
import json
import magic
from vtapi3 import VirusTotalAPIFiles, VirusTotalAPIError
# from bs4 import BeautifulSoup
# import requests
# import urllib
# import re

# Prima etapa este sa scanez Downloadurile si sa verific daca este prezent malware
# Trebuie sa gasesc o baza de date de unde sa preiau toate potentialele amenintari (ceva API idk)

virustotal_apikey = "8585f51b40008950b8cc0a9776996697de63c73b51ac6688bfcdd84c03558329"
download_path = "/home/klaus/Downloads"
malware_list_URL = "https://dasmalwerk.eu/"
vt_files = VirusTotalAPIFiles(virustotal_apikey)

# result = requests.get(malware_list_URL)
# print(result.text)


# def is_int(value):
#     try:
#         int(value)
#         return True
#     except ValueError:
#         return False


def scan_file(file_path):
    try:
        result = vt_files.upload(str(file_path))
    except VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if vt_files.get_last_http_error() == vt_files.HTTP_OK:
            result = json.loads(result)
            result = json.dumps(result, sort_keys=False, indent=4)
            print(result)
        else:
            print('HTTP Error [' + str(vt_files.get_last_http_error()) + ']')


def remove_virused_file(virused):
    decision = input(f"A fost gasit un fisier periculos:{virused}. Doriti sa l eliminati?(y/N)").lower()
    if "y" in decision:
        try:
            shutil.rmtree(virused)
        except OSError as error:
            print(error)
            os.remove(virused)
        print("Fisierul periculos a fost eliminat.")
    elif "n" in decision:
        print("Ati refuzat stergerea unui program potential periculos.")
    else:
        print("Raspuns invalid")
        remove_virused_file(virused)


# Trebuie sa definesc un criteriu dupa care se face scanarea, daca nu, scanam tot.

def search_for_viruses():
    for virused in glob.glob(f'{download_path}/*'):
        if "virus" in virused or "malware" in virused:
            try:
                print(str(magic.from_file(virused)))
                scan_file(virused)
            except os.error as error:
                print(error)


def custom_search_for_viruses():
    absolute_path = input("Introduceti calea absoluta catre fisierul pe care doriti sa l scanati. ")
    try:
        scan_file(absolute_path)
    except os.error as error:
        print(error)
