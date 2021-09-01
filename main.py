# Linux defender by me
import os
import glob
import shutil
import json
import magic
import vtapi3
from vtapi3 import VirusTotalAPIFiles, VirusTotalAPIError
import urllib
import re

# Prima etapa este sa scanez Downloadurile si sa verific daca este prezent malware
# Trebuie sa gasesc o baza de date de unde sa preiau toate potentialele amenintari (ceva API idk)

virustotal_apikey = "8585f51b40008950b8cc0a9776996697de63c73b51ac6688bfcdd84c03558329"
download_path = "/home/klaus/Downloads"
malware_list = "https://dasmalwerk.eu/"
vt_files = VirusTotalAPIFiles(virustotal_apikey)


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


def search_for_viruses():
    for virused in glob.glob(f'{download_path}/*'):
        if "virus" in virused or "malware" in virused:
            try:
                print(str(magic.from_file(virused)))
                scan_file(virused)
            except os.error as error:
                pass


search_for_viruses()
