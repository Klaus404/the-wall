# Linux defender by me
import os
import glob
import shutil
from virus_total_apis import PublicApi as VirusTotalPublicApi
import virustotal3
import urllib
import re

# Prima etapa este sa scanez Downloadurile si sa verific daca este prezent malware
# Trebuie sa gasesc o baza de date de unde sa preiau toate potentialele amenintari (ceva API idk)

virustotal_apikey = "8585f51b40008950b8cc0a9776996697de63c73b51ac6688bfcdd84c03558329"
download_path = "/home/klaus/Downloads"
malware_list = "https://dasmalwerk.eu/"
vt = VirusTotalPublicApi(virustotal_apikey)

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


def search_for_virus_in_filename():
    for virused in glob.glob(f'{download_path}/*'):
        if "virus" in virused or "malware" in virused:
            remove_virused_file(virused)


search_for_virus_in_filename()
