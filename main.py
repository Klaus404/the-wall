# Linux defender by me
import brain

sem = 1

while sem:
    what_to_scan = input("Doriti o scanare rapida (1) sau o scanare punctuala (2) sau sa iesiti din program (q). ")
    if what_to_scan.isnumeric() and int(what_to_scan) < 3:
        if int(what_to_scan) == 1:
            brain.search_for_viruses()
        elif int(what_to_scan) == 2:
            brain.custom_search_for_viruses()
    else:
        if "q" in what_to_scan:
            exit()
        else:
            print("Input ul nu a fost recunoscut, incercati din nou. ")
