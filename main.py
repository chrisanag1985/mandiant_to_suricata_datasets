import mandiant_threatintel
import json
import configparser
import argparse
import base64
import sys
from datetime import datetime
from urllib.parse import urlparse


"""
NOTICE
------
In datarep I hit a hardlimit of 241000 so use here the minscore to reduce the records that you will 
retrieve. Else you have to convert them to datasets.
"""

# ARGPARSE CONFIGURATOR

description = "Download Mandiant Threat Intelligence Through API"

parser = argparse.ArgumentParser(description=description)

parser.add_argument("-s","--start-datetime",type=str,help="Start Datetime of search | Format dd/mm/YYYY@HH:MM:SS | (Default: Start of current day)")
parser.add_argument("-e","--end-datetime",type=str,help="End Datetime of search | Format dd/mm/YYYY@HH:MM:SS | (Default: Now)")
parser.add_argument("-m","--min-score",type=int,help="Minimum score of confidence (Default: 0)",default=0)
parser.add_argument("-p","--page-size",type=int,help="The number of results to retrieve per page - Not limit the results to retrieve (Default: 1000)",default=1000)
parser.add_argument("--exclude-osint",help="Exclude OSINT from results",action="store_true" )
parser.add_argument("--dataset",help="Create lists as datasets | (Default: datarep)",action="store_true")
parser.add_argument("-v","--verbose",help="Print Arguments",action="store_true")
args= parser.parse_args()

if args.verbose:
    print(args)

if (args.start_datetime != None):
    start_datetime= datetime.strptime(args.start_datetime,"%d/%m/%Y@%H:%M:%S")
else:
    start_datetime = datetime.combine(datetime.today(),datetime.min.time())

if (args.end_datetime != None):
    end_datetime= datetime.strptime(args.end_datetime,"%d/%m/%Y@%H:%M:%S")
else:
    end_datetime= datetime.now()

isDataset = args.dataset


# LOAD CONFIG
config = configparser.ConfigParser()
config.read('config.ini')
api_key = config["MANDIANT_CONFIG"]["api_key"]
secret_key = config["MANDIANT_CONFIG"]["secret_key"]

def write_to_file(filename,lista):


    f = ""
    f = open(filename,"w")
    if lista == list_ipv4 or lista ==list_http:
        for key in lista:
            if isDataset:
                line = lista[key]["payload"]
            else:
                line = lista[key]["payload"] +","+str(lista[key]["score"])
            f.write(line+"\n")

    else:
        for key in lista:
            if isDataset:
                if type(lista[key]["payload"]) is bytes:
                    line = lista[key]["payload"].decode('utf-8')
                else:
                    line = lista[key]["payload"]

            else:
                if type(lista[key]["payload"]) is bytes:
                    line = lista[key]["payload"].decode('utf-8') +","+str(lista[key]["score"])
                else:
                    line = lista[key]["payload"] +","+str(lista[key]["score"])
            f.write(line+"\n")
    f.close()
    print(f"[+] File %s created"%filename)


"""
https://github.com/google/mandiant-ti-client/blob/main/mandiant_threatintel/threat_intel_client.py

Args:
      minimum_mscore: A minimum 'mscore', or 'confidence'.
      exclude_osint: If True, then exclude Open Source Intelligence from results
      start_epoch: A datetime object representing the start of the time range
      end_epoch: An optional datetime object representing the end of the time
        range to retrieve.  Defaults to "now"
      page_size: The number of results to retrieve from MATI per page.  Does not
        limit the total number of results to retrieve
"""

print(f"[+] Download Indicators from %s to %s with score %d"%(start_datetime,end_datetime,args.min_score))

mati_client = mandiant_threatintel.ThreatIntelClient(api_key=api_key,secret_key=secret_key)
indicators = mati_client.Indicators.get_list(start_epoch=start_datetime,end_epoch=end_datetime,minimum_mscore=args.min_score,exclude_osint=args.exclude_osint,page_size=args.page_size)

## Download process
count = 0
with open("./indicators.json","w") as f:

    for indicator in indicators:
        count = count + 1
        sys.stdout.write("\r[+] Indicators downloaded: "+str(count))
        event_data: dict = indicator._api_response
        f.write(json.dumps(event_data)+"\n")
    
f.close()
sys.stdout.write("\n")


try:
    f = open("./indicators.json","r")
except:
    print("[+] Couldn't open the file")
    exit()

list_ipv4 = {} 
list_fqdn = {}
list_tls = {} 
list_http = {} 
list_smtp = {} 
list_tcp = {} 
list_else = {} 
list_md5 = {}

count = 0

for x in f.readlines():
    event_data = json.loads(x)
    itype, ivalue, imscore = event_data["type"],event_data["value"],event_data["mscore"]

    match itype:

        case 'fqdn' | "url":

            if "http://" in ivalue:
                if ivalue not in list_http:
                    list_http[ivalue] = { "payload":ivalue ,"score" : imscore }
            elif "https://" in ivalue:
                #here we need filtering because we don't 
                #inspect TLS
                pass
            elif "tcp://" in ivalue:
                if ivalue not in list_fqdn:
                    hostname = urlparse(ivalue).hostname 
                    text_bytes = hostname.encode('utf-8')
                    base64_bytes = base64.b64encode(text_bytes)
                    payload = base64_bytes.decode('utf-8') 
                    list_fqdn[ivalue] = {"payload":payload,"score":imscore}
            elif "smtp://" in ivalue:
                if ivalue not in list_fqdn:
                    hostname = urlparse(ivalue).hostname 
                    text_bytes = hostname.encode('utf-8')
                    base64_bytes = base64.b64encode(text_bytes)
                    payload = base64_bytes.decode('utf-8') 
                    list_fqdn[ivalue] = {"payload":payload,"score":imscore}

            elif "://" not in ivalue:
                if ivalue not in list_fqdn:
                    text_bytes = ivalue.encode('utf-8')
                    base64_bytes = base64.b64encode(text_bytes)
                    payload = base64_bytes.decode('utf-8') 
                    list_fqdn[ivalue] = {"payload":payload,"score":imscore}
            else:
                if ivalue not in list_fqdn:
                    hostname = urlparse(ivalue).hostname 
                    text_bytes = hostname.encode('utf-8')
                    base64_bytes = base64.b64encode(text_bytes)
                    payload = base64_bytes.decode('utf-8') 
                    list_fqdn[ivalue] = {"payload":payload,"score":imscore}
        case 'md5':
            list_md5[ivalue] = { "payload" : ivalue , "score":imscore }

        case 'ipv4' | 'ip':
            if ivalue not in list_ipv4:
                    list_ipv4[ivalue] = {"payload":ivalue,"score":imscore}

    count = count + 1
    sys.stdout.write("\r[+] Indicators processed: "+str(count))

        
f.close()

d = "Datasets" if isDataset else "Datareps"
print(f"\n[+] Creating %s"%d)

write_to_file("http.lst",list_http)
write_to_file("ipv4.lst",list_ipv4)
write_to_file("fqdn.lst",list_fqdn)
write_to_file("md5.lst",list_md5)