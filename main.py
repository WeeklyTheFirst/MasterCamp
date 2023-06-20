import requests
import tkinter as tk
import re
import ntpath
from tkinter.filedialog import askopenfilename
tk.Tk().withdraw() # part of the import if you are not using other tkinter functions

def path_leaf(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)

def FileUpload() :
    url = "https://www.virustotal.com/api/v3/files"
    print("séléctionnez votre fichier\n")
    input("Pressez entrée pour continuer")
    ans = askopenfilename()

    files = {
        "file": (path_leaf(ans), open(ans,"r", "rb"), "application/pdf")
    }
    headers = {
    "accept": "application/json",
    "x-apikey": "0804a81061b66b0775a83ea6d2877e465677be0ec9e70a9727965d62a468196f"
    }

    response = requests.post(url, files=files, headers=headers)
    


def Analyse() :
    url = "https://www.virustotal.com/api/v3/analyses/M2VjMzdhOGFjNjExMWFkMzVkZGFkMDE0YmRlYWM5OTY6MTY4NjU1OTM1NA=="

    headers = {
    "accept": "application/json",
   "x-apikey": "0804a81061b66b0775a83ea6d2877e465677be0ec9e70a9727965d62a468196f"
    }

    response = requests.get(url, headers=headers)

    print(response.text)
    f= open("analyse-results.txt","w")
    f.write(response.text)
    f.close


def main():
    print("\tMenu\n1. uploader un fichier\n2. analyser une URL\n")
    fct = int(input("que souhaitez vous faire ?\n"))
    match fct:
        case 1:
            FileUpload()
        case 2:
            URL_Analyse()

def Read_id(response) :
    found = re.search('"id": "(.+?)",', response).group(1) #group(0) will return full matched string, group(1) only the string between
    return found



def URL_Analyse() :

    url = "https://www.virustotal.com/api/v3/urls"
    ans = "url="
    ans = ans + input("quel est l'URL à analyser ?")
    payload = ans
    headers = {
        "accept": "application/json",
        "x-apikey": "0804a81061b66b0775a83ea6d2877e465677be0ec9e70a9727965d62a468196f",
        "content-type": "application/x-www-form-urlencoded"
    }

    response = requests.post(url, data=payload, headers=headers)

    print(response.text)

    id = Read_id(response.text)
    id_request = "https://www.virustotal.com/api/v3/analyses/"
    id_request = id_request + id

    headers = {
    "accept": "application/json",
    "x-apikey": "0804a81061b66b0775a83ea6d2877e465677be0ec9e70a9727965d62a468196f"
    }

    response = requests.get(id_request, headers=headers)

    print(response.text)

    results = get_results(response.text)
    print(results)

def get_results(response) :
    found = re.search('"harmless":(.+?),', response).group(0) #group(0) donnera le string et ses marqueurs, group(1) envoie uniquement le string entre les marqueurs
    found = found + "\n" + re.search('"malicious":(.+?),', response).group(0)
    found = found + "\n" + re.search('"suspicious":(.+?),', response).group(0)
    found = found + "\n" + re.search('"undetected":(.+?),', response).group(0)
    return found


main()
#import json
#import requests
...
#api_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
#params = dict (apikey = '<access key>')
#with open ('<path to file>', 'rb') as file:
#  files = dict (file = ('<path to file>', file))
#  response = requests.post(api_url, files=files, params=params)
#if response.status_code == 200:
#  result=response.json()
#  print(json.dumps(result, sort_keys=False, indent=4))
