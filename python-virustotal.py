from hashlib import sha1
from time import sleep
import argparse

import requests

class VT_Handler():

    def __init__(self, api_key):
        self.key = api_key

    def printKey(self) -> None:
        """ prints loaded API key """
        print(f"API key: {self.key}")

    def printFile(self, file) -> None:
        """ prints loaded file to analyze """
        print(f"Loaded file: {file} (Hash: {self.getFileHash(file)})")

    def getFileHash(self, file_path) -> str:
        """ returns SHA-1 digest of a file """
        hash_lib = sha1()

        with open(file_path, 'rb') as file:

            chunk = 0
            while chunk != b'':
                chunk = file.read(1024)
                hash_lib.update(chunk)

            return hash_lib.hexdigest()


    def hashLookup(self, hash_sample) -> None:
        """ sends GET request to gather information about hash """
        " TODO: add more outputz "

        url = f"https://www.virustotal.com/api/v3/search?query={hash_sample}"

        headers = {
            "accept" : "application/json",
            "x-apikey" : self.key
            }

        response = requests.get(url, headers=headers)
        contents = response.json()

        if not contents['data']:
            print('[!] Hash not present in virustotal DB.')
        else:
            names = contents['data'][0]['attributes']['names']
            tags = contents['data'][0]['attributes']['tags']

            print("[!] File names:")
            for name in names:
                print('\t' + name)

            print("[*] Tags:")
            for tag in tags:
                print('\t' + tag)

    def uploadFile(self, file_to_upload) -> str:
        """ uploads file to VirusTotal, returns report ID """
        url =  "https://www.virustotal.com/api/v3/files"
        headers = {
            'accept': 'application/json',
            'x-apikey': self.key
        }
        files = {'file': open(file_to_upload, 'rb')}

        response = requests.post(url, files=files, headers=headers)
        contents = response.json()
        return contents['data']['id']

    def getFileAnalysis(self, id):
        """ prints results of file analysis """
        url = f"https://www.virustotal.com/api/v3/analyses/{id}"
        headers = {
            "accept": "application/json",
            "x-apikey": self.key
        }

        response = requests.get(url, headers=headers)
        contents = response.json()

        while contents['data']['attributes']['status'] == 'queued':
            sleep(5)
            print("[!] Report status: queued. Waiting..")
            response = requests.get(url, headers=headers)
            contents = response.json()

        if contents['data']['attributes']['status'] == 'completed':
            stats = contents['data']['attributes']['stats']

            print("[!] Stats: ")
            for attribute, value in stats.items():
                print(f"\t{attribute} = {value}")

    def createReport(self):
        """ creates PDF report file """
        pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-k', '--key', type=str, required=False, help="Your VirusTotal API key.")
    parser.add_argument('-f', '--file', type=str, required=False, help="File to analyze.")
    args = parser.parse_args()

    api_key = ''
    file = ''
    
    if args.key:
        api_key = args.key
    
    if args.file:
        file = args.file

    virus_total = VT_Handler(api_key=api_key)
    virus_total.printKey()
    virus_total.printFile(file)

    hash = virus_total.getFileHash(file)
    virus_total.hashLookup(hash)
    id = virus_total.uploadFile(file)
    virus_total.getFileAnalysis(id=id)
