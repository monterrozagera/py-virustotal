import argparse
import hashlib
import requests
import json

class VT_Handler():

    def __init__(self, api_key):
        self.key = api_key

    def printKey(self):
        """ prints loaded API key """
        print(f"API key: {self.key}")

    def printFile(self, file):
        """ prints loaded file to analyze """
        print(f"Loaded file: {file} (Hash: {self.getFileHash(file)})")

    def getFileHash(self, file_path) -> str:
        """ returns SHA-1 digest of a file """
        hash_lib = hashlib.sha1()

        with open(file_path, 'rb') as file:

            chunk = 0
            while chunk != b'':
                chunk = file.read(1024)
                hash_lib.update(chunk)

            return hash_lib.hexdigest()


    def hashLookup(self, hash_sample) -> dict:
        """ request for hash information """

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
