#!/usr/bin/env python3
import requests
import csv
import time
from decouple import config
from urllib.parse import urljoin
import sqlite3
from sqlite3 import Error

class SessionWithURLBase(requests.Session):
    def __init__(self, base_url=None, *args, **kwargs):
        super(SessionWithURLBase, self).__init__(*args, *kwargs)
        self.base_url = base_url

    def request(self, method, url, *args, **kwargs):
        full_url = urljoin(self.base_url, url)
        return super(SessionWithURLBase, self).request(method, full_url, *args, **kwargs)


class AssetExport():
    def __init__(self, session):
        self.s = session

    def get_data(self, url_mod):
        try:
            request = self.s.get(url_mod)

            if request.status_code == 200:
                data = request.json()
                #print(r.headers)
                return data
            elif request.status_code == 404:
                print('Check your query...')
                print(request)
            elif request.status_code == 429:
                print("Too many requests at a time... Threading is unbound right now.")
            elif request.status_code == 400:
                pass
            else:
                print("Something went wrong... Don't be trying to hack me now.")
                print(request)
        except ConnectionError:
            print("Check your connection... You got a connection error.")
        #Trying to catch API errors

    def post_data(self, url_mod, payload):
        #send Post request to API endpoint
        request = self.s.post(url_mod, json=payload)
        #retreive data in json format
        data = request.json()
        return data

    def new_db_connection(self, db_file):
        conn = None
        try:
            conn = sqlite3.connect(db_file)
            print(sqlite3.version)
        except Error as E:
            print(E)

        return conn

    def asset_export(self):
        # Set the payload to the maximum number of assets to be pulled at once
        thirty_days = time.time() - 7776000
        payload = {"chunk_size": 100, "filters": {"last_assessed": int(thirty_days)}}
        try:
            # request an export of the data
            export = self.post_data("/assets/export", payload)

            # grab the export UUID
            ex_uuid = export['export_uuid']
            print('Requesting Asset Export with ID : ' + ex_uuid)

            # now check the status
            status = self.get_data('/assets/export/{}/status'.format(ex_uuid))

            # status = get_data('/vulns/export/89ac18d9-d6bc-4cef-9615-2d138f1ff6d2/status')
            print("Status : ".format(str(status["status"])))

            # set a variable to True for our While loop
            not_ready = True

            # loop to check status until finished
            while not_ready is True:
                # Pull the status, then pause 5 seconds and ask again.
                if status['status'] == 'PROCESSING' or 'QUEUED':
                    time.sleep(5)
                    status = self.get_data('/assets/export/{}/status'.format(ex_uuid))
                    print("Status : " + str(status["status"]))

                # Exit Loop once confirmed finished
                if status['status'] == 'FINISHED':
                    not_ready = False

                # Tell the user an error occured
                if status['status'] == 'ERROR':
                    print("Error occurred")

            # create an empty list to put all of our data into.
            data = list()

            #Create our headers - We will Add these two our list in order
            header_list = [
                "IP Address", "Hostname", "FQDN", 
                "UUID", "First Found", "Last Found", 
                "Operating System", "Mac Address", "Agent UUID", 
                "Last Licensed Scan Data"
            ]

            #Crete a csv file object
            with open('asset_data.csv', mode='w+') as csv_file:
                agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')

                #write our Header information first
                agent_writer.writerow(header_list)

                # loop through all of the chunks
                for x in range(len(status['chunks_available'])):
                    chunk_data = self.get_data('/assets/export/{UUID}/chunks/{NUM}'.format(UUID=ex_uuid, NUM=str(x + 1)))

                    print("Parsing Chunk {} ...Finished".format(x+1))
                    for assets in chunk_data:
                        #create a blank list to append asset details
                        csv_list = []
                        #Try block to ignore assets without IPs
                        try:
                            #Capture the first IP
                            try:
                                ip = assets['ipv4s'][0]
                                csv_list.append(ip)
                            except:
                                csv_list.append(" ")
                            #try block to skip if there isn't a hostname
                            try:
                                csv_list.append(assets['hostnames'][0])

                            except:
                                # If there is no hostname add a space so columns still line up
                                csv_list.append(" ")

                            try:
                                csv_list.append(assets['fqdns'][0])
                            except:
                                csv_list.append(" ")

                            try:
                                id = assets['id']
                                csv_list.append(id)
                            except:
                                csv_list.append(" ")
                            try:

                                csv_list.append(assets['first_seen'])
                            except:
                                csv_list.append(" ")
                            try:

                                csv_list.append(assets['last_seen'])
                            except:
                                csv_list.append(" ")
                            try:
                                csv_list.append(assets['operating_systems'][0])
                            except:
                                csv_list.append(" ")

                            try:
                                csv_list.append(assets['mac_addresses'][0])
                            except:
                                csv_list.append(" ")

                            try:
                                csv_list.append(assets['agent_uuid'])
                            except:
                                csv_list.append(" ")

                            try:
                                csv_list.append(assets["last_licensed_scan_date"])
                            except:
                                csv_list.append(" ")

                            agent_writer.writerow(csv_list)

                        except IndexError:
                            pass


        except KeyError:
            print("Well this is a bummer; you don't have permissions to download Asset data :( ")


if __name__ == '__main__':
    requests.packages.urllib3.disable_warnings()
    BASE_URL = "https://cloud.tenable.com"
    ACCESS_KEY = config("ACCESS_KEY")
    SECRET_KEY = config("SECRET_KEY")
    session = SessionWithURLBase(BASE_URL)
    session.headers.update({
        "x-apikeys": "accessKey={};secretKey={}".format(ACCESS_KEY, SECRET_KEY),
        "accept": "application/json",
    })
    asset_export = AssetExport(session)
    asset_export.asset_export()

    print("\nStarting your CSV Export now")
    print("\nYour export is finished")
