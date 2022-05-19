from AnonChat_main import *
import string
import os
import random
#import RSA
import traceback
from Crypto.PublicKey import RSA
from datetime import datetime

public_key = ""

def add_to_contact_list(url,key):
    '''
    url: Tor URL
    key: Public Key of the contact
    '''
    db[url] = {"messages": [], "pubkey": None}
    try:
        key = RSA.import_key(key)
    except:
        print("Import Failure! Please try again!")
        # print the stack trace
        traceback.print_exc()

    db[url]["pubkey"] = key

def send_message(chosen_person,message):
    '''
    chosen_person:Url of person to send message to
    message:Message to be send
    '''
    return sockp.send_message(askey.public_key, db[chosen_person]["pubkey"],
                                            chosen_person, message)


def perform_benchmark(receiver_url,reciever_public_key):
    # check if benchmark file exists
    if(os.path.exists("benchmark_output.csv")):
        os.remove("benchmark_output.csv")
    # create file
    f = open("benchmark_output.csv","w")
    # write header in format Time in seconds,Message Size,Message
    f.write("Time in seconds,Message Size,Message\n")

    # remove the db file
    os.remove("messages.log")
    '''
    Performs the benchmark
    '''
    # add the keys to the database
    add_to_contact_list(receiver_url,reciever_public_key)
    for i in range(100):
        # create a random message with random length
        message = ''.join(random.choice(string.ascii_letters) for _ in range(random.randint(1,100)))
        # print the message
        print("Message:",message)
        t1 = datetime.now()
        # send the message
        response = send_message(receiver_url,message)
        print("Response:",response)
        if(response):
           # write the time diff in seconds
            t2 = datetime.now()
            diff = t2 - t1
            diff = diff.total_seconds()
            # write the message size
            message_size = len(message)
            # write the message
            message = message.replace(","," ")
            # write the message to the file
            f.write(str(diff)+","+str(message_size)+","+message+"\n")
        else:
            print("Message not sent")





if __name__ == "__main__":
    key = '''ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCbd5wIZBn5cnz1mn74WlKo8s0NkvDzLVnFXBaLqlBy4vBx7s6OVD7MGcsTKvg0E7pSoL5A5Eq2BlxgVOse0tlI+dJKQ/uuiyJ7zw3aP08wHs+94oxyMfeS07k+Pf0MLOSn2R1x2lLGdeR3zoLF6KkPDbfTE89ZUaYitSzDAloFB86GnDhbcMwfRcKUHQK0e1HQ1Pz3Xz54+hW1k3KLaEuwyaT8nV6ocAt8SdjmDSLN4jih4QB4hPiFyFLhH4K1wlEls5b8PDVeADNNFUq1KARGPB+gMSmeqC3lIU9Q7C+XLPjkEpLz4jvONg+QVwvxRHhi8+H3n0N+J4xWEYyoeti9'''
    url = "192.168.8.5"
    perform_benchmark(url,key)


