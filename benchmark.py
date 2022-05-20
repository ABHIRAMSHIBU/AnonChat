import os

# remove the db file
if os.path.exists("messages.log"):
    os.remove("messages.log")
if os.path.exists("checksum.txt"):
    os.remove("checksum.txt")

from AnonChat_main import *
import string
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
    key = '''ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDFZNe7E3ruW8//ESTvPDbRoSlZfFU8MDmnhKgA8pufxSyMTm54ApvxK0PHez2h3/cQl1w74neIGUBHko+XodQM00KJc+ZitNzmvY2uHGnHRD4a38huhnq6bG1w+2i6ZvY2Kh08+nWZUb00Psd9yVsyb5mY2AkAwYeIiM0cnzQ5s+KfEoLZpq78yQwvIrbJdL0p6Y/iN2HO9D6O2Sf/z9hTnMdgPAJvOF9kDc3qHCW0YHMx39SUNdjcMLENaM1FMkCvg2HZu348+ISexdvjr9PxZRtj+Do/ZNtWhdHHJTwzTQIoDYICmj56I/ou7GsBjdbjscqE/MvqbpJ+DRvN3Rnh'''
    url = "qk2x3zg7slhyplmfcxhhhch7zcbok3q7tucgkgg7zol63f7hivudwead.onion"
    # url = "192.168.43.3"
    perform_benchmark(url,key)


