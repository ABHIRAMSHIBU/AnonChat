import socketpremitives
from anoncrypto import AnonKeys
from threading import Thread
from pprint import pprint
from Crypto.PublicKey import RSA
import traceback

db = {}
askey = AnonKeys(file_name="userkey.pickle")
askey.load_RSA_key()

sockp = socketpremitives.CommUtils(db=db, askey=askey, HOST="192.168.43.3")

t = Thread(target=sockp.receiver_function)
t.start()

def print_banner():
    # GPL 2 banner no warrante
    print("""
    AnonChat (c) 2022 Abhiram Shibu
    This program comes with ABSOLUTELY NO WARRANTY.
    This is free software, and you are welcome to redistribute it
    under certain conditions.
    """)
    print("Enter $help for help")

def UI_Main():
    print_banner()
    chosen_person = None
    while(True):
        try:
            inp = input("You:").strip()
            if(inp == "$help"):
                print("Help Menu - Conrgatz you have discovered help menu")
                print("1) $menu for menu")
                print("2) $help for help")
                print("Type a message to chat")
            elif(inp == "$menu"):
                print("1) Contact list")
                print("2) Messages")
                print("3) New Contact")
                print("4) Export Public Key")
                print("5) Print DB")
                print("6) Exit")
                inp = input("Choice?[1]:").strip()
                if(inp == "1" or inp == ""):
                    pprint(db.keys())
                    inp = int(input(f"Choice?[{list(db.keys()).index(list(db.keys())[0])+1}]:").strip())
                    if(inp != ""):
                        chosen_person = list(db.keys())[inp-1]
                    else:
                        chosen_person = list(db.keys())[0]
                elif(inp == "2"):
                    if(chosen_person):
                        pprint(db[chosen_person]["messages"])
                    else:
                        print("No selected contact, please select one.")
                elif(inp == "3"):
                    contact = input("Contact url:")
                    # Bail out if user is not going to enter anything
                    if(contact == ""):
                        continue
                    inp = input("PublicKey:").strip('\ ').encode()
                    # Bail out if user is not going to enter anything
                    if(inp == ""):
                        continue
                    db[contact] = {"messages": [], "pubkey": None}
                    key = None
                    try:
                        key = RSA.import_key(inp)
                    except:
                        print("Import Failure! Please try again!")
                    db[contact]["pubkey"] = key
                elif(inp == "4"):
                    print(askey.public_key.export_key("OpenSSH").decode())
                elif(inp == "5"):
                    print(db)
                elif(inp == "6"):
                    exit(0)
                    break
                else:
                    print("Try again!")
            else:
                if(chosen_person):
                    try:
                        sockp.send_message(askey.public_key, db[chosen_person]["pubkey"],
                                        chosen_person, inp)
                    except Exception as e:
                        # print stacktrace of the error
                        traceback.print_exc()
                        print(e)
                        print("Error sending message")
                else:
                    print("No selected contact, please select one.")
        except KeyboardInterrupt:
            print("Exiting!")
            break
        except Exception as e:
            print(e)
            continue


if(__name__ == "__main__"):
    UI_Main()
