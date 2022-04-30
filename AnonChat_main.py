import socketpremitives
from anoncrypto import AnonKeys
from threading import Thread
from pprint import pprint
from Crypto.PublicKey import RSA

db = {}
askey = AnonKeys(file_name="userkey.pickle")
askey.load_RSA_key()

sockp = socketpremitives.CommUtils(db=db, askey=askey, HOST="192.168.43.3")

t = Thread(target=sockp.receiver_function)
t.start()


def UI_Main():
    chosen_person = None
    while(True):
        try:
            inp = input(">").strip()
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
                if(inp == "1"):
                    pprint(db.keys())
                    inp = int(input(f"Choice?[{list(db.keys())[0]}]:").strip())
                    chosen_person = list(db.keys())[inp]
                elif(inp == "2"):
                    if(chosen_person):
                        pprint(db[chosen_person]["messages"])
                    else:
                        print("No selected contact, please select one.")
                elif(inp == "3"):
                    contact = input("Contact url:")
                    db[contact] = {"messages": [], "pubkey": None}
                    inp = input("PublicKey:").strip('\' ').encode()
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
                    break
                else:
                    print("Try again!")
            else:
                if(chosen_person):
                    sockp.send_message(db[chosen_person]["pubkey"],
                                       chosen_person, inp)
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
