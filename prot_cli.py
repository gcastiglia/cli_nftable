import json
from nftables import Nftables
import sys



def init_nftables():

    nft = Nftables()
    
    # Désactiver les logs pour une exécution propre
    nft.set_json_output(True)
    commandes_json = """{
    "nftables": [
    { "flush": { "ruleset": null } },
    { "add": { "table": { "family": "inet", "name": "firewall" } } },
    { "add": { "set": { "family": "inet", "name": "blacklist", "table": "firewall", "type": "ipv4_addr", "flags": ["interval"], "elem": ["1.2.3.4"]} } },
    { "add": { "chain": { "family": "inet", "table": "firewall", "name": "input","type":"filter","hook":"input","prio":0,"policy":"drop" } } },
    { "add": { "chain": { "family": "inet", "table": "firewall", "name": "forward", "type":"filter","hook":"forward","prio":0,"policy":"drop"} } },
    { "add": { "chain": { "family": "inet", "table": "firewall", "name": "nat", "type":"nat","hook":"postrouting","prio":0,"policy":"accept"} } },
    { "add": { "chain": { "family": "inet", "table": "firewall", "name": "prerouting", "type":"filter","hook":"prerouting","prio":-300,"policy":"accept"} } },
    { "add": { "rule": { "family": "inet", "table": "firewall", "chain": "nat",
                         "expr": [ { "match": { "op": "==", "left": { "meta": { "key": "oifname"} }, "right": "enp0s1" } },
                                   { "masquerade": null } ] } } },
    { "add": { "rule": { "family": "inet", "table": "firewall", "chain": "input",
                         "expr": [ { "match": { "op": "==", "left": { "meta": { "key": "iif"} }, "right": "lo" } },
                                   { "accept": null } ] } } },                                   
    { "add": { "rule": { "family": "inet", "table": "firewall", "chain": "input",
                        "expr": [{"match": {"op": "==", "left": {"ct": {"key":"state"}}, "right": {"set": ["established", "related"]}}},
                                 {"accept": null}]}}},                               
    { "add": { "rule": { "family": "inet", "table": "firewall", "chain": "input",
                        "expr": [{"match": {"op": "==", "left": {"ct": {"key":"state"}}, "right": "invalid"}},
                                 {"drop": null}]}}},
    { "add": { "rule": { "family": "inet", "table": "firewall", "chain": "forward",
                        "expr": [{"match": {"op": "==", "left": {"ct": {"key":"state"}}, "right": {"set": ["established", "related"]}}},
                                 {"accept": null}]}}},                               
    { "add": { "rule": { "family": "inet", "table": "firewall", "chain": "forward",
                        "expr": [{"match": {"op": "==", "left": {"ct": {"key":"state"}}, "right": "invalid"}},
                                 {"drop": null}]}}},
    { "add": { "rule": { "family": "inet", "table": "firewall", "chain": "input",
                        "expr": [{"match": {"op": "==", "left": {"meta": {"key":"l4proto"}}, "right": "icmp"}},
                                 {"accept": null}]}}},                                                                                                      
    { "add": { "rule": { "family": "inet", "table": "firewall", "chain": "input",
                        "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": "22"}},
                                 {"accept": null}]}}},
    { "add": { "rule": { "family": "inet", "table": "firewall", "chain": "prerouting",
                        "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "@blacklist"}},
                                 {"drop": null}]}}}                             
    ]
    }
"""   
    try:
        # Convertir en JSON et appliquer
        rc, output, error = nft.json_cmd(json.loads(commandes_json))
       
        if rc != 0:
            print(f"❌ Erreur lors de l'application des règles: {error}")
            return False
        else:
            print("✅ Règles nftables appliquées avec succès!")
            print(f"📋 Sortie: {output}")
            return True
            
    except Exception as e:
        print(f"❌ Exception: {e}")
        return False


def set_port(liste_protocole):
    if len(liste_protocole) == 0:
        return liste_protocole[0]
    else:
        return {"set":liste_protocole}

def set_ip(liste_ip):
    def traite_ip(ip):
        if "/" in ip:
            addr,len = ip.split("/")
            return { "prefix" : {"addr" : addr, "len": int(len) } }
        else:
            return ip
    retour = list(map(traite_ip,liste_ip))
    return {"set": retour}        

def choix_nftables():
    """ajout de regle"""
    
    nft = Nftables()
    
    # Désactiver les logs pour une exécution propre
    nft.set_json_output(True)
    ruleset_base = {"nftables" : []}
    ruleset_input_tcp_udp = { 
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": "firewall",
                        "chain": "input",
                        "expr": [
                            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp_or_udp", "field": "dport"}}, "right": "port"}},
                            {"accept": None}
                        ]
                    }
            }       
    }

    ruleset_input_spec_ip_tcp_udp = {
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": "firewall",
                        "chain": "input",
                        "expr": [
                            {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "ip_or_set"}},
                            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp_or_udp", "field": "dport"}}, "right": "port"}},
                            {"accept": None}
                        ]
                    }
            }    
    } 
    
    ruleset_forward_tcp_udp = {

                "add": {
                    "rule": {
                        "family": "inet",
                        "table": "firewall",
                        "chain": "forward",
                        "expr": [
                            {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "ip_subnet_set"}},
                            {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "ip_subnet_set"}},
                            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp_udp", "field": "dport"}}, "right": "port_or set" }},
                            {"accept": None}
                        ]
                    }
            }    
    }




    ruleset_forward_ping = {

                "add": {
                    "rule": {
                        "family": "inet",
                        "table": "firewall",
                        "chain": "forward",
                        "expr": [
                            {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "ip_subnet_set"}},
                            {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "ip_subnet_set"}},
                            {"match": {"op": "==", "left": {"payload": {"protocol": "icmp", "field": "type"}}, "right": {"set" : ["echo-reply","echo-request"] }}},
                            {"accept": None}
                        ]
                    }
            }    

    }
    
    ruleset_forward_wan = {
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": "firewall",
                        "chain": "forward",
                        "expr": [
                            {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "ip_subnet_set"}},
                            {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "enp1s0" }},
                            {"accept": None}
                        ]
                    }
            }    

    }
    continuer = 1
    while(continuer):  
        choix_user = input("quelle type de chaine voulez vous crééer ?\n\"input\" qui permet de créer une regle pour un flux direct pour le router\n\"forward\" pour du routage : ")
        if choix_user == "input":
            choix_input = int(input("[1] : toutes IP, [2] : ip specifiques : "))
            if choix_input == 1:
                ruleset_user = ruleset_input_tcp_udp
                choix_protocole = input("quelle protocole : udp ou tcp : ")
                if choix_protocole == "udp" or choix_protocole == "tcp":
                    ruleset_user["add"]["rule"]["expr"][0]["match"]["left"]["payload"]["protocol"] = choix_protocole
                else:
                    print(f"❌ Exception: {e}")
                    break
                try :
                    choix_protocole = int(input("combien de ports/protocole ? : "))
                    liste_ports = []
                    for i in range(choix_protocole):
                        choix_port = int(input("donner les ports : "))
                        liste_ports.append(choix_port)
                    ruleset_user["add"]["rule"]["expr"][0]["match"]["right"] = set_port(liste_ports)
                    ruleset_base["nftables"].append(ruleset_user)   
                except Exception as e:
                    print(f"❌ Exception: {e}")
                    break
            elif choix_input == 2:
                ruleset_user = ruleset_input_spec_ip_tcp_udp
                try:
                    choix_nb_ip = int(input("combien d'ip accede au routeur ? : "))
                    liste_ip = []
                    for i in range(choix_nb_ip):
                        choix_ip = input("donnez l'ip ou le subnet : ")
                        liste_ip.append(choix_ip)
                    ruleset_user["add"]["rule"]["expr"][0]["match"]["right"] = set_ip(liste_ip)    
                except Exception as e:
                    print(f"❌ Exception: {e}")
                    break
                choix_protocole = input("quelle protocole : udp ou tcp : ")
                if choix_protocole == "udp" or choix_protocole == "tcp":
                    ruleset_user["add"]["rule"]["expr"][1]["match"]["left"]["payload"]["protocol"] = choix_protocole
                else:
                    break
                try :
                    choix_protocole = int(input("combien de ports/protocole ? : "))
                    liste_ports = []
                    for i in range(choix_protocole):
                        choix_port = int(input("donner les ports : "))
                        liste_ports.append(choix_port)
                    ruleset_user["add"]["rule"]["expr"][1]["match"]["right"] = set_port(liste_ports)
                    ruleset_base["nftables"].append(ruleset_user)
                except Exception as e:
                    print(f"❌ Exception: {e}")
                    break    
        elif choix_user == "forward":
            choix_input = int(input("[1] routage tcp/udp LAN, [2] routage ping, [3]  routage WAN : "))
            if choix_input == 1:
                print("routage LAN to LAN tcp et udp")
                ruleset_user = ruleset_forward_tcp_udp
                try:
                    choix_nb_ip = int(input("combien d'ip source : "))
                    liste_ip = []
                    for i in range(choix_nb_ip):
                        choix_ip = input("donnez l'ip ou le subnet source : ")
                        liste_ip.append(choix_ip)
                    ruleset_user["add"]["rule"]["expr"][0]["match"]["right"] = set_ip(liste_ip)    
                except Exception as e:
                    print(f"❌ Exception: {e}")
                    break
                try:
                    choix_nb_ip = int(input("combien d'ip destination : "))
                    liste_ip = []
                    for i in range(choix_nb_ip):
                        choix_ip = input("donnez l'ip ou le subnet destination : ")
                        liste_ip.append(choix_ip)
                    ruleset_user["add"]["rule"]["expr"][1]["match"]["right"] = set_ip(liste_ip)    
                except Exception as e:
                    print(f"❌ Exception: {e}")
                    break
                choix_protocole = input("quelle protocole : udp ou tcp : ")
                if choix_protocole == "udp" or choix_protocole == "tcp":
                    ruleset_user["add"]["rule"]["expr"][2]["match"]["left"]["payload"]["protocol"] = choix_protocole
                else:
                    break
                try :
                    choix_protocole = int(input("combien de ports/protocole ? : "))
                    liste_ports = []
                    for i in range(choix_protocole):
                        choix_port = int(input("donner les ports : "))
                        liste_ports.append(choix_port)
                    ruleset_user["add"]["rule"]["expr"][2]["match"]["right"] = set_port(liste_ports)
                    ruleset_base["nftables"].append(ruleset_user)
                except Exception as e:
                    print(f"❌ Exception: {e}")
                    break
            elif choix_input == 2 :
                print("routage LAN to LAN ping")                
                ruleset_user = ruleset_forward_ping
                try:
                    choix_nb_ip = int(input("combien d'ip source : "))
                    liste_ip = []
                    for i in range(choix_nb_ip):
                        choix_ip = input("donnez l'ip ou le subnet source : ")
                        liste_ip.append(choix_ip)
                    ruleset_user["add"]["rule"]["expr"][0]["match"]["right"] = set_ip(liste_ip)    
                except Exception as e:
                    print(f"❌ Exception: {e}")
                    break
                try:
                    choix_nb_ip = int(input("combien d'ip destination : "))
                    liste_ip = []
                    for i in range(choix_nb_ip):
                        choix_ip = input("donnez l'ip ou le subnet destination : ")
                        liste_ip.append(choix_ip)
                    ruleset_user["add"]["rule"]["expr"][1]["match"]["right"] = set_ip(liste_ip)
                    ruleset_base["nftables"].append(ruleset_user)    
                except Exception as e:
                    print(f"❌ Exception: {e}")
                    break
            elif choix_input == 3 :
                ruleset_user = ruleset_forward_wan
                print("routage acces WAN")                 
                try:
                    choix_nb_ip = int(input("combien d'ip source : "))
                    liste_ip = []
                    for i in range(choix_nb_ip):
                        choix_ip = input("donnez l'ip ou le subnet source : ")
                        liste_ip.append(choix_ip)
                    ruleset_user["add"]["rule"]["expr"][0]["match"]["right"] = set_ip(liste_ip)
                    ruleset_base["nftables"].append(ruleset_user)    
                except Exception as e:
                    print(f"❌ Exception: {e}")
                    break                    
        else:
            continuer = 0
    return ruleset_base                  




def manipuler_resultat():
    nft = Nftables()
    nft.set_json_output(True)
    
    cmd = {
        "nftables": [
            {"list": {"ruleset": None}}
        ]
    }
    json_cmd = json.loads(json.dumps(cmd))
    rc, output, error = nft.json_cmd(json_cmd)
    if rc == 0:
        #print("\n📋 Règles actuelles:")
        json_dmp = json.loads(json.dumps(output))
        return json_dmp
    else:
        print(f"❌ Erreur: {error}")
        sys.exit(1)     



        
def configure_nftable():  
    nft = Nftables()
    nft.set_json_output(True)
    try:

        # Convertir en JSON et appliquer
        ruleset_json = json.dumps(choix_nftables())
        ruleset_json = json.loads(ruleset_json)
        print(ruleset_json)
        rc, output, error = nft.json_cmd(ruleset_json)
        
        if rc != 0:
            print(f"❌ Erreur lors de l'application des règles: {error}")
            return False
        else:
            print("✅ Règles nftables appliquées avec succès!")
            print(f"📋 Sortie: {output}")
            return True
            
    except Exception as e:
        print(f"❌ Exception: {e}")
        return False


def separer_rule_list(json_dmp):
    liste_exploitable = json_dmp["nftables"]
    liste_finale = []
    def get_chain(element):
        return "chain" in element   
    chaines = list(filter(get_chain,liste_exploitable))
    def get_rule(element):
        return "rule" in element   
    rules = list(filter(get_rule,liste_exploitable))
    def get_table(element):
        return "table" in element
    tables = list(filter(get_table,liste_exploitable))
    def get_set(element):
        return "set" in element
    sets = list(filter(get_set,liste_exploitable))    
    liste_finale.append(tables)
    liste_finale.append(sets)
    liste_finale.append(chaines)
    liste_finale.append(rules)                            
    return liste_finale         


def afficher_rule(json_dmp):
    liste_rule = separer_rule_list(json_dmp)
    continuer = 1
    while continuer:
        choix = input("Que voulez-vous consulter : tout, set, table, chaine, rule ou quitter : ")
        if choix == "quitter":
            continuer = 0
            print("quitter l'affichage")
        elif choix == "table":
            print(json.dumps(liste_rule[0]))
        elif choix == "set":
            print(json.dumps(liste_rule[1]))
        elif choix == "chaine":
            print(json.dumps(liste_rule[2]))            
        elif choix == "rule":
            print(json.dumps(liste_rule[3]))
        elif choix == "tout":
            print(json.dumps(liste_rule))
        else:
            print("choix indefinie")
    return 0        

def avoir_rule(json_dmp,choix):
    sous_ensemble = {}
    liste_rule = separer_rule_list(json_dmp)
    if choix == "table":
        sous_ensemble = json.dumps(liste_rule[0])
    elif choix == "set":
        sous_ensemble = json.dumps(liste_rule[1])
    elif choix == "chaine":
        sous_ensemble = json.dumps(liste_rule[2])            
    elif choix == "rule":
        sous_ensemble = json.dumps(liste_rule[3])
    elif choix == "tout":
        sous_ensemble = json.dumps(liste_rule)
    return sous_ensemble




def list_rules():
    """Affiche les règles actuelles"""
    json_dmp = manipuler_resultat()
    afficher_rule(json_dmp)
    
        
def gere_blacklist():
    """Gerer la blacklist"""
    nft = Nftables()
    nft.set_json_output(True)    
    json_dmp = manipuler_resultat()
    sets = avoir_rule(json_dmp,"set")[0]

        

def flush_rules():
    """Supprime toutes les règles"""
    nft = Nftables()
    nft.set_json_output(True)
    
    cmd = {
        "nftables": [
            {"flush": {"ruleset": None}}
         ]   
    }
    json_flush = json.loads(json.dumps(cmd))
    rc, output, error = nft.json_cmd(json_flush)
    if rc == 0:
        print("🗑️  Toutes les règles ont été supprimées")
    else:
        print(f"❌ Erreur: {error}")

if __name__ == "__main__":
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "flush":
            flush_rules()
            sys.exit(0)
        elif sys.argv[1] == "list":
            list_rules()
            sys.exit(0)
        elif sys.argv[1] == "configure_rule":
            configure_nftable()
            sys.exit(0)
        elif sys.argv[1] == "init":
            init_nftables()
            sys.exit(0)            
        else:
            print("option : init, configure_rule, list ou flush")
    else:
        print("mettez un argumment : init, configure_rule, list ou flush")   

    # Appliquer les règles par défaut
    # Afficher le résultat
