# cli_nftable
Une petite app pour interragir avec libnftable-json pour créer des règles nftables afin de créer un petit par-feu en parantant d'une vm Debia classique


Linux permet de router des paquest via

`/etc/sysctl.conf`

Cette option

```
net.ipv4.ip_forward=1
```

## Libnftable-json

En python, on peut interagir avec nftable via la paquet python-nftable, qui permet d'interragir avec netfilter, et d'ainsi définir des régles sur la chaine INPUT (ie les paquets destinés au routeur), FORWARD (les paquets transitant par le routeur) etc...

## Choix 

Pour le NAT pour accéder à Internet, j'ai fait le choix arbitraire de l'interface enp0s1 car le lab tournait sur https://cockpit-project.org/ via le plugin cockpit-VM qui permet de gérer des VMs via KVM
la règle est défiinie ainsi via l'option masquerade


```
{ "add": { "chain": { "family": "inet", "table": "firewall", "name": "nat", "type":"nat","hook":"postrouting","prio":0,"policy":"accept"} } },
{ "add": { "rule": { "family": "inet", "table": "firewall", "chain": "nat",
                         "expr": [ { "match": { "op": "==", "left": { "meta": { "key": "oifname"} }, "right": "enp0s1" } },
                                   { "masquerade": null } ] } } },
```


Pour la blacklist, j'ai créer un ensemble `@blacklist` avec une règle qui vérifie l'appartenance des IPs et drop le trafique en PREROUTING 



## Chaine nftable

### Routage est accès au routeur
Voici les définitions JSON qui permettent d’interagir avec libnftable-json pour rajouter des règles INPUT, FORWARD et d'accès au NAT 

```python3
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
```

### Liste des régles, applications et flush

La suppression de règles se fait via cette instruction

```
    cmd = {
        "nftables": [
            {"flush": {"ruleset": None}}
         ]   
    }
```

La liste se fait via

```
    cmd = {
        "nftables": [
            {"list": {"ruleset": None}}
        ]
    }
```

et l’application se fait via cette instruction, on traduit le dictionnaire en JSON et on utilise la methode `json_cmd` du paquet Nftables


```
    json_cmd = json.loads(json.dumps(cmd))
    rc, output, error = nft.json_cmd(json_cmd)
    if rc == 0:
        #print("\n📋 Règles actuelles:")
        json_dmp = json.loads(json.dumps(output))
        return json_dmp
    else:
        print(f"❌ Erreur: {error}")
        sys.exit(1)  

```

## Utilisation

Le programme permet d'ajouter des règles en INPUT, de routage, des IPs à la blacklist et d'accès à Internet via un NAT

