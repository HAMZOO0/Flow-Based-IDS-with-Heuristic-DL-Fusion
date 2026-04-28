### to find adopter id 
``` tshark -D  ```

### output 
`
Internet + OS services + VMs + VPN + internal apps (there are lots of connection but we choose  wifi2 )
` 

### what to improve 
add some time stamp dl model with uniqe ports as well  . and also need a real time scanning pipling which can handle flow of one ip but store the data ... but it is ok like now it is working on same concept like storeing src ports data flow count as well , 
but i want to create in which : 
scanner can store all the data , like ack , syn etc , of each flow - ip to ip communicaiton 
on this bases we can detect the real attack  . 

---

##  MLP IDS Architecture (Layer Breakdown)

| Stage | Layer Type | Size / Units | Description |
|------|------------|-------------|-------------|
| Input (Not a layer) | Input | input_dim | Your raw network flow features (NFStreamer data) |
| Layer 1 | Linear | 128 | Scans raw data for basic patterns in traffic |
| Activation 1 | ReLU | - | Adds non-linearity to learn complex relationships |
| Dropout 1 | Dropout | 0.2 | Prevents overfitting by randomly disabling neurons |
| Layer 2 | Linear | 64 | Combines basic patterns into more complex representations |
| Activation 2 | ReLU | - | Adds non-linearity again for deeper learning |
| Dropout 2 | Dropout | 0.2 | Further regularization to improve generalization |
| Layer 3 (Output) | Linear | num_classes | Produces final prediction (e.g., Attack vs Normal or multi-class labels) |

---

### HEURISTIC ENGINE 
pkts : number of packts 
syn : number of sync packs
fin : fin packs 
rst : end conneciton 
psh : send data 
fwd : src to dest 
bwd : dest to src 
dst _port : which port is using by which ip 

port_tracker : dst ort of src ip 
flow cont : number of flows from each ip  (flow means the full connection and communication of ip to ip or we say connection )


is_broadcast : avoid this broadcast ips , 192 :) 

---

### udp port scan 
check the protocol , check the fwd and back_pkts  is this lesss or not , in scan it migt be less number and but number of ports are high 

### Syn 


### sA - traget send te ack flag 
**ACK Scan — Connection Diagrams**

---

**Normal Traffic (no scan, legitimate ACK)**
```
Client          Server
  |                |
  |─── SYN ───────►|
  |◄── SYN+ACK ───|
  |─── ACK ───────►|   ← ACK appears INSIDE an established connection
  |   (data flows) |
```
ACK only appears **after** SYN and SYN+ACK. That's normal.

---

**ACK Scan — No Firewall — Port UNFILTERED**
```
Attacker        Target
  |                |
  |─── ACK ───────►|   ← out of nowhere! no SYN before this
  |                |
  |         Target thinks:
  |         "I have no record of this connection"
  |         "This ACK belongs to nothing"
  |                |
  |◄── RST ───────|   ← "I don't know you, get out"
  |                |

Attacker learns:  PORT IS UNFILTERED 
(packet reached the target, firewall didn't block it)
```

---

**ACK Scan — With Firewall — Port FILTERED**
```
Attacker        Firewall          Target
  |                |                |
  |─── ACK ───────►|                |
  |                |                |
  |           Firewall thinks:      |
  |           "No SYN was seen"     |
  |           "This ACK is          |
  |            suspicious"          |
  |           *DROP*                |
  |                |                |
  |   (silence)    |         Target never
  |   (timeout)    |         sees the packet
  |                |                |

Attacker learns:  PORT IS FILTERED 
(no response = firewall is blocking)
```

---

**ACK Scan — Stateless/Old Firewall — Firewall FOOLED**
```
Attacker        Firewall          Target
  |                |                |
  |─── ACK ───────►|                |
  |                |                |
  |           Old firewall thinks:  |
  |           "ACK = existing       |
  |            session, allow it"   |
  |           *ALLOW*               |
  |                |                |
  |────────── ACK ─────────────────►|
  |                |                |
  |                |         Target thinks:
  |                |         "No record of this"
  |                |                |
  |◄────────── RST ────────────────|
  |                |                |

Attacker learns:  PORT UNFILTERED + FIREWALL IS STATELESS 
(huge info — firewall can be bypassed)
```


----

### HTTP flood - > dos 
Attacker        Server
  |─── SYN ───────►|
  |◄── SYN+ACK ───|
  |─── ACK ───────►|   (legit connection)
  |─── GET / ─────►|
  |─── GET / ─────►|   (thousands of these)
  |─── GET / ─────►|
  |─── GET / ─────►|
  |                |
         Server CPU/RAM exhausted
         Legitimate users can't get in


---

#  7. DL CLASSIFY  (from Code 3)
# ═══════════════════════════════════════════════════════════════

# features dict
#      ↓
# numpy array (1 × N_FEATURES)
#      ↓
# clean NaN/inf → 0
#      ↓
# scale to same range
#      ↓
# pytorch tensor → GPU/CPU
#      ↓
# neural network → raw logits
#      ↓
# softmax → probabilities
#      ↓
# argmax → winning class index
#      ↓
# label decoder → "Port Scanning"
#      ↓
# return ("Port Scanning", 0.9312)

---


