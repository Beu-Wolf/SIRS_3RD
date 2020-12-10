# SIRS_RRRD
SIRS course project 2020-2021

## Run locally (clients, server and backup in same machine)

### Pre-requisites:
 - Linux (Ubuntu 20.04, openSuse)
 - Java 11
 - Maven
 - Keytool

### Build:
```
./genca.sh
./genclient.sh keys
mvn compile
```
<b>NOTE</b>: If you want to simulate more than one client, run `./genclient.sh <keysRootFolder>` as many times as clients you want, and specifying different `<keysRootFolder>`s.

### Exec:
#### Server:
  - Make sure there is a `files` folder inside the main folder
  - run `mvn exec:java`
  
#### Backup:
  - Make sure there is a `files` folder inside the main folder
  - run `mvn exec:java`
  
#### Client:
   <!-- - Make sure there is a `files` folder inside the main folder and a `sharedFiles` folder inside the `files` folder -->
  - For each client, make sure there exists a `<fileRootFolder>` and a `<keysRootFolder>` inside the main folder. Also `<fileRootFolder>` must have a `sharedFiles` folder inside it
  - run `mvn exec:java -Dexec.args="-f <fileRootFolder> -k <keysRootFolder>"` 
  
## Run in VMs (each client, server and backup in different VMs)

### Pre-requisites:
One machine per node with
 - Ubuntu 18.04 64 bit
 - Java 11
 - Maven
 - Keytool

### Connections
 - Make sure the VMs have a NAT adapter to connect to general internet
 - One other adapter for an internal network (`sw-1` for example)
 - setup IP of each node, all must be in network `192.168.0.0/24`
      - Server must have IP `192.168.0.100`
      - Backup must have IP `192.168.0.200`
 

### Build: <!-- maybe discriminate by node-->
```
mvn compile
```

### Exec:
#### Server:
  - run `mvn exec:java`
  
#### Backup:
  - run `mvn exec:java`
  
#### Client:
  - run `mvn exec:java` 
