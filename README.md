# SIRS_RRRD
SIRS course project 2020-2021

### Build (if locally):
```
./genca.sh
./genclient.sh keys
mvn compile
```
<b>NOTE</b>: If you want to simulate more than one client, run `./genclient.sh <keysRootFolder>` as many times as clients you want, and specifying different `<keysRootFolder>`s.

### Build (if in VMs):
```
mvn compile
```

### Exec (if locally):
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
  
### Exec (if in VMs):
#### Server:
  - run `mvn exec:java`
  
#### Backup:
  - run `mvn exec:java`
  
#### Client:
  - run `mvn exec:java` 
