How to use.

If you are only interested in running the topology visualisation, the output.json file is already provided for OT.pcap, so skip to step 7.

This will require bash terminal, python, and virtualenv to be installed (pip install virtualenv)

1. Open a bash terminal and change to the project directory

2. create the venv (python -m venv venv), press yes allowing it to be selected for the workplace folder 

3. activate virtual environment (source venv/Scripts/activate)

4. install scapy (pip install -r requirements.txt)

5. Choose which pcap you wish to read, OT.pcap is preset, if you wish to see OT2 replace line four with " packets = rdpcap('OT2.pcap') "

6. run pcap reader in terminal (python pcapReader.py)

7. Start up local host server in the terminal (py -m http.server), ensure you are still in the same file directory.

8. open a web browser and go to the visualisation address (http://localhost:8000/networkTopology.html)
