# 2025_01_01_HelloMegaMaskPushToIID

See: https://github.com/EloiStree/2025_01_01_HelloMegaMaskListenToIID.git
This code allows pushing an integer as an Ethereum private key or MetaMask key through a WebSocket.




```
sudo su root
```

```
git clone https://github.com/EloiStree/2025_01_01_HelloMetaMaskPushToIID.git /git/push_iid
cd /git/push_iid
```

Let's look at what module in python is missing
```
python RunServer.py
```
Module to install
```
pip install web3 eth-account base58 websockets requests tornado ntplib --break-system-packages
```

Change in the file what NTP server you want to use
ntp_server = "be.pool.ntp.org"  # for Belgium one
ntp_server = "127.0.0.1"   # for NTP on your current Raspberry Pi as for your home
ntp_server = "raspberrypi4.local"  # if you need an other rapsberr pi for that ^^





Generate and use a SHA256 if server auth is allows in this none cryptographic authentification.  
https://emn178.github.io/online-tools/sha256.html    
BonjourIID cdc166e605ed058f1cd21fc61aa8b098827cef38297ad4c042a224719a217294      
-42:cdc166e605ed058f1cd21fc61aa8b098827cef38297ad4c042a224719a217294    
SHA256:cdc166e605ed058f1cd21fc61aa8b098827cef38297ad4c042a224719a217294  


https://learnmeabitcoin.com/technical/keys/base58/


```
# https://github.com/EloiStree/2025_01_01_MegaMaskSignInHandshake_Python
# import iidwshandshake 

# 
# pip install web3 eth-account base58 websockets requests tornado ntplib --break-system-packages 

# git clone https://github.com/EloiStree/2025_01_01_HelloMegaMaskPushToIID.git /git/push_iid




# Debian: /lib/systemd/system/apintio_push_iid.service
# sudo nano /lib/systemd/system/apintio_push_iid.service
"""
[Unit]
Description=APIntIO Push IID Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /git/push_iid/RunServer.py
Restart=always
User=root
WorkingDirectory=/git/push_iid

[Install]
WantedBy=multi-user.target
"""
#1h
# sudo nano /etc/systemd/system/apintio_push_iid.timer
"""
[Unit]
Description=APIntIO Push IID Timer

[Timer]
OnBootSec=0min
OnUnitActiveSec=10s

[Install]
WantedBy=timers.target
"""

# cd /lib/systemd/system/
# sudo systemctl daemon-reload
# sudo systemctl enable apintio_push_iid.service
# chmod +x /git/push_iid/RunServer.py
# sudo systemctl enable apintio_push_iid.service
# sudo systemctl start apintio_push_iid.service
# sudo systemctl status apintio_push_iid.service
# sudo systemctl stop apintio_push_iid.service
# sudo systemctl restart apintio_push_iid.service
# sudo systemctl enable apintio_push_iid.timer
# sudo systemctl start apintio_push_iid.timer
# sudo systemctl status apintio_push_iid.timer
# sudo systemctl list-timers | grep apintio_push_iid


"""
sudo systemctl stop apintio_push_iid.service
sudo systemctl stop apintio_push_iid.timer
"""

"""
sudo systemctl restart apintio_push_iid.service
sudo systemctl restart apintio_push_iid.timer
"""


```


