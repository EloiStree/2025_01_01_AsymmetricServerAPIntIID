
------------------------

⚠️ The code is compatible with MetaMask and Ethereum, but it also works without them! 😅 ⚠️

(I’ll be creating a Visual Studio tool to generate keys offline for those who prefer to avoid MetaMask and Ethereum. I'm simply using asymmetric key authentication—RSA for Unity3D and ECC for the web. 🤗🧙‍♂️)

---------------
# Client example

- **Setup for Unity3D and Pi**: https://github.com/EloiStree/2025_03_11_NtpWsClientIntegerLobbySetup
- **Unity3D Client**: https://github.com/EloiStree/OpenUPM_WsMetaMaskAuth  
- **Rasbperry Pi Pico Client:** https://github.com/EloiStree/2025_03_13_PicoInputNtpWsClientIID  
- **Python / Javascript Client:** https://github.com/EloiStree/2025_03_14_WsNtpIntRaspberryPiClientPyJS
- **Stream Deck Client:** https://github.com/EloiStree/2025_03_15_WsNtpIntStreamDeckClient

------------

# 2025_01_01_HelloMegaMaskPushToIID

See: https://github.com/EloiStree/2025_01_01_HelloMegaMaskListenToIID.git
This code allows pushing an integer as an **compatible** Ethereum private key or MetaMask key through a WebSocket.


If you want to use the project offline, the first thing to do is to step the PI to be a NTP server.
[https://github.com/EloiStree/2025_01_01_HelloPiOsNtpServer](https://github.com/EloiStree/2025_01_01_HelloPiOsNtpServer)  

Let's change session to the admin
```
sudo su root
```


Update our PI
```
sudo apt update && sudo apt upgrade -y
```

Open the port 4615 for the incoming app.
And to do that you need ufw to be install.
```
sudo apt install ufw -y
sudo ufw allow 4615
```

Let's copy the project on the PI:
```
rm /git/push_iid -r
mkdir /git/push_iid 
git clone https://github.com/EloiStree/2025_01_01_HelloMetaMaskPushToIID.git /git/push_iid
cd /git/push_iid
```



Let's install the python module needed:
```
pip install web3 eth-account base58 websockets requests tornado ntplib --break-system-packages
```
- Web3 to use crypthogarphy and ethereum
- eth-account to authentify with ethereum
- base58 to be able to uncompress text fiting url
- websockets to have the tool in aim to build the server
- tornado to because it is the best tool for websocket server I found yet
- requests to make so download form there to there
- ntplib to syncrhonise the clock on a network time protocole
- `--break-system-packages` Because we are on Raspberry Pi OS
  -... don't know what I am doing.


Let's look at what module in python is missing that I did not add to this documentation:
```
python RunServer.py
```

You can edit the file and replace `ntp_server`
```
nano /git/push_iid/RunServer.py
```

Replace by what you need:
```
ntp_server="be.pool.ntp.org" # If you want to have the Belgium time
ntp_server="127.0.0.1" # If you want the NTP Server on the PI that you installed
```

**Background Servrice**:
Now that the server is present, you need to be sure it launch at start and auto-restart if it catch an error or an exception.

Go to the system service folder aand create a service:
```
cd /lib/systemd/system/
sudo nano /lib/systemd/system/apintio_push_iid.service
```

In the service file copy the following:
```
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
```

A service is good but you need to check it is running all the time.
```
sudo nano /etc/systemd/system/apintio_push_iid.timer
```

You can copy the following that wil check every 10 seconds if the service is running
```
[Unit]
Description=APIntIO Push IID Timer

[Timer]
OnBootSec=0min
OnUnitActiveSec=10s

[Install]
WantedBy=timers.target
```


Now that the service is running, you need to reload the system file:

```
cd /lib/systemd/system/
sudo systemctl daemon-reload
```

Let's enable the service and add permission
```
sudo systemctl enable apintio_push_iid.service
chmod +x /git/push_iid/RunServer.py
sudo systemctl restart apintio_push_iid.service
sudo systemctl status apintio_push_iid.service
```

Same for the timer:
```
sudo systemctl enable apintio_push_iid.timer
sudo systemctl start apintio_push_iid.timer
sudo systemctl status apintio_push_iid.timer
sudo systemctl list-timers | grep apintio_push_iid
```

If you need to stop them to code a new version:
```
sudo systemctl stop apintio_push_iid.service
sudo systemctl stop apintio_push_iid.timer
```

When you want to reenable them:
```
sudo systemctl restart apintio_push_iid.service
sudo systemctl restart apintio_push_iid.timer
```

As you run earlier the code it produced 4 white listes files in a gitignored fileder.
- `Auth/SHA256`
- `Auth/ETH`
- `Auth/pBit4096B58Pkcs1SHA256`

Let's try to white list in the fours currently allowed system.


For the SHA256 you can go on this website:
https://emn178.github.io/online-tools/sha256.html

Let's try to create a "HelloWorld" password.
It give you a random number: `872e4e50ce9990d8b041330c47c9ddd11bec6b503ae9386a99da8584e9bb12c4`

Go in the `Auth/SHA256.txt` and add the user with a integer to identify him:
`-4656:872e4e50ce9990d8b041330c47c9ddd11bec6b503ae9386a99da8584e9bb12c4`
Now if someone connect with this password he won't be kicked of the server and will be authentify as the user `-4656`

See an other tutorial on how to connect to the server with SHA256: (todo)


The other best way and initial way of the project is to use MetaMask when outside of Unity3D:
Create a MetaMask Account and copy the public adress: `0x8Fd7205237FdF4158b114a95A776ED2153CB36A3`
![image](https://github.com/user-attachments/assets/0ce1cb26-4468-4549-b109-58c18b18de3d)

Go in the `Auth/ETH.txt` and add him to the file like for the SHA256:
"525:0x8Fd7205237FdF4158b114a95A776ED2153CB36A3`
I did give him a positive nuumber as an ethereum account is proably an active user of the server.


If the user is playing from Unity3D, we need to use a RSA cryptography.
But it is compose of `<!\` char that URL don't like and so we need a base58 format.
So I created this storing format:    
- https://github.com/EloiStree?tab=repositories&q=pBit4096B58Pkcs1SHA256  

You can generate in Unity3D the key:
![image](https://github.com/user-attachments/assets/9bb2020f-e4e6-4a71-ace8-0101dba1422f)

 It looks like this in **RSA format**:
RSA Key format: 
```
<RSAKeyValue><Modulus>uFn8AZ5tGhACDx5FIcr5YJh0vIElKJvKV32EwL7vlp3tuHBkYfcCFRRSVYSmVQOW6o8r3aO0cB/36+Y6NBKiaL92W92unbt7u9Gyddfwb2wnjzqwjvYHqkOSKU8nHeHq6Lik1mctUGy6td7fy/gu47oEByy2g7oag/zg6CbsN1s=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>
```

RSA Key format:
```
<RSAKeyValue><Modulus>uFn8AZ5tGhACDx5FIcr5YJh0vIElKJvKV32EwL7vlp3tuHBkYfcCFRRSVYSmVQOW6o8r3aO0cB/36+Y6NBKiaL92W92unbt7u9Gyddfwb2wnjzqwjvYHqkOSKU8nHeHq6Lik1mctUGy6td7fy/gu47oEByy2g7oag/zg6CbsN1s=</Modulus><Exponent>AQAB</Exponent><P>xk34qOlkPUgvEle8E3PilYZHSSMKUAfMSHVam9kYVtdV/E3mb8hiDXsIePD/kz/PZ/dw/hq+zXc7o4eZ9cxITw==</P><Q>7fzESUowyHwuJ+X5x79NAh+ey3SHFUduKw8f4kEp3v7Dgs6BpypzP6ha2SFPDZR64nsIt/7MOOQitiu/1uwRNQ==</Q><DP>o3fS6yq5vuqqIuy/1SlKNwgh62A/OAm1lGVo89/Z+Hw6HWn581uzuHkbWtcPV0raplGLi2xwrN8FAqDdgYmMcQ==</DP><DQ>TWbvZDLYCOyyilF22qtyXWVxXRSqNpaD00dZBFpTRu6vIeUOMBNTZnnYClSWBIGtMen4HPem7j3suDkkbL9cnQ==</DQ><InverseQ>Pikof1cQbTnwZcKJHmOaZPiBeIrZ7FSl7m1eKdxcgr7CoO0Sd1VI3uhF8VLRw+lRgtzFo71xWN7TiB5gJP6ZYw==</InverseQ><D>UcN/VQx6IUQWVbQ8PzeyEVis9eplm7Q1M0a1eXN1+hyDkfkvXI/ceZLwzYMu7qfP6KqlbwErh0t2f0c2a2AUbZVzvGF+yScndCnCm2AyY7wR4f7GuLfWRalGWFHZ3RhehmZjD2I//dnOGMvgXAZBZaopKVABYQD/92Z/TxLMzEk=</D></RSAKeyValue>
```

That is the clipboard pastable url version of it, **pBit4096B58Pkcs1SHA256**.
When turn in a pastable url public key format:
```
pBit4096B58Pkcs1SHA2568arQkFZ8ZJYKVVkCiefn9ckvmUDmF9Qh2QwrDrX63KXs1eUmvAgai9phsXRUzanKkD5qQz8rwc2MQgZh91BTmzSmfdTS3uBxWHTkUkUVvfHWwBVnHUaocqwHW8RJgit845Qus5AWUJn9GRECfapNWp5AGz62iWoimGbWQx45vZkgtswRYuQSXGjh2tL1dLEjUPCNoCPdkY2Q5tJh3m7DyCB1MdFVdtXwRVbKwxkudaVwcuzDimJJgWzzhADT8V9L6Z1M6A1sxtcokk3jpdfKHYaoeYKGQL6sHnHrTDz2XWVPnsLK7PickurddzjC2kL2TBpCkdcdY9fB
```

When turn in a pastable url private key format:
```
PBit4096B58Pkcs1SHA2563TT9g43oGiJ1Hz7LN9zMaTHk2eKbGXYeKvgzCWQpGTaJfthb3P6dtva5EXWqnWGFg4x4JpWy1NM6JqzHG1WdQyrcUThuNFesheDVnhDNXTFUm4qkXqDLvL43png9yn1RQi91pbXzvM66zwaBRuYwj4QA9A16x9oy7d3dL1hrqLvqN3UxGBLUKj2NrKfz5kwZD6DFa2m9a21jjk1QsFsKaWdHNM9VsmtCB6Mw4VxotmHiiamT5dPNdFB6KNNAU8iYS9h5M3LY5SpB3eKwveFeGixjR8Fd3J2Y44hqfLbGnLSwuprQCcf2hiDPi8XtNqbcEK4Swd7AZGJwLsR9ofWZiKfejP5Dngejcq3XCqFYRRq6rhcp3iUm4Rd9qBMJE4X9WCAzaoWit6EDVwrUYvP5ndMywLiq7A5tVwmc7EP9H9cXbRX3m1JZcm9mgszNd1AwgL1SffBXkHHhsWAZEHstGec8oemk7Zh1FfwkEhRoGrkTNufKmLhGa1XzcziK6WjKdViKEe8n2oyvfCk4PSZnAGdX3Leh1W2gN7fUzmbZ1pH7PKEja3EY3RgwBxSoKCKdexa9Rj8K58EKn9fVZMynHqCJMQmkKbV6icfFMhLv9PpbsUMUJSrENqK9TKF59rv1eXkun6G1bmA9rQAZkjWaFWorxwcfQkQ6FHLpXtnZmEiWHf3vBfj94Kb9LgTiEP5ifCZnPZuSWSMu8Ubq42EYrFmu4E5Gc5JogyXa3o3w41nEUW3gaCY3RqpE7As8ZN1jgVKw8hyZoP2y8V6gFfoGFxrdRsFA8rd71FbrgZX24P31j13jdJBFG95G6Ui7ZapGLR62tF5QcnkM2Furq5tz8AC1jtL4URWzzReqyEYreCSWTzJCZGcxUro38pNeXemii9n9enWnzVfUwiqdJXGcWdGvgU65zVh3KjouTbvcE4EN5PkdXEtxhsvCNTad26kWbvXJLYyY1reeRLJqeMskbbNTwwQ27njKzJXvvunts1tHXs4VjP2C6vq3WFL2WeBEBNcVwR9MepWeLuDfkWNHdR1F14hnKumcPspyuPMB6LiZeRaLNs4QJUXoZyqokgRiQTtRwT9KnJzBCabUuqfkBc77qF6W8FUo7VwFaibSjSveGizhULqYMCymjCuM7VkZUaJDKK7QwzDGqXBhXC1F8Ue9m6hoRDgcaBu7rM7sFwxJUT51i4K53QGPJGSe3FE6Hwr3pu3DqvE6anrTMTH8yett94DoGzrXc1
```

I will make a javascript static page later for all that  (^^' )

Take the public key and add it to the `Auth/pBit4096B58Pkcs1SHA256.txt`:
```
451:pBit4096B58Pkcs1SHA2568arQkFZ8ZJYKVVkCiefn9ckvmUDmF9Qh2QwrDrX63KXs1eUmvAgai9phsXRUzanKkD5qQz8rwc2MQgZh91BTmzSmfdTS3uBxWHTkUkUVvfHWwBVnHUaocqwHW8RJgit845Qus5AWUJn9GRECfapNWp5AGz62iWoimGbWQx45vZkgtswRYuQSXGjh2tL1dLEjUPCNoCPdkY2Q5tJh3m7DyCB1MdFVdtXwRVbKwxkudaVwcuzDimJJgWzzhADT8V9L6Z1M6A1sxtcokk3jpdfKHYaoeYKGQL6sHnHrTDz2XWVPnsLK7PickurddzjC2kL2TBpCkdcdY9fB
```


If you want to make a eSport game you need to be able to send the reward to the winner in your Unity3D game.
That why I created the "Mark letter" idea:
![image](https://github.com/user-attachments/assets/98e8c88e-f1d0-45f7-84f2-1b3ba19f20fa)
![image](https://github.com/user-attachments/assets/9bd2b000-5dbd-4d73-a0a2-98ea3e160602)

It is producing this pastable text:
```
pBit4096B58Pkcs1SHA2568arQkFZ8ZJYKVVkCiefn9ckvmUDmF9Qh2QwrDrX63KXs1eUmvAgai9phsXRUzanKkD5qQz8rwc2MQgZh91BTmzSmfdTS3uBxWHTkUkUVvfHWwBVnHUaocqwHW8RJgit845Qus5AWUJn9GRECfapNWp5AGz62iWoimGbWQx45vZkgtswRYuQSXGjh2tL1dLEjUPCNoCPdkY2Q5tJh3m7DyCB1MdFVdtXwRVbKwxkudaVwcuzDimJJgWzzhADT8V9L6Z1M6A1sxtcokk3jpdfKHYaoeYKGQL6sHnHrTDz2XWVPnsLK7PickurddzjC2kL2TBpCkdcdY9fB|0x8Fd7205237FdF4158b114a95A776ED2153CB36A3|0x95c5b4931fa187d55e58692f96329395001c64a218ec37650bb2b5d7f089817119a8c61715c364d0689213ffb26bb32d140283317990c3edc0c82ec3eb0c399d1b
```

It provide a RSA public key a message signed by an ethereum metamask account. Meaning that at one point in time this RSA key was authorized by the user to be used in his name.




You will received a GUID to sign when connecting to the server.
**You have four ways to authentify in the server from a white list:**
- Add a public ethereum identification
- Add a password in SHA256 format
- Add a pBit4096B58Pkcs1SHA256 RSA public key that I created for the server

The fours way is to add a public ethereum identification and signe a RSA (pBit4096B58Pkcs1SHA256) key in Unity3D to do actoin in the name of the ethereum account.

Why all those authentification.

RSA is old tech but the only multiplatorme cryptographt usable in Unity3D without complexity
Ethereum is the one I want to use in aim to make esport and tournament possible in my games
So to allows ranked player you can create a "mark letter" to allows a RSA key to play in the game of your eth account.
But most people don't care of security and crytogrpahy.
So I added a good old password system in it with a SHA256 to authentify.
The SHA256 is highly hackable but when you use it, it is more for the sake of prototyping and make quick invite.

Note: in the convention of my tool, -Number is a Guest and +Number is a registered user.
If you want to diable guest, just tweak a boolean variable.



**Ok, we succeed to setup the server and the whiteliste.**
Let's try to connect to it from a python script.






