#!/usr/bin/env python 3.7.2
# -*- coding: utf-8 -*-

try:
    import scapy.all as scapy
except KeyboardInterrupt:
    print("[-] CTRL+C basıldı.")
    print("[-] Uygulamadan çıkış yapıldı.")
    exit()
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import datetime
import time


class Detector():
    def __init__(self, email, parola, to_email):
        self.about()
        self.email = email
        self.parola = parola
        self.to_email = to_email
        self.host = "smtp.gmail.com"
        self.port = 587

    def mac_bul(self, ip):
        arp_istek = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_istek_broadcast = broadcast / arp_istek
        cevap = scapy.srp(arp_istek_broadcast, timeout=1, verbose=False)[0]
        return cevap[0][1].hwsrc

    def sniff(self, interface=""):
        try:
            if interface == "":
                print("[-] Lütfen bir interface belirtiniz!")
            else:
                scapy.sniff(iface=interface, store=False, prn=self.sniffed_packet)
        except (OSError, ValueError):
            print("[-] Böyle bir interface bulunmamaktadır.")

    def sniffed_packet(self, paket):
        if paket.haslayer(scapy.ARP) and paket[scapy.ARP].op == 2:
            try:
                gercek_mac = self.mac_bul(paket[scapy.ARP].psrc)
                paket_mac = paket[scapy.ARP].hwsrc
                if paket_mac != gercek_mac:
                    print("[+] saldırı altındasınız!")
                    tarih = datetime.datetime.now()
                    if tarih.second == 00:
                        self.mailGonder(paket_mac, tarih)
                        time.sleep(1)
            except IndexError:
                pass

    def uyari(self, mac_adresi, tarih):
        mail = MIMEMultipart()
        tarih = tarih.strftime("%d-%m-%Y %H:%M:%S")
        mail["Subject"] = "Saldırı Altındasınız  ~ " + tarih
        mail["From"] = self.email
        mesaj = """
        <html>
        <head>
              <title>Bir Saldırı girişimi !!!</title>
        </head>
        <body>
              <h1 align="center">Bir Saldırı girişimi !!!</h1>
              <p style="font-size:16px;" ><b style="color:lime;background:black"> {mac} </b></h3>  mac  adresinden <b style="color:lime;background:black;"> {tarih} </b>  tarihinde bilgisayarınıza <span style="text-decoration: underline;">ARP Spoofing Saldırısı</span> gerçekleştirildi. </p>
              <br>
        </body >
        </html>
        """.format(mac=mac_adresi, tarih=tarih)
        part = MIMEText(mesaj, "html")
        mail.attach(part)
        return mail.as_string()

    def mailGonder(self, mac,tarih):
        try:
            self.server = smtplib.SMTP(self.host, self.port)
            self.server.ehlo()
            self.server.starttls()
            self.server.ehlo()
            self.server.login(self.email, self.parola)
            self.server.sendmail(self.email, self.to_email, self.uyari(mac,tarih))
            self.server.quit()
        except smtplib.SMTPException:
            print("[-] Sending Mail Hatası!")
        except smtplib.SMTPServerDisconnected:
            print("[-] SMTP Sunucusu Bağlantısı Kesildi!")
        except smtplib.SMTPConnectError:
            print("[-] SMTP Bağlantı Hatası!")


    def about(self):
        print("           _____  _____     _____                    __   _____       _            _             ")
        print("     /\   |  __ \|  __ \   / ____|                  / _| |  __ \     | |          | |            ")
        print("    /  \  | |__) | |__) | | (___  _ __   ___   ___ | |_  | |  | | ___| |_ ___  ___| |_ ___  _ __ ")
        print("   / /\ \ |  _  /|  ___/   \___ \| '_ \ / _ \ / _ \|  _| | |  | |/ _ \ __/ _ \/ __| __/ _ \| '__|")
        print("  / ____ \| | \ \| |       ____) | |_) | (_) | (_) | |   | |__| |  __/ ||  __/ (__| || (_) | |   ")
        print(" /_/    \_\_|  \_\_|      |_____/| .__/ \___/ \___/|_|   |_____/ \___|\__\___|\___|\__\___/|_|   ")
        print("                                 | |                                                             ")
        print("                                 |_|                                                             ")
        print("# ==============================================================================")
        print("# author         : Mustafa Dalga")
        print("# website        : https://apierson.com")
        print("# linkedin       : https://www.linkedin.com/in/mustafadalga")
        print("# github         : https://github.com/mustafadalga")
        print("# email          : mustafadalgaa < at > gmail[.]com")
        print("# description    : Bilgisayarınıza yapılan ARP Spoofing saldırılarını tespit eden ARP Spoof Detector Scripti.")
        print("# date           : 01.07.2019")
        print("# version        : 1.0")
        print("# python_version: 3.7.2")
        print("# ==============================================================================")


try:
    from_email=""
    from_parola=""
    to_email=""
    interface=""
    detector = Detector(from_email,from_parola,to_email)
    detector.sniff(interface)
except KeyboardInterrupt:
    print("[-] CTRL+C basıldı.")
    print("[-] Uygulamadan çıkış yapıldı.")
    exit()
