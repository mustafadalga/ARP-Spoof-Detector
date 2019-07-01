```
           _____  _____     _____                    __   _____       _            _             
     /\   |  __ \|  __ \   / ____|                  / _| |  __ \     | |          | |            
    /  \  | |__) | |__) | | (___  _ __   ___   ___ | |_  | |  | | ___| |_ ___  ___| |_ ___  _ __ 
   / /\ \ |  _  /|  ___/   \___ \| '_ \ / _ \ / _ \|  _| | |  | |/ _ \ __/ _ \/ __| __/ _ \| '__|
  / ____ \| | \ \| |       ____) | |_) | (_) | (_) | |   | |__| |  __/ ||  __/ (__| || (_) | |   
 /_/    \_\_|  \_\_|      |_____/| .__/ \___/ \___/|_|   |_____/ \___|\__\___|\___|\__\___/|_|   
                                 | |                                                             
                                 |_|                                                             
```

## Açıklama
**Bilgisayarınıza yapılan ARP Spoofing saldırılarını tespit eden ARP Spoof Detector Scripti.**

<hr>

:arrow_right: ARP Spofing saldırısı tespit edildiğinde belirlediğiniz mail adresine uyarı bildirimi gönderilerek durumdan haberdar &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;olmanızı sağlar.

:arrow_right: Eğer uyari bildirimi Gmail SMTP  sunucusu kullanılarak yapılacaksa [Daha az güvenli uygulama erişimi](https://www.google.com/settings/security/lesssecureapps) açık olmalıdır.


<hr>

### Kurulum


* Windows için kurulum

```
python -m pip install scapy==2.4.0
```

<hr>

### Kullanım

ARP SPoof Detector'u test edebilmek için [buradaki](https://github.com/mustafadalga/ARP-poisoning-packet-sniffer) script ile ARP Spoof saldırısı yapabilirsiniz.

* Windows için kullanım

```
python ARPSpoofDetector.py
```

<hr>

### Notlar
* Python versiyonu:3.7.2
* Script sadece Windows işletim sisteminde test edilmiştir.
* Eğer ARP Spoofing işlemi Windows işletim sisteminden Linux işletim sistemine yapılacaksa , Windows işletim sisteminde ip forwarding ayarlarının konfigüre Edilmesi gerekmektedir.
