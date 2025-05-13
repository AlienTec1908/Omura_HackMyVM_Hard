# Omura - HackMyVM (Hard)

![Omura.png](Omura.png)

## Übersicht

*   **VM:** Omura
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Omura)
*   **Schwierigkeit:** Hard
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 11. April 2023
*   **Original-Writeup:** https://alientec1908.github.io/Omura_HackMyVM_Hard/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Omura" zu erlangen. Der Weg dorthin begann mit der Entdeckung einer Webanwendung, die XSLT-Transformationen durchführt. Durch eine Local File Inclusion (LFI)-Schwachstelle in der XSLT-Verarbeitung (`unparsed-text()`) konnte die WordPress-Konfigurationsdatei (`wp-config.php`) ausgelesen werden, was Datenbank-Credentials (`admin:dw42k25MiXT`) enthüllte. Nach dem Auffinden des WordPress-VHosts (`wordpress.omura.hmv`) und dem Login ins Admin-Backend wurde mittels Metasploit (`wp_admin_shell_upload`) eine Meterpreter-Shell als `www-data` erlangt. Die finale Rechteausweitung zu Root gelang durch das Auslesen von iSCSI-CHAP-Credentials (`root:gTQynqDRAyqvny7AbpeZ1Vi6e`) aus einer ungeschützten Konfigurationsdatei (`/etc/rtslib-fb-target/saveconfig.json`). Mit diesen Credentials konnte ein iSCSI-Target gemountet werden, das den privaten SSH-Schlüssel des Root-Benutzers enthielt.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `curl`
*   `gobuster`
*   `nikto`
*   `wfuzz`
*   `msfconsole` (Metasploit Framework, `wp_admin_shell_upload`)
*   `systemctl`
*   `iscsiadm`
*   `lsblk`
*   `mount` / `umount`
*   `rm`
*   Standard Linux-Befehle (`vi`, `cat`, `ls`, `cp`, `mkdir`, `chmod`, `ssh`, `id`, `man`, `nano`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Omura" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration (XSLT LFI):**
    *   IP-Adresse des Ziels (192.168.2.126) mit `arp-scan` identifiziert. Hostname `omura.hmv` in `/etc/hosts` eingetragen.
    *   `nmap`-Scan offenbarte Port 22 (SSH, OpenSSH 8.4p1), Port 80 (HTTP, Apache 2.4.54, Titel "XSLT Transformation") und Port 3260 (iSCSI, Synology DSM iSCSI, Authentifizierung erforderlich).
    *   Auf Port 80 wurde eine XSLT-Anwendung (Saxon-B) identifiziert (`index.php`, `process.php`).
    *   Eine Local File Inclusion (LFI)-Schwachstelle wurde in der XSLT-Verarbeitung von `process.php` gefunden. Mittels einer präparierten XSL-Datei (mit `unparsed-text('/var/www/wordpress/wp-config.php', 'utf-8')`) konnte der Inhalt von `wp-config.php` ausgelesen werden.
    *   `wp-config.php` enthielt Datenbank-Credentials: `admin`:`dw42k25MiXT`.

2.  **VHost & WordPress Enumeration & Initial Access (Metasploit als `www-data`):**
    *   Mittels `wfuzz` VHost-Fuzzing wurde die Subdomain `wordpress.omura.hmv` entdeckt und in `/etc/hosts` eingetragen.
    *   Login auf `http://wordpress.omura.hmv/wp-login.php` mit den Credentials `admin:dw42k25MiXT` war erfolgreich.
    *   Der Versuch, eine Webshell über den Theme-Editor manuell hochzuladen, scheiterte an fehlenden Schreibrechten.
    *   Mittels Metasploit (`exploit/unix/webapp/wp_admin_shell_upload`) und den Admin-Credentials wurde eine PHP-Meterpreter-Reverse-Shell als `www-data` auf dem Zielsystem etabliert.
    *   Die `www-data`-Shell wurde stabilisiert.

3.  **Privilege Escalation (von `www-data` zu `root` via iSCSI):**
    *   Als `www-data` wurde die Datei `/etc/rtslib-fb-target/saveconfig.json` gefunden und kopiert (aufgrund unsicherer Berechtigungen lesbar).
    *   `saveconfig.json` enthielt iSCSI-CHAP-Credentials: `chap_userid: "root"`, `chap_password: "gTQynqDRAyqvny7AbpeZ1Vi6e"` sowie den erlaubten Initiator-Namen `iqn.2023-02.omura.hmv:node01.initiator01`.
    *   Auf dem Angreifer-System wurde `open-iscsi` installiert. Der Initiator-Name wurde in `/etc/iscsi/initiatorname.iscsi` auf den erlaubten Namen gesetzt und die CHAP-Credentials in `/etc/iscsi/iscsid.conf` eingetragen. Der iSCSI-Dienst wurde neu gestartet.
    *   Mittels `iscsiadm -m discovery -t sendtargets -p omura.hmv` und `iscsiadm -m node --login` wurde eine Verbindung zum iSCSI-Target (`iqn.2023-02.omura.hmv:target01`) hergestellt.
    *   Das neue Blockgerät (z.B. `/dev/sdb`) wurde mit `lsblk` identifiziert und in ein lokales Verzeichnis (`~/disk`) gemountet.
    *   Auf dem gemounteten iSCSI-Laufwerk wurde eine Datei `id_rsa` gefunden – der private SSH-Schlüssel des Root-Benutzers.
    *   Der private Schlüssel wurde kopiert, die Berechtigungen gesetzt (`chmod 600`) und mit `ssh root@omura.hmv -i id_rsa` wurde erfolgreich Root-Zugriff erlangt.
    *   Die User-Flag (`cf7ddf6fa6393b8e7aef2396451fefdd`) in `/home/ford/user.txt` und die Root-Flag (`052cf26a6e7e33790391c0d869e2e40c`) in `/root/root.txt` wurden gefunden.

## Wichtige Schwachstellen und Konzepte

*   **XSLT Local File Inclusion (LFI):** Eine unsichere XSLT-Implementierung (Saxon-B) erlaubte das Auslesen beliebiger Dateien (hier `wp-config.php`) über die `unparsed-text()`-Funktion.
*   **Exponierte WordPress-Credentials:** Datenbank-Zugangsdaten wurden in `wp-config.php` gefunden und ermöglichten den Admin-Login.
*   **WordPress Admin Shell Upload:** Ausnutzung der Admin-Rechte, um über Metasploit eine Shell als `www-data` hochzuladen.
*   **Informationsleck (iSCSI CHAP Credentials):** CHAP-Benutzername und -Passwort für iSCSI waren im Klartext in einer lesbaren Konfigurationsdatei (`saveconfig.json`) gespeichert.
*   **Exponierter Root SSH-Schlüssel auf iSCSI-Laufwerk:** Der private SSH-Schlüssel des Root-Benutzers wurde auf einem iSCSI-Laufwerk gespeichert, das mit den geleakten CHAP-Credentials zugänglich war.
*   **VHost Enumeration:** Auffinden der `wordpress.omura.hmv`-Subdomain.

## Flags

*   **User Flag (`/home/ford/user.txt`):** `cf7ddf6fa6393b8e7aef2396451fefdd`
*   **Root Flag (`/root/root.txt`):** `052cf26a6e7e33790391c0d869e2e40c`

## Tags

`HackMyVM`, `Omura`, `Hard`, `XSLT LFI`, `WordPress Exploit`, `wp_admin_shell_upload`, `Metasploit`, `iSCSI`, `CHAP Credentials Leak`, `SSH Key Leak`, `Linux`, `Web`, `Privilege Escalation`, `Apache`
