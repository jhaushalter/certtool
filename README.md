# SSL Certtool

Servlet-Webanwendung zum Einlesen einer PKCS#12-Datei (`.pfx`/`.p12`) und zum Exportieren von Schlüssel und Zertifikaten. Fehlende Zwischen- und Stammzertifikate lassen sich über die AIA-Ausstellerangaben online suchen oder als PEM-, DER- beziehungsweise PKCS#7-X.509-Dateien manuell importieren. Der Export `pa-workspace.pem` enthält in IBM-Reihenfolge den privaten Schlüssel, das Serverzertifikat und die geordnete Zertifikatskette. Er wird erst freigegeben, wenn eine bis zu einem selbstsignierten Aussteller geprüfte Kette vorliegt. PEM-Blöcke werden direkt aus DER-Daten erzeugt; OpenSSL-`Bag Attributes` werden nicht übernommen.

Eine vorhandene `pa-workspace.pem` kann alternativ im Prüfmodus eingelesen werden. Das Tool prüft die Zuordnung des unverschlüsselten PKCS#8-Privatschlüssels zum Serverzertifikat, die Signaturen und Reihenfolge der enthaltenen Zertifikatskette sowie die aktuelle zeitliche Gültigkeit. Die geordnete Chain und Prüfergebnisse werden angezeigt; in diesem Modus wird der private Schlüssel nach dem Abgleich nicht in der Sitzung gespeichert und es stehen keine Exporte zur Verfügung.

Die Chain-Prüfung bestätigt die in der Datei enthaltenen Ausstellerbeziehungen und Signaturen, ersetzt jedoch keine vollständige PKIX-Pfadvalidierung und prüft nicht, ob das Root-Zertifikat im Zielsystem vertraut wird.

## WAR bauen

Voraussetzungen: JDK 8 oder neuer und Maven 3.6 oder neuer.

```text
mvn clean package
```

Das deploybare WAR liegt danach unter `target/Certtool.war`. Es verwendet die Servlet-3.1-API (`javax.servlet`) und ist für einen kompatiblen Servlet-Container, zum Beispiel Tomcat 8.5/9, vorgesehen. Die Servlet-API wird vom Container bereitgestellt.

## Betrieb und Schutz

- Die App verarbeitet PFX-Dateien bis 25 MiB. Ein falsches Passwort oder eine ungültige Datei wird als Importfehler angezeigt.
- Das eingegebene Passwort wird nicht gespeichert. Temporäre Multipart-Dateien werden nach dem Import gelöscht. Extrahierte PEM-Daten bleiben bis zu zehn Minuten nach der letzten Aktivität im Arbeitsspeicher der HTTP-Sitzung oder bis „Sitzung leeren“ verwendet wird.
- Der Container kann Sitzungen je nach Konfiguration persistieren. Für den produktiven Einsatz Sitzungspersistenz/Serialisierung deaktivieren, TLS verwenden und den Zugriff hinter einer Authentifizierung (z. B. Reverse-Proxy-Basic-Auth) beschränken. Keine öffentlichen Uploads zulassen.
- Die Online-Suche ruft nur AIA-CA-Issuers-URLs über HTTP/HTTPS auf, die auf öffentliche IP-Adressen aufgelöst werden. Weiterleitungen sind deaktiviert; Antwortgröße, Zeitlimits und Anzahl der Abrufe sind begrenzt.
- Das Ergänzen prüft Ausstellername, CA-Eigenschaft und Zertifikatssignatur. Es bestätigt nicht, dass die CA vom Zielsystem vertraut wird oder dass die Zertifikate aktuell gültig sind. Kontrollieren Sie die Zertifikatskette vor dem Einsatz in Planning Analytics Workspace.
- Die komplette CA-Kette muss in der PFX-Datei, in den Online-AIA-Antworten oder in den manuell importierten Zertifikaten verfügbar sein, damit der PAW-Export freigegeben wird. Der Schlüssel wird als PKCS#8-PEM (`BEGIN PRIVATE KEY`) ausgegeben.

IBM-Vorgabe: [TLS für Planning Analytics Workspace Local konfigurieren](https://www.ibm.com/docs/de/planning-analytics/2.0.0?topic=servers-configure-tls-planning-analytics-workspace-local).

## Cognos Analytics Importpaket

Bei einer vollständigen, geprüften RSA-Zertifikatskette stellt die Oberfläche optional ein ZIP für den IBM-`ThirdPartyCertificateTool` bereit. Dafür wird ein neues, mindestens zwölf Zeichen langes Passwort abgefragt, mit dem die erzeugte `encryptCertificate.pfx` geschützt wird. Das Passwort wird weder gespeichert noch in das ZIP aufgenommen.

Das Paket enthält die PFX mit Server-Schlüssel und vollständiger Kette, die CA-Dateien `ca.cer` (Root) und `ica-NN.cer` (Zwischenzertifikate) als DER sowie Windows-/Linux-Befehlsvorlagen und eine Anleitung. In den Befehlen müssen das Cognos-Keystore-Passwort und das PFX-Passwort lokal eingesetzt werden. Die Passwörter werden absichtlich nicht in eine Befehlsdatei geschrieben.

Das ist eine Vorbereitung, kein Cognos-Keystore-Generator: Das Paket erstellt und verändert keinen Cognos-`CAMKeystore`. Stoppen Sie die betroffenen Cognos-Komponenten und führen Sie die IBM-Befehle mit dem zur installierten Cognos-Version gehörenden `ThirdPartyCertificateTool` auf jedem betroffenen Cognos-Rechner aus. Sichern Sie den vorhandenen Keystore und folgen Sie vor dem Import der IBM-Anforderung eines leeren Keystores. IBM übergibt das PFX-Passwort laut dokumentiertem Befehl als Prozessargument; dieses kann dadurch in Shell-History oder Prozesslisten sichtbar sein. Verwenden Sie die Vorlagen daher nur in einer geschützten Administrationsumgebung und beachten Sie die Cognos-/IBM-Betriebsrichtlinien.

Die Paketoption ist auf vollständige RSA-Ketten beschränkt, da der dokumentierte Cognos-Aufruf `-a RSA` verwendet. Prüfen Sie die IBM-Anweisungen für Ihre genaue Cognos-Version vor dem Import:
[CA-Zertifikate importieren](https://www.ibm.com/docs/en/cognos-analytics/12.1.x?topic=certificate-import-existing-authority-ca-certificates).
