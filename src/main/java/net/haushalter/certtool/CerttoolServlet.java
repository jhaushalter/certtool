package net.haushalter.certtool;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyFactory;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionBindingEvent;
import javax.servlet.http.HttpSessionBindingListener;
import javax.servlet.http.Part;

@MultipartConfig(
        fileSizeThreshold = 1024 * 1024,
        maxFileSize = 25L * 1024 * 1024,
        maxRequestSize = 25L * 1024 * 1024 + 64 * 1024)
public final class CerttoolServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final String MATERIAL_ATTRIBUTE = CerttoolServlet.class.getName() + ".material";
    private static final String CSRF_ATTRIBUTE = CerttoolServlet.class.getName() + ".csrf";
    private static final int SESSION_TIMEOUT_SECONDS = 10 * 60;
    private static final int MAX_CHAIN_CERTIFICATES = 12;
    private static final int MAX_AIA_DOWNLOADS = 4;
    private static final int MAX_AIA_RESPONSE_BYTES = 1024 * 1024;
    private static final int MAX_MANUAL_CERTIFICATE_BYTES = 5 * 1024 * 1024;
    private static final String AUTHORITY_INFO_ACCESS_OID = "1.3.6.1.5.5.7.1.1";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        setSecurityHeaders(response);
        String path = request.getPathInfo();
        if ("/status".equals(path)) {
            writeStatus(request, response);
        } else if ("/download".equals(path)) {
            download(request, response);
        } else {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        setSecurityHeaders(response);
        String path = request.getPathInfo();
        if (!"/import".equals(path) && !"/clear".equals(path)
                && !"/complete-chain".equals(path) && !"/import-chain".equals(path)
                && !"/cognos-bundle".equals(path) && !"/import-pem".equals(path)) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        HttpSession session = request.getSession(false);
        String expectedToken = session == null ? null : (String) session.getAttribute(CSRF_ATTRIBUTE);
        String suppliedToken = request.getHeader("X-CSRF-Token");
        if (expectedToken == null || !expectedToken.equals(suppliedToken)) {
            writeJson(response, HttpServletResponse.SC_FORBIDDEN,
                    "{\"error\":\"Sitzung abgelaufen. Bitte laden Sie die Seite neu.\"}");
            return;
        }

        if ("/clear".equals(path)) {
            session.invalidate();
            writeJson(response, HttpServletResponse.SC_OK, "{\"ok\":true}");
            return;
        }
        if ("/complete-chain".equals(path)) {
            completeChain(request, response, session);
            return;
        }
        if ("/import-chain".equals(path)) {
            importChain(request, response, session);
            return;
        }
        if ("/cognos-bundle".equals(path)) {
            downloadCognosBundle(request, response, session);
            return;
        }
        if ("/import-pem".equals(path)) {
            importWorkspacePem(request, response, session);
            return;
        }
        importPfx(request, response, session);
    }

    private void writeStatus(HttpServletRequest request, HttpServletResponse response) throws IOException {
        HttpSession session = request.getSession(true);
        session.setMaxInactiveInterval(SESSION_TIMEOUT_SECONDS);
        String token = (String) session.getAttribute(CSRF_ATTRIBUTE);
        if (token == null) {
            token = java.util.UUID.randomUUID().toString();
            session.setAttribute(CSRF_ATTRIBUTE, token);
        }

        CertificateMaterial material = (CertificateMaterial) session.getAttribute(MATERIAL_ATTRIBUTE);
        StringBuilder json = new StringBuilder("{\"loaded\":")
                .append(material != null)
                .append(",\"csrfToken\":\"").append(jsonEscape(token)).append('\"');
        if (material != null) {
            json.append(",\"subject\":\"").append(jsonEscape(material.subject))
                    .append("\",\"validUntil\":\"").append(jsonEscape(material.validUntil))
                    .append("\",\"chainCount\":").append(material.chainCount)
                    .append(",\"chainComplete\":").append(material.chainComplete)
                    .append(",\"inspectionOnly\":").append(material.inspectionOnly)
                    .append(",\"privateKeyMatches\":").append(material.privateKeyMatches)
                    .append(",\"allCertificatesUsed\":").append(material.allCertificatesUsed)
                    .append(",\"certificatesCurrentlyValid\":").append(material.certificatesCurrentlyValid)
                    .append(",\"cognosReady\":").append(isCognosReady(material))
                    .append(",\"chain\":").append(chainJson(material));
        }
        json.append('}');
        writeJson(response, HttpServletResponse.SC_OK, json.toString());
    }

    private static String chainJson(CertificateMaterial material) {
        StringBuilder json = new StringBuilder("[");
        for (int i = 0; i < material.chainCertificates.size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            X509Certificate certificate = material.chainCertificates.get(i);
            boolean root = i == material.chainCertificates.size() - 1 && material.chainComplete;
            boolean signatureVerified = root
                    ? isSelfSigned(certificate)
                    : i + 1 < material.chainCertificates.size()
                            && canIssue(certificate, material.chainCertificates.get(i + 1));
            String role = i == 0 ? "Serverzertifikat" : root ? "Stammzertifikat" : "Zwischenzertifikat";
            json.append("{\"role\":\"").append(role)
                    .append("\",\"subject\":\"").append(jsonEscape(certificate.getSubjectX500Principal().getName()))
                    .append("\",\"issuer\":\"").append(jsonEscape(certificate.getIssuerX500Principal().getName()))
                    .append("\",\"serialNumber\":\"").append(certificate.getSerialNumber().toString(16).toUpperCase(Locale.ROOT))
                    .append("\",\"validFrom\":\"").append(formatDate(certificate.getNotBefore()))
                    .append("\",\"validUntil\":\"").append(formatDate(certificate.getNotAfter()))
                    .append("\",\"isCa\":").append(certificate.getBasicConstraints() >= 0)
                    .append(",\"currentlyValid\":").append(isCurrentlyValid(certificate))
                    .append(",\"signatureVerified\":").append(signatureVerified)
                    .append(",\"selfSigned\":").append(root).append('}');
        }
        return json.append(']').toString();
    }

    private void importWorkspacePem(HttpServletRequest request, HttpServletResponse response, HttpSession session)
            throws IOException {
        Part pemPart = null;
        byte[] content = null;
        byte[] privateKeyBytes = null;
        try {
            pemPart = request.getPart("pem");
            if (pemPart == null || pemPart.getSize() == 0) {
                writeJson(response, HttpServletResponse.SC_BAD_REQUEST,
                        "{\"error\":\"Bitte wählen Sie eine pa-workspace.pem-Datei aus.\"}");
                return;
            }
            if (pemPart.getSize() > MAX_MANUAL_CERTIFICATE_BYTES) {
                throw new IOException("Die PEM-Datei überschreitet die maximale Größe von 5 MiB.");
            }
            try (InputStream input = pemPart.getInputStream()) {
                content = readLimited(input, MAX_MANUAL_CERTIFICATE_BYTES);
            }
            PemContents parsed = parseWorkspacePem(content);
            privateKeyBytes = parsed.privateKeyBytes;
            PrivateKey privateKey = parsePrivateKey(privateKeyBytes);

            X509Certificate serverCertificate = null;
            for (X509Certificate certificate : parsed.certificates) {
                if (certificate.getBasicConstraints() < 0) {
                    serverCertificate = certificate;
                    break;
                }
            }
            if (serverCertificate == null) {
                throw new GeneralSecurityException("PEM-Datei enthält kein Serverzertifikat.");
            }
            boolean keyMatches = false;
            try {
                keyMatches = privateKeyMatches(privateKey, serverCertificate);
            } catch (GeneralSecurityException e) {
                getServletContext().log("Schlüssel-Zertifikat-Prüfung der PEM-Datei fehlgeschlagen", e);
            }

            ChainResult chain = orderChain(serverCertificate, parsed.certificates);
            boolean allCertificatesUsed = chain.chain.size() == parsed.certificates.size();
            CertificateMaterial material = createMaterial(new byte[0], privateKey.getAlgorithm(), chain,
                    true, keyMatches, allCertificatesUsed);
            session.setMaxInactiveInterval(SESSION_TIMEOUT_SECONDS);
            session.setAttribute(MATERIAL_ATTRIBUTE, material);
            writeJson(response, HttpServletResponse.SC_OK, "{\"ok\":true}");
        } catch (GeneralSecurityException | ServletException | IllegalStateException | IOException e) {
            getServletContext().log("PEM-Prüfung fehlgeschlagen", e);
            writeJson(response, HttpServletResponse.SC_BAD_REQUEST,
                    "{\"error\":\"PEM-Datei ungültig oder nicht konsistent. Erwartet wird eine unverschlüsselte PKCS#8-PEM-Datei mit X.509-Zertifikaten.\"}");
        } finally {
            if (content != null) {
                java.util.Arrays.fill(content, (byte) 0);
            }
            if (privateKeyBytes != null) {
                java.util.Arrays.fill(privateKeyBytes, (byte) 0);
            }
            if (pemPart != null) {
                try {
                    pemPart.delete();
                } catch (IOException e) {
                    getServletContext().log("Temporäre PEM-Datei konnte nicht gelöscht werden", e);
                }
            }
        }
    }

    private static PemContents parseWorkspacePem(byte[] content) throws IOException, GeneralSecurityException {
        String text = new String(content, StandardCharsets.US_ASCII);
        for (int i = 0; i < text.length(); i++) {
            if (text.charAt(i) > 0x7f) {
                throw new IOException("PEM-Datei enthält ungültige Zeichen.");
            }
        }
        Pattern blockPattern = Pattern.compile(
                "-----BEGIN ([A-Z0-9 ]+)-----\\s*(.*?)\\s*-----END \\1-----", Pattern.DOTALL);
        Matcher matcher = blockPattern.matcher(text);
        int offset = 0;
        byte[] privateKey = null;
        List<X509Certificate> certificates = new ArrayList<X509Certificate>();
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        try {
            while (matcher.find()) {
                if (!text.substring(offset, matcher.start()).trim().isEmpty()) {
                    throw new IOException("PEM-Datei enthält Daten außerhalb der PEM-Blöcke.");
                }
                String label = matcher.group(1);
                byte[] der;
                try {
                    der = Base64.getDecoder().decode(matcher.group(2).replaceAll("\\s", ""));
                } catch (IllegalArgumentException e) {
                    throw new IOException("PEM-Block enthält ungültiges Base64.", e);
                }
                if ("PRIVATE KEY".equals(label)) {
                    if (privateKey != null) {
                        java.util.Arrays.fill(der, (byte) 0);
                        throw new IOException("PEM-Datei enthält mehr als einen privaten Schlüssel.");
                    }
                    privateKey = der;
                } else if ("CERTIFICATE".equals(label)) {
                    if (certificates.size() >= MAX_CHAIN_CERTIFICATES) {
                        java.util.Arrays.fill(der, (byte) 0);
                        throw new IOException("PEM-Datei enthält mehr als zwölf Zertifikate.");
                    }
                    ByteArrayInputStream input = new ByteArrayInputStream(der);
                    Certificate certificate = factory.generateCertificate(input);
                    java.util.Arrays.fill(der, (byte) 0);
                    if (input.available() != 0 || !(certificate instanceof X509Certificate)) {
                        throw new GeneralSecurityException("PEM-Datei enthält ein ungültiges X.509-Zertifikat.");
                    }
                    certificates.add((X509Certificate) certificate);
                } else {
                    java.util.Arrays.fill(der, (byte) 0);
                    throw new IOException("Nicht unterstützter PEM-Block: " + label);
                }
                offset = matcher.end();
            }
            if (!text.substring(offset).trim().isEmpty() || privateKey == null || certificates.isEmpty()) {
                throw new IOException("PEM-Datei muss einen privaten Schlüssel und mindestens ein Zertifikat enthalten.");
            }
            return new PemContents(privateKey, certificates);
        } catch (IOException | GeneralSecurityException e) {
            if (privateKey != null) {
                java.util.Arrays.fill(privateKey, (byte) 0);
            }
            throw e;
        }
    }

    private static PrivateKey parsePrivateKey(byte[] encoded) throws GeneralSecurityException {
        GeneralSecurityException failure = null;
        for (String algorithm : new String[] {"RSA", "EC", "DSA"}) {
            try {
                return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(encoded));
            } catch (GeneralSecurityException e) {
                failure = e;
            }
        }
        throw new GeneralSecurityException("Der private Schlüssel ist kein unterstützter PKCS#8-Schlüssel.", failure);
    }

    private void importPfx(HttpServletRequest request, HttpServletResponse response, HttpSession session)
            throws IOException {
        Part pfxPart;
        try {
            pfxPart = request.getPart("pfx");
        } catch (ServletException | IOException | IllegalStateException e) {
            getServletContext().log("PFX-Upload fehlgeschlagen", e);
            writeJson(response, HttpServletResponse.SC_BAD_REQUEST,
                    "{\"error\":\"PFX ungültig, zu groß oder Passwort falsch. Bitte prüfen Sie Datei und Passwort.\"}");
            return;
        }
        if (pfxPart == null || pfxPart.getSize() == 0) {
            if (pfxPart != null) {
                try {
                    pfxPart.delete();
                } catch (IOException e) {
                    getServletContext().log("Temporäre PFX-Datei konnte nicht gelöscht werden", e);
                }
            }
            writeJson(response, HttpServletResponse.SC_BAD_REQUEST,
                    "{\"error\":\"Bitte wählen Sie eine PFX-Datei aus.\"}");
            return;
        }

        char[] password = null;
        CertificateMaterial material;
        try {
            String passwordValue = request.getParameter("password");
            password = passwordValue == null ? new char[0] : passwordValue.toCharArray();

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream input = pfxPart.getInputStream()) {
                keyStore.load(input, password);
            }

            PrivateKey privateKey = null;
            Certificate[] chain = null;
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (!keyStore.isKeyEntry(alias)) {
                    continue;
                }
                Key key = keyStore.getKey(alias, password);
                if (key instanceof PrivateKey) {
                    privateKey = (PrivateKey) key;
                    chain = keyStore.getCertificateChain(alias);
                    break;
                }
            }
            if (privateKey == null || chain == null || chain.length == 0) {
                throw new GeneralSecurityException("Die PFX-Datei enthält keinen privaten Schlüssel mit Zertifikatkette.");
            }
            if (privateKey.getEncoded() == null) {
                throw new GeneralSecurityException("Der private Schlüssel kann nicht exportiert werden.");
            }

            List<X509Certificate> certificates = new ArrayList<X509Certificate>(chain.length);
            for (Certificate certificate : chain) {
                if (!(certificate instanceof X509Certificate)) {
                    throw new GeneralSecurityException("Die PFX-Datei enthält ein nicht unterstütztes Zertifikat.");
                }
                certificates.add((X509Certificate) certificate);
            }

            byte[] privateKeyPem = pem("PRIVATE KEY", privateKey.getEncoded());
            material = createMaterial(privateKeyPem, privateKey.getAlgorithm(),
                    orderChain(certificates.get(0), certificates));
        } catch (GeneralSecurityException | IOException | IllegalStateException e) {
            getServletContext().log("PFX-Import fehlgeschlagen", e);
            writeJson(response, HttpServletResponse.SC_BAD_REQUEST,
                    "{\"error\":\"PFX ungültig, zu groß oder Passwort falsch. Bitte prüfen Sie Datei und Passwort.\"}");
            return;
        } finally {
            if (password != null) {
                java.util.Arrays.fill(password, '\0');
            }
            if (pfxPart != null) {
                try {
                    pfxPart.delete();
                } catch (IOException e) {
                    getServletContext().log("Temporäre PFX-Datei konnte nicht gelöscht werden", e);
                }
            }
        }

        session.setMaxInactiveInterval(SESSION_TIMEOUT_SECONDS);
        session.setAttribute(MATERIAL_ATTRIBUTE, material);
        writeJson(response, HttpServletResponse.SC_OK, "{\"ok\":true}");
    }

    private void importChain(HttpServletRequest request, HttpServletResponse response, HttpSession session)
            throws IOException {
        CertificateMaterial material = (CertificateMaterial) session.getAttribute(MATERIAL_ATTRIBUTE);
        if (material == null) {
            writeJson(response, HttpServletResponse.SC_NOT_FOUND,
                    "{\"error\":\"Bitte importieren Sie zuerst eine PFX-Datei.\"}");
            return;
        }

        List<Part> parts = new ArrayList<Part>();
        List<X509Certificate> uploaded = new ArrayList<X509Certificate>();
        try {
            parts.addAll(request.getParts());
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            for (Part part : parts) {
                if (!"certificates".equals(part.getName()) || part.getSize() == 0) {
                    continue;
                }
                if (part.getSize() > MAX_MANUAL_CERTIFICATE_BYTES) {
                    throw new IOException("Eine Zertifikatsdatei überschreitet die maximale Größe von 5 MiB.");
                }
                byte[] content;
                try (InputStream input = part.getInputStream()) {
                    content = readLimited(input, MAX_MANUAL_CERTIFICATE_BYTES);
                }
                Collection<? extends Certificate> parsed =
                        factory.generateCertificates(new ByteArrayInputStream(content));
                for (Certificate certificate : parsed) {
                    if (!(certificate instanceof X509Certificate)) {
                        throw new GeneralSecurityException("Nur X.509-Zertifikate können importiert werden.");
                    }
                    uploaded.add((X509Certificate) certificate);
                    if (uploaded.size() > MAX_CHAIN_CERTIFICATES) {
                        throw new GeneralSecurityException("Es können höchstens zwölf Zertifikate importiert werden.");
                    }
                }
            }
        } catch (GeneralSecurityException | ServletException | IllegalStateException e) {
            getServletContext().log("Manueller Zertifikatsimport fehlgeschlagen", e);
            writeJson(response, HttpServletResponse.SC_BAD_REQUEST,
                    "{\"error\":\"Zertifikatsdatei ungültig oder Upload zu groß. Bitte PEM-, DER- oder PKCS#7-X.509-Dateien verwenden.\"}");
            return;
        } catch (IOException e) {
            getServletContext().log("Manueller Zertifikatsimport fehlgeschlagen", e);
            writeJson(response, HttpServletResponse.SC_BAD_REQUEST,
                    "{\"error\":\"Zertifikatsdatei ungültig oder Upload zu groß. Bitte PEM-, DER- oder PKCS#7-X.509-Dateien verwenden.\"}");
            return;
        } finally {
            for (Part part : parts) {
                try {
                    part.delete();
                } catch (IOException e) {
                    getServletContext().log("Temporäre Zertifikatsdatei konnte nicht gelöscht werden", e);
                }
            }
        }

        if (uploaded.isEmpty()) {
            writeJson(response, HttpServletResponse.SC_BAD_REQUEST,
                    "{\"error\":\"Bitte wählen Sie mindestens ein Zertifikat aus.\"}");
            return;
        }

        List<X509Certificate> candidates = new ArrayList<X509Certificate>(material.chainCertificates);
        candidates.addAll(uploaded);
        ChainResult result;
        try {
            result = orderChain(material.chainCertificates.get(0), candidates);
        } catch (GeneralSecurityException e) {
            getServletContext().log("Zertifikatskette konnte nicht geprüft werden", e);
            writeJson(response, HttpServletResponse.SC_BAD_REQUEST,
                    "{\"error\":\"Die Zertifikatskette konnte nicht geprüft werden.\"}");
            return;
        }
        int added = countImportedCertificates(result.chain, uploaded);
        if (added == 0) {
            writeJson(response, HttpServletResponse.SC_BAD_REQUEST,
                    "{\"error\":\"Keines der Zertifikate gehört zur Ausstellerkette des Serverzertifikats.\"}");
            return;
        }

        try {
            session.setAttribute(MATERIAL_ATTRIBUTE, material.withChain(result));
        } catch (GeneralSecurityException | IOException e) {
            getServletContext().log("Manuell ergänzte Zertifikatskette konnte nicht exportiert werden", e);
            writeJson(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "{\"error\":\"Die ergänzte Zertifikatskette konnte nicht gespeichert werden.\"}");
            return;
        }
        writeJson(response, HttpServletResponse.SC_OK,
                chainResultJson(result, added,
                        result.complete ? "Zertifikatskette manuell ergänzt." : "Zertifikatskette teilweise ergänzt; weitere Ausstellerzertifikate fehlen."));
    }

    private void completeChain(HttpServletRequest request, HttpServletResponse response, HttpSession session)
            throws IOException {
        CertificateMaterial material = (CertificateMaterial) session.getAttribute(MATERIAL_ATTRIBUTE);
        if (material == null) {
            writeJson(response, HttpServletResponse.SC_NOT_FOUND,
                    "{\"error\":\"Bitte importieren Sie zuerst eine PFX-Datei.\"}");
            return;
        }

        ChainResult result;
        int added = 0;
        int downloads = 0;
        List<X509Certificate> candidates = new ArrayList<X509Certificate>(material.chainCertificates);
        try {
            result = orderChain(candidates.get(0), candidates);
            while (!result.complete && downloads < MAX_AIA_DOWNLOADS
                    && result.chain.size() < MAX_CHAIN_CERTIFICATES) {
                X509Certificate issuer = result.chain.get(result.chain.size() - 1);
                List<X509Certificate> fetched = new ArrayList<X509Certificate>();
                List<String> issuerUris;
                try {
                    issuerUris = caIssuerUris(issuer);
                } catch (IOException e) {
                    getServletContext().log("AIA-Angabe des Zertifikats konnte nicht gelesen werden", e);
                    break;
                }
                for (String uri : issuerUris) {
                    if (downloads >= MAX_AIA_DOWNLOADS) {
                        break;
                    }
                    downloads++;
                    try {
                        fetched.addAll(fetchCaCertificates(uri));
                    } catch (IOException e) {
                        getServletContext().log("AIA-Zertifikat konnte nicht geladen werden", e);
                    }
                }
                int previousSize = result.chain.size();
                for (X509Certificate certificate : fetched) {
                    if (canIssue(issuer, certificate) && !containsCertificate(candidates, certificate)) {
                        candidates.add(certificate);
                        added++;
                    }
                }
                result = orderChain(candidates.get(0), candidates);
                if (result.chain.size() == previousSize) {
                    break;
                }
            }
        } catch (GeneralSecurityException e) {
            getServletContext().log("AIA-Zertifikatskette konnte nicht geprüft werden", e);
            writeJson(response, HttpServletResponse.SC_BAD_GATEWAY,
                    "{\"error\":\"Die online gefundene Zertifikatskette konnte nicht geprüft werden.\"}");
            return;
        }

        if (added > 0) {
            try {
                session.setAttribute(MATERIAL_ATTRIBUTE, material.withChain(result));
            } catch (GeneralSecurityException | IOException e) {
                getServletContext().log("Online ergänzte Zertifikatskette konnte nicht exportiert werden", e);
                writeJson(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        "{\"error\":\"Die ergänzte Zertifikatskette konnte nicht gespeichert werden.\"}");
                return;
            }
        }
        String message = result.complete
                ? (added == 0 ? "Die Zertifikatskette ist bereits vollständig." : "Zertifikatskette online ergänzt.")
                : (added == 0 ? "Keine passende Zertifikatskette online gefunden; importieren Sie die Zertifikate manuell."
                        : "Zertifikatskette teilweise ergänzt; weitere Ausstellerzertifikate fehlen.");
        writeJson(response, HttpServletResponse.SC_OK, chainResultJson(result, added, message));
    }

    private static String chainResultJson(ChainResult result, int added, String message) {
        return "{\"ok\":true,\"added\":" + added + ",\"chainCount\":" + (result.chain.size() - 1)
                + ",\"chainComplete\":" + result.complete + ",\"message\":\"" + jsonEscape(message) + "\"}";
    }

    private static int countImportedCertificates(List<X509Certificate> chain, List<X509Certificate> uploaded) {
        int count = 0;
        for (X509Certificate certificate : uploaded) {
            if (containsCertificate(chain, certificate)) {
                count++;
            }
        }
        return count;
    }

    private static CertificateMaterial createMaterial(byte[] privateKeyPem, String privateKeyAlgorithm,
                                                      ChainResult chain)
            throws GeneralSecurityException, IOException {
        return createMaterial(privateKeyPem, privateKeyAlgorithm, chain, false, true, true);
    }

    private static CertificateMaterial createMaterial(byte[] privateKeyPem, String privateKeyAlgorithm,
                                                      ChainResult chain, boolean inspectionOnly,
                                                      boolean privateKeyMatches, boolean allCertificatesUsed)
            throws GeneralSecurityException, IOException {
        X509Certificate serverCertificate = chain.chain.get(0);
        byte[] serverCertificatePem = pem("CERTIFICATE", serverCertificate.getEncoded());
        List<byte[]> chainParts = new ArrayList<byte[]>();
        for (int i = 1; i < chain.chain.size(); i++) {
            chainParts.add(pem("CERTIFICATE", chain.chain.get(i).getEncoded()));
        }
        byte[] chainPem = concatenate(chainParts);
        byte[] workspacePem = new byte[0];
        if (!inspectionOnly) {
            List<byte[]> workspaceParts = new ArrayList<byte[]>();
            workspaceParts.add(privateKeyPem);
            workspaceParts.add(serverCertificatePem);
            workspaceParts.addAll(chainParts);
            workspacePem = concatenate(workspaceParts);
        }
        boolean certificatesCurrentlyValid = true;
        for (X509Certificate certificate : chain.chain) {
            certificatesCurrentlyValid &= isCurrentlyValid(certificate);
        }
        return new CertificateMaterial(
                inspectionOnly ? new byte[0] : privateKeyPem,
                serverCertificatePem,
                chainPem,
                workspacePem,
                serverCertificate.getSubjectX500Principal().getName(),
                formatDate(serverCertificate.getNotAfter()),
                privateKeyAlgorithm,
                chain.chain,
                chain.complete,
                inspectionOnly,
                privateKeyMatches,
                allCertificatesUsed,
                certificatesCurrentlyValid);
    }

    private void downloadCognosBundle(HttpServletRequest request, HttpServletResponse response,
                                      HttpSession session) throws IOException {
        CertificateMaterial material = (CertificateMaterial) session.getAttribute(MATERIAL_ATTRIBUTE);
        if (material == null) {
            writeJson(response, HttpServletResponse.SC_NOT_FOUND,
                    "{\"error\":\"Bitte importieren Sie zuerst eine PFX-Datei.\"}");
            return;
        }
        if (!isCognosReady(material)) {
            writeJson(response, HttpServletResponse.SC_BAD_REQUEST,
                    "{\"error\":\"Für das Cognos-Paket werden ein RSA-Schlüssel und eine vollständige, geprüfte Zertifikatskette benötigt.\"}");
            return;
        }

        Part passwordPart;
        try {
            passwordPart = request.getPart("pfxPassword");
        } catch (ServletException | IOException | IllegalStateException e) {
            getServletContext().log("Cognos-PFX-Passwort konnte nicht gelesen werden", e);
            writeJson(response, HttpServletResponse.SC_BAD_REQUEST,
                    "{\"error\":\"Das PFX-Passwort konnte nicht gelesen werden.\"}");
            return;
        }
        if (passwordPart == null) {
            writeJson(response, HttpServletResponse.SC_BAD_REQUEST,
                    "{\"error\":\"Bitte geben Sie ein neues PFX-Passwort ein.\"}");
            return;
        }

        char[] pfxPassword = null;
        byte[] privateKeyBytes = null;
        byte[] pfxBytes = null;
        WipingByteArrayOutputStream pfxOutput = null;
        try {
            try (InputStream input = passwordPart.getInputStream()) {
                pfxPassword = readPassword(input);
            }
            if (pfxPassword.length < 12) {
                writeJson(response, HttpServletResponse.SC_BAD_REQUEST,
                        "{\"error\":\"Das neue PFX-Passwort muss mindestens 12 Zeichen lang sein.\"}");
                return;
            }
            privateKeyBytes = privateKeyBytes(material.privateKeyPem);
            PrivateKey privateKey = KeyFactory.getInstance(material.privateKeyAlgorithm)
                    .generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
            verifyPrivateKeyMatches(privateKey, material.chainCertificates.get(0));

            KeyStore pfx = KeyStore.getInstance("PKCS12");
            pfx.load(null, pfxPassword);
            pfx.setKeyEntry("encryptCertificate", privateKey, pfxPassword,
                    material.chainCertificates.toArray(new Certificate[0]));
            pfxOutput = new WipingByteArrayOutputStream();
            pfx.store(pfxOutput, pfxPassword);
            pfxBytes = pfxOutput.toByteArray();
            pfxOutput.wipe();

            response.setContentType("application/zip");
            response.setHeader("Content-Disposition",
                    "attachment; filename=\"cognos-certificate-preparation.zip\"");
            try (ZipOutputStream zip = new ZipOutputStream(response.getOutputStream(), StandardCharsets.UTF_8)) {
                addZipEntry(zip, "encryptCertificate.pfx", pfxBytes);
                for (int i = 1; i < material.chainCertificates.size() - 1; i++) {
                    X509Certificate certificate = material.chainCertificates.get(i);
                    addZipEntry(zip, String.format(Locale.ROOT, "ica-%02d.cer", i),
                            certificate.getEncoded());
                }
                addZipEntry(zip, "ca.cer",
                        material.chainCertificates.get(material.chainCertificates.size() - 1).getEncoded());
                addZipEntry(zip, "commands-windows.txt", cognosCommands(material, true));
                addZipEntry(zip, "commands-linux.txt", cognosCommands(material, false));
                addZipEntry(zip, "README.txt", cognosReadme(material));
            }
        } catch (InvalidPasswordException e) {
            getServletContext().log("Cognos-PFX-Passwort ungültig", e);
            if (!response.isCommitted()) {
                writeJson(response, HttpServletResponse.SC_BAD_REQUEST,
                        "{\"error\":\"Das neue PFX-Passwort muss gültiges UTF-8 und höchstens 128 Zeichen enthalten.\"}");
            }
        } catch (GeneralSecurityException e) {
            getServletContext().log("Cognos-Vorbereitung fehlgeschlagen", e);
            if (!response.isCommitted()) {
                writeJson(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        "{\"error\":\"Das Cognos-Paket konnte nicht erstellt werden. Prüfen Sie RSA-Schlüssel und Zertifikatskette.\"}");
            }
        } finally {
            if (pfxPassword != null) {
                java.util.Arrays.fill(pfxPassword, '\0');
            }
            if (privateKeyBytes != null) {
                java.util.Arrays.fill(privateKeyBytes, (byte) 0);
            }
            if (pfxBytes != null) {
                java.util.Arrays.fill(pfxBytes, (byte) 0);
            }
            if (pfxOutput != null) {
                pfxOutput.wipe();
            }
            try {
                passwordPart.delete();
            } catch (IOException e) {
                getServletContext().log("Temporäre Cognos-Passwortdatei konnte nicht gelöscht werden", e);
            }
        }
    }

    private static char[] readPassword(InputStream input) throws IOException {
        byte[] encoded;
        try {
            encoded = readLimited(input, 512);
        } catch (IOException e) {
            throw new InvalidPasswordException("Das PFX-Passwort ist zu groß.", e);
        }
        CharBuffer decoded = null;
        try {
            decoded = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(encoded));
            if (decoded.remaining() > 128) {
                throw new InvalidPasswordException("Das PFX-Passwort überschreitet 128 Zeichen.");
            }
            char[] password = new char[decoded.remaining()];
            decoded.get(password);
            return password;
        } catch (CharacterCodingException e) {
            throw new InvalidPasswordException("Das PFX-Passwort enthält ungültige Zeichen.", e);
        } finally {
            java.util.Arrays.fill(encoded, (byte) 0);
            if (decoded != null && decoded.hasArray()) {
                java.util.Arrays.fill(decoded.array(), '\0');
            }
        }
    }

    private static boolean isCognosReady(CertificateMaterial material) {
        return !material.inspectionOnly && material.chainComplete
                && "RSA".equalsIgnoreCase(material.privateKeyAlgorithm)
                && "RSA".equalsIgnoreCase(material.chainCertificates.get(0).getPublicKey().getAlgorithm());
    }

    private static byte[] privateKeyBytes(byte[] pemBytes) throws GeneralSecurityException {
        String encoded = new String(pemBytes, StandardCharsets.US_ASCII)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        try {
            return Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException("Der sitzungsinterne PKCS#8-Schlüssel ist ungültig.", e);
        }
    }

    private static void verifyPrivateKeyMatches(PrivateKey privateKey, X509Certificate certificate)
            throws GeneralSecurityException {
        if (!privateKeyMatches(privateKey, certificate)) {
            throw new GeneralSecurityException("Privater Schlüssel und Serverzertifikat passen nicht zusammen.");
        }
    }

    private static boolean privateKeyMatches(PrivateKey privateKey, X509Certificate certificate)
            throws GeneralSecurityException {
        String algorithm;
        if ("RSA".equalsIgnoreCase(privateKey.getAlgorithm())) {
            algorithm = "SHA256withRSA";
        } else if ("EC".equalsIgnoreCase(privateKey.getAlgorithm())
                || "ECDSA".equalsIgnoreCase(privateKey.getAlgorithm())) {
            algorithm = "SHA256withECDSA";
        } else if ("DSA".equalsIgnoreCase(privateKey.getAlgorithm())) {
            algorithm = "SHA256withDSA";
        } else {
            throw new GeneralSecurityException("Nicht unterstützter Schlüsselalgorithmus.");
        }
        byte[] challenge = new byte[32];
        byte[] signedChallenge = null;
        try {
            new java.security.SecureRandom().nextBytes(challenge);
            Signature signer = Signature.getInstance(algorithm);
            signer.initSign(privateKey);
            signer.update(challenge);
            signedChallenge = signer.sign();
            Signature verifier = Signature.getInstance(algorithm);
            verifier.initVerify(certificate.getPublicKey());
            verifier.update(challenge);
            return verifier.verify(signedChallenge);
        } finally {
            java.util.Arrays.fill(challenge, (byte) 0);
            if (signedChallenge != null) {
                java.util.Arrays.fill(signedChallenge, (byte) 0);
            }
        }
    }

    private static String cognosCommands(CertificateMaterial material, boolean windows) {
        String tool = windows ? "ThirdPartyCertificateTool.bat" : "./ThirdPartyCertificateTool.sh";
        StringBuilder commands = new StringBuilder();
        commands.append(tool).append(" -i -T -r ca.cer -p YOUR_COGNOS_KEYSTORE_PASSWORD\n");
        for (int i = 1; i < material.chainCertificates.size() - 1; i++) {
            commands.append(tool).append(" -i -T -r ")
                    .append(String.format(Locale.ROOT, "ica-%02d.cer", i))
                    .append(" -p YOUR_COGNOS_KEYSTORE_PASSWORD\n");
        }
        commands.append(tool)
                .append(" -i -e -a RSA -p YOUR_COGNOS_KEYSTORE_PASSWORD")
                .append(" -K encryptCertificate.pfx -w YOUR_PFX_FILE_PASSWORD\n");
        return commands.toString();
    }

    private static String cognosReadme(CertificateMaterial material) {
        StringBuilder readme = new StringBuilder();
        readme.append("Cognos Analytics - Zertifikatsvorbereitung\n")
                .append("===========================================\n\n")
                .append("Dieses Paket bereitet die Dateien und Befehle fuer den dokumentierten ")
                .append("Cognos ThirdPartyCertificateTool-Import vor. Es ersetzt weder das ")
                .append("IBM-Tool noch einen Cognos-Keystore.\n\n")
                .append("Enthaltene Dateien:\n")
                .append("- encryptCertificate.pfx: Serverzertifikat, privater RSA-Schluessel ")
                .append("und komplette Zertifikatskette; PFX-Passwort selbst gewaehlt.\n")
                .append("- ca.cer: selbstsigniertes Root-CA-Zertifikat im DER-Format.\n");
        for (int i = 1; i < material.chainCertificates.size() - 1; i++) {
            readme.append("- ")
                    .append(String.format(Locale.ROOT, "ica-%02d.cer", i))
                    .append(": Zwischenzertifikat im DER-Format.\n");
        }
        readme.append("- commands-windows.txt und commands-linux.txt: IBM-Importbefehle ")
                .append("mit Platzhaltern.\n\n")
                .append("Vorbereitung und Import:\n")
                .append("1. Alle betroffenen Cognos Analytics Komponenten stoppen. IBM verlangt ")
                .append("den Import auf jedem Rechner, auf dem Cognos-Komponenten installiert sind.\n")
                .append("2. Den vorhandenen Cognos-Keystore gemaess IBM-Anleitung sichern und ")
                .append("sicherstellen, dass der zu importierende Keystore leer ist.\n")
                .append("3. Alle Dateien dieses Pakets in das Cognos-Verzeichnis install_location/bin kopieren.\n")
                .append("4. YOUR_COGNOS_KEYSTORE_PASSWORD in den Befehlen durch das in Cognos ")
                .append("Configuration konfigurierte Keystore-Passwort ersetzen. Standard laut IBM: NoPassWordSet.\n")
                .append("5. YOUR_PFX_FILE_PASSWORD durch das beim Erstellen dieses Pakets ")
                .append("eingegebene PFX-Passwort ersetzen.\n")
                .append("6. Zuerst die Befehle fuer CA-Zertifikate ausfuehren, anschliessend ")
                .append("den PFX-Importbefehl. Die Befehlssyntax ist fuer die installierte ")
                .append("Cognos-Version anhand der IBM-Dokumentation zu pruefen.\n")
                .append("7. Cognos-Komponenten gemaess IBM-Anleitung konfigurieren und neu starten.\n\n")
                .append("Sicherheit:\n")
                .append("- PFX-Passwort ist nicht in diesem Paket enthalten. Bewahren Sie es ")
                .append("getrennt und sicher auf.\n")
                .append("- IBM verlangt das PFX-Passwort als Befehlsargument. Vermeiden Sie ")
                .append("Shell-History und beschraenken Sie waehrend des Imports den Zugriff ")
                .append("auf Prozesslisten und Konsolen.\n")
                .append("- Das Passwort des Cognos-Keystores wird nicht gespeichert und ")
                .append("absichtlich nicht in den Befehlsdateien hinterlegt.\n")
                .append("- Dieses Paket bearbeitet keine Cognos-Dateien direkt.\n\n")
                .append("Zertifikats-Subject: ").append(material.subject).append('\n')
                .append("Chain of Trust: ").append(material.chainCertificates.size())
                .append(" Zertifikate; Root-Signatur und Aussteller-Signaturen geprueft.\n");
        return readme.toString();
    }

    private static void addZipEntry(ZipOutputStream zip, String filename, byte[] content) throws IOException {
        zip.putNextEntry(new ZipEntry(filename));
        zip.write(content);
        zip.closeEntry();
    }

    private static void addZipEntry(ZipOutputStream zip, String filename, String content) throws IOException {
        addZipEntry(zip, filename, content.getBytes(StandardCharsets.UTF_8));
    }

    private static ChainResult orderChain(X509Certificate leaf, List<X509Certificate> candidates)
            throws GeneralSecurityException {
        List<X509Certificate> ordered = new ArrayList<X509Certificate>();
        ordered.add(leaf);
        X509Certificate current = leaf;
        boolean complete = false;
        while (ordered.size() < MAX_CHAIN_CERTIFICATES) {
            if (isSelfSigned(current)) {
                complete = true;
                break;
            }
            X509Certificate issuer = null;
            for (X509Certificate candidate : candidates) {
                if (!containsCertificate(ordered, candidate) && canIssue(current, candidate)) {
                    issuer = candidate;
                    break;
                }
            }
            if (issuer == null) {
                break;
            }
            ordered.add(issuer);
            current = issuer;
        }
        if (ordered.size() == MAX_CHAIN_CERTIFICATES && isSelfSigned(current)) {
            complete = true;
        }
        return new ChainResult(ordered, complete);
    }

    private static boolean canIssue(X509Certificate certificate, X509Certificate issuer) {
        if (!certificate.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())
                || issuer.getBasicConstraints() < 0) {
            return false;
        }
        boolean[] keyUsage = issuer.getKeyUsage();
        if (keyUsage != null && (keyUsage.length <= 5 || !keyUsage[5])) {
            return false;
        }
        try {
            certificate.verify(issuer.getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    private static boolean isSelfSigned(X509Certificate certificate) {
        if (!certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
            return false;
        }

        try {
            certificate.verify(certificate.getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    private static boolean isCurrentlyValid(X509Certificate certificate) {
        try {
            certificate.checkValidity();
            return true;
        } catch (java.security.cert.CertificateException e) {
            return false;
        }
    }

    private static boolean containsCertificate(List<X509Certificate> certificates, X509Certificate candidate) {
        for (X509Certificate certificate : certificates) {
            if (certificate.equals(candidate)) {
                return true;
            }
        }
        return false;
    }

    private static List<String> caIssuerUris(X509Certificate certificate) throws IOException {
        byte[] extension = certificate.getExtensionValue(AUTHORITY_INFO_ACCESS_OID);
        if (extension == null) {
            return new ArrayList<String>();
        }
        DerReader outerReader = new DerReader(extension);
        DerElement octetString = outerReader.read();
        if (octetString.tag != 0x04 || outerReader.hasRemaining()) {
            throw new IOException("Ungültige Authority-Information-Access-Erweiterung.");
        }
        DerReader extensionReader = new DerReader(octetString.value);
        DerElement sequence = extensionReader.read();
        if (sequence.tag != 0x30 || extensionReader.hasRemaining()) {
            throw new IOException("Ungültige Authority-Information-Access-Erweiterung.");
        }
        byte[] caIssuersOid = new byte[] {0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02};
        Set<String> uris = new LinkedHashSet<String>();
        DerReader descriptions = new DerReader(sequence.value);
        while (descriptions.hasRemaining()) {
            DerElement description = descriptions.read();
            if (description.tag != 0x30) {
                continue;
            }
            DerReader fields = new DerReader(description.value);
            DerElement method = fields.read();
            if (method.tag != 0x06 || !java.util.Arrays.equals(method.value, caIssuersOid)
                    || !fields.hasRemaining()) {
                continue;
            }
            DerElement location = fields.read();
            if (location.tag == 0x86) {
                String value = new String(location.value, StandardCharsets.US_ASCII);
                if (value.length() <= 2048) {
                    uris.add(value);
                }
            }
        }
        return new ArrayList<String>(uris);
    }

    private List<X509Certificate> fetchCaCertificates(String value) throws IOException, GeneralSecurityException {
        URI uri;
        try {
            uri = new URI(value);
        } catch (java.net.URISyntaxException e) {
            throw new IOException("Ungültige AIA-Adresse.", e);
        }
        String scheme = uri.getScheme();
        if (uri.getHost() == null || uri.getUserInfo() != null || uri.getFragment() != null
                || !( "http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))
                || (uri.getPort() != -1 && uri.getPort() != 80 && uri.getPort() != 443)
                || ("http".equalsIgnoreCase(scheme) && uri.getPort() == 443)
                || ("https".equalsIgnoreCase(scheme) && uri.getPort() == 80)) {
            throw new IOException("Nicht zulässige AIA-Adresse.");
        }
        InetAddress[] addresses = InetAddress.getAllByName(uri.getHost());
        if (addresses.length == 0) {
            throw new IOException("AIA-Adresse konnte nicht aufgelöst werden.");
        }
        for (InetAddress address : addresses) {
            if (!isPublicAddress(address)) {
                throw new IOException("AIA-Adresse verweist nicht ausschließlich auf öffentliche IP-Adressen.");
            }
        }

        HttpURLConnection connection = (HttpURLConnection) uri.toURL().openConnection(java.net.Proxy.NO_PROXY);
        connection.setInstanceFollowRedirects(false);
        connection.setConnectTimeout(3000);
        connection.setReadTimeout(3000);
        connection.setRequestProperty("Accept", "application/pkix-cert, application/pkcs7-mime, */*");
        connection.setRequestProperty("User-Agent", "Haushalter-Certtool");
        try {
            int status = connection.getResponseCode();
            if (status != HttpURLConnection.HTTP_OK) {
                throw new IOException("AIA-Server antwortete mit HTTP " + status + ".");
            }
            if (connection.getContentLengthLong() > MAX_AIA_RESPONSE_BYTES) {
                throw new IOException("AIA-Antwort überschreitet die zulässige Größe.");
            }
            byte[] content;
            try (InputStream input = connection.getInputStream()) {
                content = readLimited(input, MAX_AIA_RESPONSE_BYTES);
            }
            Collection<? extends Certificate> parsed = CertificateFactory.getInstance("X.509")
                    .generateCertificates(new ByteArrayInputStream(content));
            List<X509Certificate> certificates = new ArrayList<X509Certificate>();
            for (Certificate certificate : parsed) {
                if (certificate instanceof X509Certificate
                        && certificates.size() < MAX_CHAIN_CERTIFICATES) {
                    certificates.add((X509Certificate) certificate);
                }
            }
            return certificates;
        } finally {
            connection.disconnect();
        }
    }

    private static boolean isPublicAddress(InetAddress address) {
        if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                || address.isSiteLocalAddress() || address.isMulticastAddress()) {
            return false;
        }
        byte[] bytes = address.getAddress();
        if (address instanceof Inet4Address) {
            int first = bytes[0] & 0xff;
            int second = bytes[1] & 0xff;
            int third = bytes[2] & 0xff;
            return first != 0 && first != 10 && first != 127 && first < 224
                    && !(first == 100 && second >= 64 && second <= 127)
                    && !(first == 169 && second == 254)
                    && !(first == 172 && second >= 16 && second <= 31)
                    && !(first == 192 && (second == 0 || second == 168))
                    && !(first == 192 && second == 88 && third == 99)
                    && !(first == 198 && (second == 18 || second == 19 || second == 51))
                    && !(first == 203 && second == 0 && third == 113);
        }
        return address instanceof Inet6Address && (bytes[0] & 0xe0) == 0x20;
    }

    private static byte[] readLimited(InputStream input, int limit) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = input.read(buffer)) != -1) {
            if (output.size() + read > limit) {
                throw new IOException("Datei überschreitet die zulässige Größe.");
            }
            output.write(buffer, 0, read);
        }
        return output.toByteArray();
    }

    private void download(HttpServletRequest request, HttpServletResponse response) throws IOException {
        HttpSession session = request.getSession(false);
        CertificateMaterial material = session == null
                ? null : (CertificateMaterial) session.getAttribute(MATERIAL_ATTRIBUTE);
        if (material == null) {
            writeJson(response, HttpServletResponse.SC_NOT_FOUND,
                    "{\"error\":\"Keine importierte PFX-Datei in der Sitzung.\"}");
            return;
        }
        if (material.inspectionOnly) {
            writeJson(response, HttpServletResponse.SC_FORBIDDEN,
                    "{\"error\":\"Im PEM-Prüfmodus sind keine Exporte verfügbar.\"}");
            return;
        }

        String type = request.getParameter("type");
        byte[] content;
        String filename;
        if ("private-key".equals(type)) {
            content = material.privateKeyPem;
            filename = "private-key.pem";
        } else if ("server-certificate".equals(type)) {
            content = material.serverCertificatePem;
            filename = "server-certificate.pem";
        } else if ("chain".equals(type)) {
            content = material.chainPem;
            filename = "certificate-chain.pem";
        } else if ("paw".equals(type)) {
            content = material.workspacePem;
            filename = "pa-workspace.pem";
        } else {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Unbekannter Exporttyp");
            return;
        }
        if (content.length == 0) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "Die PFX-Datei enthält keine Zertifikatskette.");
            return;
        }

        response.setContentType("application/x-pem-file");
        response.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");
        response.setContentLength(content.length);
        try (OutputStream output = response.getOutputStream()) {
            output.write(content);
        }
    }

    private static byte[] pem(String label, byte[] der) {
        String body = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der);
        String value = "-----BEGIN " + label + "-----\n" + body + "\n-----END " + label + "-----\n";
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] concatenate(List<byte[]> parts) throws IOException {
        java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
        for (byte[] part : parts) {
            output.write(part);
        }
        return output.toByteArray();
    }

    private static String formatDate(Date date) {
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd", Locale.ROOT);
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        return format.format(date);
    }

    private static String jsonEscape(String value) {
        StringBuilder escaped = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '"' || c == '\\') {
                escaped.append('\\').append(c);
            } else if (c < 0x20) {
                escaped.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
            } else {
                escaped.append(c);
            }
        }
        return escaped.toString();
    }

    private static void writeJson(HttpServletResponse response, int status, String json) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json; charset=UTF-8");
        response.getWriter().write(json);
    }

    private static void setSecurityHeaders(HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("Referrer-Policy", "no-referrer");
    }

    private static final class InvalidPasswordException extends IOException {
        private static final long serialVersionUID = 1L;

        private InvalidPasswordException(String message, Throwable cause) {
            super(message, cause);
        }

        private InvalidPasswordException(String message) {
            super(message);
        }
    }

    private static final class WipingByteArrayOutputStream extends ByteArrayOutputStream {
        private void wipe() {
            java.util.Arrays.fill(buf, (byte) 0);
            reset();
        }
    }

    private static final class DerReader {
        private final byte[] data;
        private int offset;

        private DerReader(byte[] data) {
            this.data = data;
        }

        private boolean hasRemaining() {
            return offset < data.length;
        }

        private DerElement read() throws IOException {
            if (data.length - offset < 2) {
                throw new IOException("Ungültige DER-Kodierung.");
            }
            int tag = data[offset++] & 0xff;
            int firstLength = data[offset++] & 0xff;
            int length;
            if ((firstLength & 0x80) == 0) {
                length = firstLength;
            } else {
                int lengthBytes = firstLength & 0x7f;
                if (lengthBytes == 0 || lengthBytes > 4 || data.length - offset < lengthBytes) {
                    throw new IOException("Ungültige DER-Länge.");
                }
                long parsedLength = 0;
                for (int i = 0; i < lengthBytes; i++) {
                    parsedLength = (parsedLength << 8) | (data[offset++] & 0xff);
                }
                if (parsedLength > Integer.MAX_VALUE) {
                    throw new IOException("DER-Element ist zu groß.");
                }
                length = (int) parsedLength;
            }
            if (length > data.length - offset) {
                throw new IOException("DER-Element ist abgeschnitten.");
            }
            byte[] value = new byte[length];
            System.arraycopy(data, offset, value, 0, length);
            offset += length;
            return new DerElement(tag, value);
        }
    }

    private static final class DerElement {
        private final int tag;
        private final byte[] value;

        private DerElement(int tag, byte[] value) {
            this.tag = tag;
            this.value = value;
        }
    }

    private static final class ChainResult {
        private final List<X509Certificate> chain;
        private final boolean complete;

        private ChainResult(List<X509Certificate> chain, boolean complete) {
            this.chain = chain;
            this.complete = complete;
        }
    }

    private static final class PemContents {
        private final byte[] privateKeyBytes;
        private final List<X509Certificate> certificates;

        private PemContents(byte[] privateKeyBytes, List<X509Certificate> certificates) {
            this.privateKeyBytes = privateKeyBytes;
            this.certificates = certificates;
        }
    }

    private static final class CertificateMaterial implements HttpSessionBindingListener {
        private final byte[] privateKeyPem;
        private final byte[] serverCertificatePem;
        private final byte[] chainPem;
        private final byte[] workspacePem;
        private final String subject;
        private final String validUntil;
        private final String privateKeyAlgorithm;
        private final int chainCount;
        private final List<X509Certificate> chainCertificates;
        private final boolean chainComplete;
        private final boolean inspectionOnly;
        private final boolean privateKeyMatches;
        private final boolean allCertificatesUsed;
        private final boolean certificatesCurrentlyValid;

        private CertificateMaterial(byte[] privateKeyPem, byte[] serverCertificatePem, byte[] chainPem,
                                    byte[] workspacePem, String subject, String validUntil,
                                    String privateKeyAlgorithm,
                                    List<X509Certificate> chainCertificates, boolean chainComplete,
                                    boolean inspectionOnly, boolean privateKeyMatches,
                                    boolean allCertificatesUsed, boolean certificatesCurrentlyValid) {
            this.privateKeyPem = privateKeyPem;
            this.serverCertificatePem = serverCertificatePem;
            this.chainPem = chainPem;
            this.workspacePem = workspacePem;
            this.subject = subject;
            this.validUntil = validUntil;
            this.privateKeyAlgorithm = privateKeyAlgorithm;
            this.chainCertificates = new ArrayList<X509Certificate>(chainCertificates);
            this.chainCount = chainCertificates.size() - 1;
            this.chainComplete = chainComplete;
            this.inspectionOnly = inspectionOnly;
            this.privateKeyMatches = privateKeyMatches;
            this.allCertificatesUsed = allCertificatesUsed;
            this.certificatesCurrentlyValid = certificatesCurrentlyValid;
        }

        private CertificateMaterial withChain(ChainResult chain) throws GeneralSecurityException, IOException {
            return createMaterial(inspectionOnly ? new byte[0] : privateKeyPem.clone(),
                    privateKeyAlgorithm, chain, inspectionOnly, privateKeyMatches,
                    allCertificatesUsed);
        }

        @Override
        public void valueBound(HttpSessionBindingEvent event) {
        }

        @Override
        public void valueUnbound(HttpSessionBindingEvent event) {
            java.util.Arrays.fill(privateKeyPem, (byte) 0);
            java.util.Arrays.fill(serverCertificatePem, (byte) 0);
            java.util.Arrays.fill(chainPem, (byte) 0);
            java.util.Arrays.fill(workspacePem, (byte) 0);
        }
    }
}
