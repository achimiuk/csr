package pl.sygnity.sbe.security.auth;

import sun.security.util.DerOutputStream;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X500Name;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.util.Base64;

public class GenerateCSR {


    public void createCSR() {
        // generate RSA key pair
        KeyPair keypair = null;
        try {
            keypair = generateKeyPair();

            // create Certficate Request Info
            X500Name x500Name = new X500Name("CN=Test,OU=Test,O=Test,L=Test,S=Test,C=Test");
            byte[] certReqInfo = createCertificationRequestInfo(x500Name, keypair.getPublic());

            // generate Signature over Certficate Request Info
            String algorithm = "SHA1WithRSA";
            Signature signature = Signature.getInstance(algorithm);
            signature.initSign(keypair.getPrivate());
            signature.update(certReqInfo);
            byte[] certReqInfoSignature = signature.sign();

            // create PKCS#10 Certificate Signing Request (CSR)
            byte[] csrDEREncoded = createCertificationRequestValue(certReqInfo, algorithm, certReqInfoSignature);
            String csrPEMEncoded = createPEMFormat(csrDEREncoded);

            // write to file
            writeToFile(csrDEREncoded, "/tmp/csr.der");
            writeToFile(csrPEMEncoded.getBytes(), "/tmp/csr.pem");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    private String createPEMFormat(byte[] data) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final PrintStream ps = new PrintStream(out);
        ps.println("-----BEGIN NEW CERTIFICATE REQUEST-----");
        ps.println(Base64.getMimeEncoder().encodeToString(data));
        ps.println("-----END NEW CERTIFICATE REQUEST-----");
        return out.toString();
    }

    private byte[] createCertificationRequestValue(byte[] certReqInfo, String algorithm, byte[] signature) throws IOException, NoSuchAlgorithmException {
        final DerOutputStream der1 = new DerOutputStream();
        der1.write(certReqInfo);

        // add signature algorithm identifier, and a digital signature on the certification request information
        AlgorithmId.get(algorithm).encode(der1);
        der1.putBitString(signature);

        // final DER encoded output
        final DerOutputStream der2 = new DerOutputStream();
        der2.write((byte) 48, der1);
        return der2.toByteArray();
    }

    private byte[] createCertificationRequestInfo(X500Name x500Name, PublicKey aPublic) throws IOException {
        final DerOutputStream der1 = new DerOutputStream();
        der1.putInteger(BigInteger.ZERO);
        x500Name.encode(der1);
        der1.write(aPublic.getEncoded());

        // der encoded certificate request info
        final DerOutputStream der2 = new DerOutputStream();
        der2.write((byte) 48, der1);
        return der2.toByteArray();
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());
        KeyPair keypair = keyGen.generateKeyPair();
        return keypair;
    }

    private static void writeToFile(byte[] data, String file) throws FileNotFoundException, IOException {
        try (FileOutputStream out = new FileOutputStream(file)) {
            out.write(data);
        }
    }
}
