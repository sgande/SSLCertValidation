package com.samsung.knox.mdm.gateway.profile;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.security.KeyStore;


import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.util.encoders.Base64;


public class Validator {

	final static String BEGIN = "-----BEGIN CERTIFICATE-----";
	final static String END = "-----END CERTIFICATE-----";
	
	private static  byte[] readPemBytes(String str) throws IOException
	  {
		 StringReader certStrReader = new StringReader(str);
		 BufferedReader pemReader = new BufferedReader(certStrReader);
		 
		 String line = pemReader.readLine();
		 if(line !=null) {
			 //chop BEGIN and END
			 if(line.startsWith(BEGIN)){
				 line = line.substring(BEGIN.length());
				}
			 if( line.endsWith(END)) {
				 line = line.substring(0,line.length()-END.length());
			 }
			 line.trim();
			 return Base64.decode(line.getBytes());
		 }

	        return null;
	    }
	 
	public static  X509Certificate readPem(String certStr) throws IOException, CertificateException  {
		
		X509Certificate  cert = null;

		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			ByteArrayInputStream bit = new ByteArrayInputStream(readPemBytes(certStr));
			cert = (X509Certificate)cf.generateCertificate(bit);
				
			return cert;
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw e;
		}
		
	}
		 
		
	
    public static boolean validateCertificateChain(List<String>  certsStr) throws Exception {
	
    	List<X509Certificate> certs = new ArrayList<X509Certificate>();
	try {
		//1. read certificates list 
		
		for( String cert : certsStr) {
			X509Certificate cert1 = readPem(cert);
		     if(cert != null) {
		    	 certs.add(cert1);
		     }
		}
		
		X509Certificate serverCert = null; 
		if(certs.size() >0) {
			serverCert = certs.get(0);
		}
		
		 //2. check intermediatery 
		/*
		 fis = new FileInputStream(certFilename);
		 BufferedInputStream interBuf = new BufferedInputStream(fis);
		 CertificateFactory cf = CertificateFactory.getInstance("X.509");
		 
		 @SuppressWarnings("unchecked")
		 Collection<X509Certificate> certs  = (Collection<X509Certificate>)cf.generateCertificates(interBuf);
		 Iterator<X509Certificate> certIter = certs.iterator();
		 X509Certificate serverCert = certIter.next();
		 /* printing certs 
		 Iterator<X509Certificate> certIt = certs.iterator();
			for (; certIt.hasNext();) {
		       System.out.println("==each=="+certIt.next().toString());
		 }
		 	 fis.close();
		 	 */
		 
	
		 
		// 3. Load the JDK's cacerts keystore file
		 System.setProperty("javax.net.ssl.trustStore","/usr/local/jdk/jre/lib/security/cacerts");
		 String filename = System.getProperty("javax.net.ssl.trustStore").replace('/', File.separatorChar);
		 FileInputStream is = new FileInputStream(filename);
		 KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		 char[] password = "changeit".toCharArray();
		 ks.load(is, password);

		 HashSet<X509Certificate> trustedRootCerts = new HashSet<X509Certificate>();
		 for (Enumeration<String> e = ks.aliases(); e.hasMoreElements();) {
		        trustedRootCerts.add((X509Certificate) ks.getCertificate(e.nextElement()));
		 }
		 
		 //4. Build CA chain path 
		// Create the selector that specifies the starting certificate
		X509CertSelector selector = new X509CertSelector();
		selector.setCertificate(serverCert);
		// Create the trust anchors (set of root CA certificates)
		Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
		for (X509Certificate trustedRootCert : trustedRootCerts) {
			trustAnchors.add(new TrustAnchor(trustedRootCert, null));
		}
		 
		 PKIXBuilderParameters pkixParams =new PKIXBuilderParameters(trustAnchors, selector);
		 // Disable CRL checks (this is done manually as additional step)
		 pkixParams.setRevocationEnabled(false);
		 // Specify a list of intermediate certificates
		 CertStore intermediateCertStore = CertStore.getInstance("Collection",new CollectionCertStoreParameters(certs));
		pkixParams.addCertStore(intermediateCertStore);

		// Build and verify the certification chain
		CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");
		PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) builder.build(pkixParams);
		System.out.println("=====Builder result:"+result.getCertPath().toString());
		 
		System.out.println("=====Builder result ends ==========");
		
		/*
		 //CertPath cp = cf.generateCertPath(mylist);
		 //System.out.println("Cert path:"+cp.toString());
		 PKIXParameters params = new PKIXParameters(ks);
		 ks.setCertificateEntry("inter1",certInters );
		 params.setRevocationEnabled(false); 
		 CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
		 PKIXCertPathValidatorResult res = (PKIXCertPathValidatorResult) cpv.validate(cp, params);
		 System.out.println(res.);
	     System.out.println(res.getPolicyTree().getValidPolicy());
*/
		 
		 System.out.println(serverCert);
			return true;
	} catch (CertPathBuilderException ex) {
		System.out.println(ex.getMessage());
		throw ex;
		}  catch (Exception ex) {
			System.out.println("Error verifying the certificate: ");
			throw ex;
		}       

	 }

	 public static void main(String args[]) {
	  List<String> certStr = new ArrayList<String>();
	  certStr.add("-----BEGIN CERTIFICATE-----MIIEsDCCA5igAwIBAgISESHYxRtyUbH2iqyQb84zq7+HMA0GCSqGSIb3DQEBBQUAMC4xETAPBgNVBAoTCEFscGhhU1NMMRkwFwYDVQQDExBBbHBoYVNTTCBDQSAtIEcyMB4XDTEzMTEwODE3MTEyMloXDTE0MTEwOTE3MTEyMlowPzEhMB8GA1UECxMYRG9tYWluIENvbnRyb2wgVmFsaWRhdGVkMRowGAYDVQQDFBEqLmIyYi1zYW5qb3NlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL1oNJZjmnNOV/OBkbwHm8lDCLHWhz/Shb0kLvr/W0vHWS8Usj4vi4guItrU2p1FhVjE7rFYZA3Ltir3EULOwS6rEpkISMspZChG//EF+1+k2X2EDIAaePvpswHPIDV9CSkA+tfHygOHIwv9nkCXDgFBt3cgPnlbWgZ6ryONwBFhncrMouyyoXEj/ly/gLgp/ITjZX4L2cVhrna2ERXj16Ro44NpUyYMxMUtW1mcV3wAtLVPX2+quDvvAvMjCOoMZCT3PsnPFtbdjQLs5fjFl32kCBfZeEo9w0wBtFkz6NZNq7WaRdi3iBpsEwfxPMtkdp2RfMzr5LqYG8SQy0XFtbECAwEAAaOCAbUwggGxMA4GA1UdDwEB/wQEAwIFoDBJBgNVHSAEQjBAMD4GBmeBDAECATA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAtBgNVHREEJjAkghEqLmIyYi1zYW5qb3NlLmNvbYIPYjJiLXNhbmpvc2UuY29tMAkGA1UdEwQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMDoGA1UdHwQzMDEwL6AtoCuGKWh0dHA6Ly9jcmwyLmFscGhhc3NsLmNvbS9ncy9nc2FscGhhZzIuY3JsMH8GCCsGAQUFBwEBBHMwcTA8BggrBgEFBQcwAoYwaHR0cDovL3NlY3VyZTIuYWxwaGFzc2wuY29tL2NhY2VydC9nc2FscGhhZzIuY3J0MDEGCCsGAQUFBzABhiVodHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vZ3NhbHBoYWcyMB0GA1UdDgQWBBQEMx43fsL4Q+GqkYaYDYic/bFM1DAfBgNVHSMEGDAWgBQU6hlV8A4NMsYfdDO3jmYaTBIxHjANBgkqhkiG9w0BAQUFAAOCAQEAvYEJC9913PEOMOwV52tIotbJTJZ+KVOqZajkQMB5X0ucqkTeT//1FnDJflS1RlVyN7OSOQEfOwtSRp5yuqu+Ns2VT2ouwf7OkWAsOK4UEAwUPhkHS9RAdQiMTK7P/9qn/LkKxerUOPn8xsFGcYnxWQB9zk9bl3h65WWX8lKJubx0mYy/OpaZm9pZWAx8pmCBvDVMTHs+V5VFgtaV+5uCHnZXMxNawR8LVdhcKAm+P3OTO+fxI4suCDbhI8NAhPrU+r6177x5cYWASofaexyb1cGc4kssl6K5m5q7omUGAokWPGCYkTXUW/nAk8OrbosrZ6EKBo7QTXkHdNvlE3gMnw==-----END CERTIFICATE-----");
	  certStr.add("-----BEGIN CERTIFICATE-----MIIELzCCAxegAwIBAgILBAAAAAABL07hNwIwDQYJKoZIhvcNAQEFBQAwVzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jvb3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw0xMTA0MTMxMDAwMDBaFw0yMjA0MTMxMDAwMDBaMC4xETAPBgNVBAoTCEFscGhhU1NMMRkwFwYDVQQDExBBbHBoYVNTTCBDQSAtIEcyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw/BliN8b3caChy/JC7pUxmM/RnWsSxQfmHKLHBD/CalSbi9l32WEP1+BstjxT9fwWrvJr9Ax3SZGKpme2KmjtrgHxMlx95WE79LqH1Sg5b7kQSFWMRBkfR5jjpxxXDygLt5n3MiaIPB1yLC2J4Hrlw3uIkWlwi80J+zgWRJRsx4F5Tgg0mlZelkXvhpLOQgSeTObZGj+WIHdiAxqulm0ryRPYeDK/Bda0jxyq6dMt7nqLeP0P5miTcgdWPh/UzWO1yKIt2F2CBMTaWawV1kTMQpwgiuT1/biQBXQHQFyxxNYalrsGYkWPODIjYYq+jfwNTLd7OX+gI73BWe0i0J1NQIDAQABo4IBIzCCAR8wDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFBTqGVXwDg0yxh90M7eOZhpMEjEeMEUGA1UdIAQ+MDwwOgYEVR0gADAyMDAGCCsGAQUFBwIBFiRodHRwczovL3d3dy5hbHBoYXNzbC5jb20vcmVwb3NpdG9yeS8wMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL2NybC5nbG9iYWxzaWduLm5ldC9yb290LmNybDA9BggrBgEFBQcBAQQxMC8wLQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL3Jvb3RyMTAfBgNVHSMEGDAWgBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0BAQUFAAOCAQEABjBCm89JAn6J6fWDWj0C87yyRt5KUO65mpBz2qBcJsqCrA6ts5T6KC6y5kk/UHcOlS9o82U8nxTyaGCStvwEDfakGKFpYA3jnWhbvJ4LOFmNIdoj+pmKCbkfpy61VWxH50Hs5uJ/r1VEOeCsdO5l0/qrUUgw8T53be3kD0CY7kd/jbZYJ82Sb2AjzAKbWSh4olGd0Eqc5ZNemI/L7z/K/uCvpMlbbkBYpZItvV1lVcW/fARB2aS1gOmUYAIQOGoICNdTHC2Tr8kTe9RsxDrE+4CsuzpOVHrNTrM+7fH8EU6f9fMUvLmxMc72qi+l+MPpZqmyIJ3E+LgDYqeF0RhjWw==-----END CERTIFICATE-----");	
	  try {
			//validateDomain("/home/sirisha/Desktop/certs-v4/intermediates.pem");
			 boolean validChian = validateCertificateChain( certStr);
			 System.out.println("Valid chain:"+validChian);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	}

