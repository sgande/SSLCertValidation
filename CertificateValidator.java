package com.samsung.knox.mdm.gateway.validator;

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

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;


public class CertificateValidator {
	
	private static final Logger logger = Logger.getLogger(CertificateValidator.class);
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
	}

