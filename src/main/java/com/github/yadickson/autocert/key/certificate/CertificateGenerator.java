/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert.key.certificate;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import javax.inject.Named;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.github.yadickson.autocert.key.provider.Provider;
import com.github.yadickson.autocert.parameters.InputInformation;
import com.github.yadickson.autocert.parameters.Parameters;

/**
 *
 * @author Yadickson Soto
 */
@Named
public class CertificateGenerator {

    /**
     * DN prefix.
     */
    private static final String PREFIX = "cn=";

    private static final SecureRandom secureRandom = new SecureRandom();
    
    private InputInformation inputInformation;

    public Certificate execute(
            final Parameters parameters,
            final Provider provider,
            final KeyPair keyPair
    ) {

        try {

            setInputInformation(parameters);
            return createCertificate(keyPair, provider);

        } catch (OperatorCreationException | CertificateException | RuntimeException ex) {
            throw new CertificateGeneratorException(ex);
        }
    }

    private void setInputInformation(final Parameters parameters) {
        this.inputInformation = parameters.getInput();
    }

    private Certificate createCertificate(final KeyPair keyPair, final Provider provider) throws OperatorCreationException, CertificateException {
        final PrivateKey privateKey = keyPair.getPrivate();
        final PublicKey publicKey = keyPair.getPublic();
        final byte[] encode = publicKey.getEncoded();
        
        X500Name issuer = new X500Name(PREFIX + inputInformation.getIssuer());
        X500Name subject = new X500Name(PREFIX + inputInformation.getSubject());
        
        BigInteger randomNumber = new BigInteger(64, secureRandom);
        
        Date notBefore = Date.from(LocalDate.now().atStartOfDay().toInstant(ZoneOffset.UTC));
        Date notAfter = Date.from(LocalDate.now().plus(inputInformation.getYears(), ChronoUnit.YEARS).atStartOfDay().toInstant(ZoneOffset.UTC));
        
        SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(encode);
        
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                issuer,
                randomNumber,
                notBefore,
                notAfter,
                subject,
                subPubKeyInfo
        );
        
        final ContentSigner signer = new JcaContentSignerBuilder(inputInformation.getSignature())
                .setProvider(provider.getProvider())
                .build(privateKey);
        
        final X509CertificateHolder holder = builder.build(signer);
        
        return new JcaX509CertificateConverter()
                .setProvider(provider.getProvider())
                .getCertificate(holder);
    }
}
