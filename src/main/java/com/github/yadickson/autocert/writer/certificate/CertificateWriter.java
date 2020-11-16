/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert.writer.certificate;

import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Base64;
import javax.inject.Named;

/**
 *
 * @author Yadickson Soto
 */
@Named
public class CertificateWriter {
        
    public void execute(
            final String filePath,
            final Certificate certificate
    ) {

        try (Writer writer = new FileWriter(filePath)) {

            final byte[] encode = certificate.getEncoded();
            final String base64 = Base64.getMimeEncoder().encodeToString(encode);
            
            writer.write("-----BEGIN CERTIFICATE-----\n\r");
            writer.write(base64);
            writer.write("\n\r-----END CERTIFICATE-----");

        } catch (CertificateEncodingException | IOException ex) {
            throw new CertificateWriterException(ex);
        }
    }

}
