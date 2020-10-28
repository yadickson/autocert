/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert.writer.publickey;

import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.security.spec.EncodedKeySpec;
import java.util.Base64;
import javax.inject.Named;
import javax.inject.Singleton;

/**
 *
 * @author Yadickson Soto
 */
@Named
@Singleton
public class PublicKeyWriter {
        
    public void execute(
            final String filePath,
            final EncodedKeySpec publicKey
    ) {

        try (Writer writer = new FileWriter(filePath)) {

            final byte[] encode = publicKey.getEncoded();
            final String base64 = Base64.getMimeEncoder().encodeToString(encode);
            
            writer.write("-----BEGIN PUBLIC KEY-----\n\r");
            writer.write(base64);
            writer.write("\n\r-----END PUBLIC KEY-----");

        } catch (RuntimeException | IOException ex) {
            throw new PublicKeyWriterException(ex);
        }
    }

}
