package com.vc.auth_backend.modules.auth.service;

import dev.samstevens.totp.code.*;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class TotpService {
    @Value("${app.2fa.issuer:AuthBackend}")
    private String issuer;

    @Value("${app.2fa.digits:6}")
    private int digits;

    @Value("${app.2fa.period:30}")
    private int period;

    // Genera un secreto Base32 de 20 bytes (160 bits)
    public String generateSecret(){
        SecretGenerator generator = new DefaultSecretGenerator(20);
        return generator.generate();
    }

    // Retorna el objeto QrData que contiene toda la configuración
    public QrData generateQrData(String email, String secret) {
        return new QrData.Builder()
                .label(email)
                .secret(secret)
                .issuer(issuer)
                .algorithm(HashingAlgorithm.SHA1)
                .digits(digits)
                .period(period)
                .build();
    }

    public String getQrUri(QrData data) {
        return data.getUri();
    }

    // Genera PNG del QR (arreglo de bytes)
    public byte[] generateQrPng(QrData data) {
        try {
            QrGenerator generator = new ZxingPngQrGenerator();
            return generator.generate(data);
        } catch (QrGenerationException e) {
            throw new IllegalStateException("Error generating QR code", e);
        }
    }

    public boolean verifyCode(String secret, String code) {
        TimeProvider timeProvider = new SystemTimeProvider();
        CodeGenerator codeGenerator = new DefaultCodeGenerator();
        // Permite un pequeño margen de tiempo por si los relojes están desincronizados
        CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
        return verifier.isValidCode(secret, code);
    }
}
