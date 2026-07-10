package com.vc.auth_backend.modules.email.template;

import org.springframework.stereotype.Component;

@Component
public class EmailVerificationTemplate {
    public String build(String code, int minutesValid) {
        return """
                <!DOCTYPE html>
                <html lang="es">
                <head>
                  <meta charset="UTF-8">
                  <meta name="viewport" content="width=device-width, initial-scale=1.0">
                  <title>Verifica tu correo electrónico</title>
                </head>
                <body style="margin:0;padding:0;background:#f4f4f5;font-family:Arial,Helvetica,sans-serif;">
                  <table width="100%%" cellpadding="0" cellspacing="0" style="background:#f4f4f5;padding:40px 0;">
                    <tr>
                      <td align="center">
                        <table width="480" cellpadding="0" cellspacing="0"
                               style="background:#ffffff;border-radius:12px;overflow:hidden;
                                      box-shadow:0 1px 4px rgba(0,0,0,0.08);">
                
                          <!-- Header -->
                          <tr>
                            <td style="background:#18181b;padding:28px 40px;">
                              <p style="margin:0;color:#ffffff;font-size:18px;font-weight:600;">
                                Auth Backend
                              </p>
                            </td>
                          </tr>
                
                          <!-- Body -->
                          <tr>
                            <td style="padding:36px 40px 24px;">
                              <h1 style="margin:0 0 8px;font-size:22px;font-weight:600;color:#18181b;">
                                Verifica tu correo electrónico
                              </h1>
                              <p style="margin:0 0 28px;font-size:15px;color:#52525b;line-height:1.6;">
                                Gracias por registrarte. Usa el siguiente código para confirmar
                                que este correo te pertenece:
                              </p>
                
                              <table width="100%%" cellpadding="0" cellspacing="0" style="margin-bottom:28px;">
                                <tr>
                                  <td align="center"
                                      style="background:#f4f4f5;border-radius:8px;padding:24px;
                                             font-size:36px;font-weight:700;letter-spacing:10px;
                                             color:#18181b;font-family:Courier New,monospace;">
                                    %s
                                  </td>
                                </tr>
                              </table>
                
                              <p style="margin:0 0 8px;font-size:14px;color:#71717a;">
                                Este código es válido por <strong>%d minutos</strong>.
                              </p>
                              <p style="margin:0;font-size:14px;color:#71717a;">
                                Si no creaste esta cuenta, puedes ignorar este mensaje.
                              </p>
                            </td>
                          </tr>
                
                          <!-- Footer -->
                          <tr>
                            <td style="padding:20px 40px 28px;border-top:1px solid #f4f4f5;">
                              <p style="margin:0;font-size:12px;color:#a1a1aa;">
                                Este es un mensaje automático. Por favor no respondas a este email.
                              </p>
                            </td>
                          </tr>
                
                        </table>
                      </td>
                    </tr>
                  </table>
                </body>
                </html>
                """.formatted(code, minutesValid);
    }

    public String subject() {
        return "Verifica tu correo electrónico";
    }
}
