package com.vc.auth_backend.modules.email;
import com.vc.auth_backend.shared.exception.EmailDeliveryException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.util.Map;

@Slf4j
@Component
public class ResendEmailProvider implements EmailProvider {

    private static final String RESEND_API_URL = "https://api.resend.com/emails";

    private final RestClient restClient;

    @Value("${app.email.from}")
    private String fromAddress;

    public ResendEmailProvider(@Value("${resend.api-key}") String apiKey) {
        this.restClient = RestClient.builder()
                .baseUrl(RESEND_API_URL)
                .defaultHeader(HttpHeaders.AUTHORIZATION, "Bearer " + apiKey)
                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .build();
    }

    @Override
    public void send(String to, String subject, String body) {
        log.debug("Sending email via Resend to={} subject='{}'", to, subject);
        Map<String, Object> payload = Map.of(
                "from",    fromAddress,
                "to",      new String[]{ to },
                "subject", subject,
                "html",    body
        );

        try {
            restClient.post()
                    .body(payload)
                    .retrieve()
                    .toBodilessEntity();
            log.info("Email sent successfully via Resend to={}", to);
        } catch (RestClientException ex) {
            log.error("Resend API call failed for to={}: {}", to, ex.getMessage());
            throw new EmailDeliveryException(
                    "Could not send email at this time. Please try again later.", ex);
        }
    }
}
