package com.vc.auth_backend;

import com.vc.auth_backend.config.EmbeddedRedisConfig;
import com.vc.auth_backend.modules.email.EmailProvider;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@SpringBootTest
@Import(EmbeddedRedisConfig.class)
class AuthApplicationTests {

	@MockitoBean
	EmailProvider emailProvider;

	@Test
	void contextLoads() {
	}

}
