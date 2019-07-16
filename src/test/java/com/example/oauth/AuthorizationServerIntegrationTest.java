package com.example.oauth;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.util.Base64Utils;
import org.springframework.web.reactive.function.BodyInserters;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class AuthorizationServerIntegrationTest {

  @Autowired
  protected WebTestClient webClient;

  @Test
  public void test() {
    String token = webClient.post()
        .uri("/spring-oauth/oauth/token")
        .header("Authorization", basicAuthorizationHeader("client", "secret"))
        .body(formBody("resourceOwner", "password"))
        .exchange()
        .expectStatus()
        .isOk()
        .expectBody(String.class)
        .returnResult()
        .getResponseBody();

    assertThat(token).contains("access_token");
    System.out.println("Token: " + token);
  }

  private BodyInserters.FormInserter<String> formBody(String username, String password) {
    return BodyInserters.fromFormData("grant_type", "password")
        .with("username", username)
        .with("password", password);
  }

  private String basicAuthorizationHeader(String username, String password) {
    return "Basic " + Base64Utils.encodeToString((username + ":" + password).getBytes());
  }
}
