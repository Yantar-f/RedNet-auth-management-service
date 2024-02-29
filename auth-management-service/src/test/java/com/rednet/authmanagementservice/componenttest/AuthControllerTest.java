package com.rednet.authmanagementservice.componenttest;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rednet.authmanagementservice.config.AccessTokenConfig;
import com.rednet.authmanagementservice.config.RefreshTokenConfig;
import com.rednet.authmanagementservice.config.RegistrationTokenConfig;
import com.rednet.authmanagementservice.controller.AuthController;
import com.rednet.authmanagementservice.entity.Session;
import com.rednet.authmanagementservice.exception.InvalidAccountDataException;
import com.rednet.authmanagementservice.exception.InvalidRegistrationDataException;
import com.rednet.authmanagementservice.exception.OccupiedValueException;
import com.rednet.authmanagementservice.exception.handler.GlobalExceptionHandler;
import com.rednet.authmanagementservice.model.RegistrationCredentials;
import com.rednet.authmanagementservice.model.RegistrationVerificationData;
import com.rednet.authmanagementservice.model.SessionDTO;
import com.rednet.authmanagementservice.payload.request.SigninRequestBody;
import com.rednet.authmanagementservice.payload.request.SignupRequestBody;
import com.rednet.authmanagementservice.payload.response.SignupResponseBody;
import com.rednet.authmanagementservice.service.AuthService;
import com.rednet.authmanagementservice.util.CookieUtil;
import jakarta.servlet.http.Cookie;
import org.instancio.Instancio;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.ResponseCookie;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.instancio.Instancio.create;
import static org.instancio.Select.field;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_ATOM_XML;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.APPLICATION_PROBLEM_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(excludeAutoConfiguration = SecurityAutoConfiguration.class, useDefaultFilters = false)
@AutoConfigureMockMvc(print = MockMvcPrint.SYSTEM_OUT, addFilters = false)
@Import({AuthController.class,
         RefreshTokenConfig.class,
         RegistrationTokenConfig.class,
         AccessTokenConfig.class,
         GlobalExceptionHandler.class})
public class AuthControllerTest {
    @MockBean
    AccessTokenConfig accessTokenConfig;

    @MockBean
    RegistrationTokenConfig registrationTokenConfig;

    @MockBean
    RefreshTokenConfig refreshTokenConfig;

    @MockBean
    CookieUtil cookieUtil;

    @MockBean
    AuthService authService;

    @Autowired
    AuthController authController;

    @Autowired
    MockMvc mvc;

    @Autowired
    ObjectMapper objectMapper;

    @Test
    public void Creating_registration_is_successful() throws Exception {
        SignupRequestBody requestBody = Instancio.of(SignupRequestBody.class)
                .generate(field(SignupRequestBody::password), g -> g.string().minLength(8).maxLength(100))
                .generate(field(SignupRequestBody::secretWord), g -> g.string().minLength(8).maxLength(100))
                .set(field(SignupRequestBody::email), generateEmail())
                .create();

        RegistrationCredentials expectedCredentials = create(RegistrationCredentials.class);
        ResponseCookie expectedCookie = create(ResponseCookie.class);

        when(authService.register(eq(requestBody)))
                .thenReturn(expectedCredentials);

        when(cookieUtil.createRegistrationTokenCookie(eq(expectedCredentials.registrationToken())))
                .thenReturn(expectedCookie);

        MockHttpServletResponse result = mvc.perform(post("/signup")
                        .content(objectMapper.writeValueAsString(requestBody))
                        .contentType(APPLICATION_JSON))
                .andExpect(status().is2xxSuccessful())
                .andExpect(content().contentType(APPLICATION_JSON))
                .andReturn().getResponse();

        String responseBody = result.getContentAsString();
        Cookie actualCookie = result.getCookie(expectedCookie.getName());
        String actualRegistrationID = objectMapper.readValue(responseBody, SignupResponseBody.class).registrationID();

        assertNotNull(actualCookie);
        assertEquals(expectedCookie.getValue(), actualCookie.getValue());
        assertEquals(expectedCredentials.registrationID(), actualRegistrationID);
    }

    @Test
    public void Creating_registration_with_invalid_content_type_is_not_successful() throws Exception {
        SignupRequestBody requestBody = create(SignupRequestBody.class);

        mvc.perform(post("/signup")
                        .content(objectMapper.writeValueAsString(requestBody))
                        .contentType(APPLICATION_ATOM_XML))
                .andExpect(status().isUnsupportedMediaType())
                .andExpect(content().contentType(APPLICATION_PROBLEM_JSON));

        verify(authService, never())
                .register(eq(requestBody));
    }

    @Test
    public void Creating_registration_without_content_type_is_not_successful() throws Exception {
        SignupRequestBody requestBody = create(SignupRequestBody.class);

        mvc.perform(post("/signup")
                        .content(objectMapper.writeValueAsString(requestBody)))
                .andExpect(status().isUnsupportedMediaType())
                .andExpect(content().contentType(APPLICATION_PROBLEM_JSON));

        verify(authService, never())
                .register(eq(requestBody));
    }

    @ParameterizedTest
    @MethodSource("signupRequestBodyStringFields")
    public void Creating_registration_with_blank_string_field_is_not_successful(String fieldName) throws Exception {
        SignupRequestBody requestBody = Instancio.of(SignupRequestBody.class)
                .set(field(fieldName), "")
                .create();

        mvc.perform(post("/signup")
                        .content(objectMapper.writeValueAsString(requestBody))
                        .contentType(APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(APPLICATION_PROBLEM_JSON));

        verify(authService, never())
                .register(eq(requestBody));
    }

    private static List<String> signupRequestBodyStringFields() {
        List<String> list = Arrays.stream(SignupRequestBody.class.getDeclaredFields())
                .filter(field -> field.getType() == String.class)
                .map(Field::getName)
                .toList();

        if (list.isEmpty()) throw new RuntimeException("No fields");

        return list;
    }

    @ParameterizedTest
    @MethodSource("signupRequestBodyFields")
    public void Creating_registration_with_nullable_field_is_not_successful(String fieldName) throws Exception {
        SignupRequestBody requestBody = Instancio.of(SignupRequestBody.class)
                .ignore(field(fieldName))
                .create();

        mvc.perform(post("/signup")
                        .content(objectMapper.writeValueAsString(requestBody))
                        .contentType(APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(APPLICATION_PROBLEM_JSON));

        verify(authService, never())
                .register(eq(requestBody));
    }

    private static List<String> signupRequestBodyFields() {
        return Arrays.stream(SignupRequestBody.class.getDeclaredFields())
                .map(Field::getName)
                .toList();
    }

    @Test
    public void Creating_registration_with_occupied_values_is_not_successful() throws Exception {
        SignupRequestBody requestBody = Instancio.of(SignupRequestBody.class)
                .generate(field(SignupRequestBody::password), g -> g.string().minLength(8).maxLength(100))
                .generate(field(SignupRequestBody::secretWord), g -> g.string().minLength(8).maxLength(100))
                .set(field(SignupRequestBody::email), generateEmail())
                .create();

        when(authService.register(eq(requestBody)))
                .thenThrow(OccupiedValueException.class);

        mvc.perform(post("/signup")
                        .contentType(APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestBody)))
                .andExpect(status().isConflict())
                .andExpect(content().contentType(APPLICATION_PROBLEM_JSON));
    }

    @Test
    public void Creating_registration_with_too_short_password_is_not_successful() throws Exception {
        SignupRequestBody requestBody = Instancio.of(SignupRequestBody.class)
                .generate(field(SignupRequestBody::password), g -> g.string().maxLength(7))
                .generate(field(SignupRequestBody::secretWord), g -> g.string().minLength(8).maxLength(100))
                .set(field(SignupRequestBody::email), generateEmail())
                .create();

        mvc.perform(post("/signup")
                        .contentType(APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestBody)))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(APPLICATION_PROBLEM_JSON));

        verify(authService, never())
                .register(eq(requestBody));
    }

    @Test
    public void Creating_registration_with_too_long_password_is_not_successful() throws Exception {
        SignupRequestBody requestBody = Instancio.of(SignupRequestBody.class)
                .generate(field(SignupRequestBody::password), g -> g.string().minLength(201))
                .generate(field(SignupRequestBody::secretWord), g -> g.string().minLength(8).maxLength(100))
                .set(field(SignupRequestBody::email), generateEmail())
                .create();

        mvc.perform(post("/signup")
                        .contentType(APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestBody)))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(APPLICATION_PROBLEM_JSON));

        verify(authService, never())
                .register(eq(requestBody));
    }

    @Test
    public void Creating_registration_with_too_short_secret_word_is_not_successful() throws Exception {
        SignupRequestBody requestBody = Instancio.of(SignupRequestBody.class)
                .generate(field(SignupRequestBody::password), g -> g.string().minLength(8).maxLength(199))
                .generate(field(SignupRequestBody::secretWord), g -> g.string().maxLength(7))
                .set(field(SignupRequestBody::email), generateEmail())
                .create();

        mvc.perform(post("/signup")
                        .contentType(APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestBody)))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(APPLICATION_PROBLEM_JSON));

        verify(authService, never())
                .register(eq(requestBody));
    }

    @Test
    public void Creating_registration_with_too_long_secret_word_is_not_successful() throws Exception {
        SignupRequestBody requestBody = Instancio.of(SignupRequestBody.class)
                .generate(field(SignupRequestBody::password), g -> g.string().minLength(8).maxLength(199))
                .generate(field(SignupRequestBody::secretWord), g -> g.string().minLength(101))
                .set(field(SignupRequestBody::email), generateEmail())
                .create();

        mvc.perform(post("/signup")
                        .contentType(APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestBody)))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(APPLICATION_PROBLEM_JSON));

        verify(authService, never())
                .register(eq(requestBody));
    }

    @Test
    public void Creating_registration_with_invalid_email_is_not_successful() throws Exception {
        SignupRequestBody requestBody = Instancio.of(SignupRequestBody.class)
                .generate(field(SignupRequestBody::password), g -> g.string().minLength(8).maxLength(199))
                .generate(field(SignupRequestBody::secretWord), g -> g.string().minLength(8).maxLength(99))
                .create();

        mvc.perform(post("/signup")
                        .contentType(APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestBody)))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(APPLICATION_PROBLEM_JSON));

        verify(authService, never())
                .register(eq(requestBody));
    }

    @Test
    public void Login_is_successful() throws Exception {
        SigninRequestBody requestBody = create(SigninRequestBody.class);
        Session session = create(Session.class);
        SessionDTO expectedSessionDTO = new SessionDTO(session);
        ResponseCookie expectedAccessTokenCookie = create(ResponseCookie.class);
        ResponseCookie expectedRefreshTokenCookie = create(ResponseCookie.class);

        when(authService.login(eq(requestBody)))
                .thenReturn(session);

        when(accessTokenConfig.getCookieName())
                .thenReturn(expectedAccessTokenCookie.getName());

        when(refreshTokenConfig.getCookieName())
                .thenReturn(expectedRefreshTokenCookie.getName());

        when(cookieUtil.createAccessTokenCookie(eq(session.getAccessToken())))
                .thenReturn(expectedAccessTokenCookie);

        when(cookieUtil.createRefreshTokenCookie(eq(session.getRefreshToken())))
                .thenReturn(expectedRefreshTokenCookie);

        MockHttpServletResponse response = mvc.perform(post("/signin")
                        .content(objectMapper.writeValueAsString(requestBody))
                        .contentType(APPLICATION_JSON))
                .andExpect(status().is2xxSuccessful())
                .andExpect(content().contentType(APPLICATION_JSON))
                .andReturn().getResponse();

        SessionDTO actualSessionDTO = objectMapper.readValue(response.getContentAsString(), SessionDTO.class);
        Cookie actualAccessTokenCookie = response.getCookie(expectedAccessTokenCookie.getName());
        Cookie actualRefreshTokenCookie = response.getCookie(expectedRefreshTokenCookie.getName());

        assertNotNull(actualAccessTokenCookie);
        assertNotNull(actualRefreshTokenCookie);

        assertEquals(expectedSessionDTO, actualSessionDTO);
        assertEquals(expectedAccessTokenCookie.getValue(), actualAccessTokenCookie.getValue());
        assertEquals(expectedRefreshTokenCookie.getValue(), actualRefreshTokenCookie.getValue());

        verify(authService).login(eq(requestBody));
    }

    @Test
    public void Login_with_invalid_content_type_is_not_successful() throws Exception {
        SigninRequestBody requestBody = create(SigninRequestBody.class);

        mvc.perform(post("/signin")
                        .content(objectMapper.writeValueAsString(requestBody))
                        .contentType(APPLICATION_ATOM_XML))
                .andExpect(status().isUnsupportedMediaType())
                .andExpect(content().contentType(APPLICATION_PROBLEM_JSON));

        verify(authService, never())
                .login(any());
    }

    @Test
    public void Login_without_content_type_is_not_successful() throws Exception {
        SigninRequestBody requestBody = create(SigninRequestBody.class);

        mvc.perform(post("/signin")
                        .content(objectMapper.writeValueAsString(requestBody)))
                .andExpect(status().isUnsupportedMediaType())
                .andExpect(content().contentType(APPLICATION_PROBLEM_JSON));

        verify(authService, never())
                .login(any());
    }

    @ParameterizedTest
    @MethodSource("signinStringFields")
    public void Login_with_blank_string_field_is_not_successful(String fieldName) throws Exception {
        SigninRequestBody requestBody = Instancio.of(SigninRequestBody.class)
                .set(field(fieldName), "")
                .create();

        mvc.perform(post("/signin")
                        .content(objectMapper.writeValueAsString(requestBody))
                        .contentType(APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(APPLICATION_PROBLEM_JSON));

        verify(authService, never())
                .login(any());
    }

    private static List<String> signinStringFields() {
        return Arrays.stream(SigninRequestBody.class.getDeclaredFields())
                .filter(field -> field.getType().equals(String.class))
                .map(Field::getName)
                .toList();
    }

    @ParameterizedTest
    @MethodSource("signinFields")
    public void Login_with_nullable_field_not_successful(String fieldName) throws Exception {
        SigninRequestBody requestBody = Instancio.of(SigninRequestBody.class)
                .ignore(field(fieldName))
                .create();

        mvc.perform(post("/signin")
                        .content(objectMapper.writeValueAsString(requestBody))
                        .contentType(APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(APPLICATION_PROBLEM_JSON));

        verify(authService, never())
                .login(any());
    }

    private static List<String> signinFields() {
        return Arrays.stream(SigninRequestBody.class.getDeclaredFields())
                .filter(field -> field.getType().equals(String.class))
                .map(Field::getName)
                .toList();
    }

    @Test
    public void Login_with_invalid_credentials_is_not_successful() throws Exception {
        SigninRequestBody requestBody = create(SigninRequestBody.class);

        when(authService.login(eq(requestBody)))
                .thenThrow(InvalidAccountDataException.class);

        mvc.perform(post("/signin")
                        .content(objectMapper.writeValueAsString(requestBody))
                        .contentType(APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(APPLICATION_PROBLEM_JSON));
    }

    @Test
    public void Verifying_email_is_successful() throws Exception {
        RegistrationVerificationData verificationData = create(RegistrationVerificationData.class);
        Session expectedSession = create(Session.class);
        SessionDTO expectedSessionDTO = new SessionDTO(expectedSession);
        ResponseCookie expectedAccessTokenCookie = create(ResponseCookie.class);
        ResponseCookie expectedRefreshTokenCookie = create(ResponseCookie.class);
        ResponseCookie expectedRegistrationTokenCleaningCookie = create(ResponseCookie.class);
        String registrationTokenCookiePath = create(String.class);

        when(authService.verifyEmail(eq(verificationData)))
                .thenReturn(expectedSession);

        when(registrationTokenConfig.getCookieName())
                .thenReturn(expectedRegistrationTokenCleaningCookie.getName());

        when(registrationTokenConfig.getCookiePath())
                .thenReturn(registrationTokenCookiePath);

        when(cookieUtil.createAccessTokenCookie(eq(expectedSession.getAccessToken())))
                .thenReturn(expectedAccessTokenCookie);

        when(cookieUtil.createRefreshTokenCookie(eq(expectedSession.getRefreshToken())))
                .thenReturn(expectedRefreshTokenCookie);

        when(cookieUtil.createRegistrationTokenCleaningCookie())
                .thenReturn(expectedRegistrationTokenCleaningCookie);

        MockHttpServletResponse response = mvc.perform(post("/verify-email")
                        .contentType(APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(verificationData)))
                .andExpect(status().is2xxSuccessful())
                .andReturn().getResponse();

        Cookie actualAccessTokenCookie = response.getCookie(expectedAccessTokenCookie.getName());
        Cookie actualRefreshTokenCookie = response.getCookie(expectedRefreshTokenCookie.getName());
        SessionDTO actualSessionDTO = objectMapper.readValue(response.getContentAsString(), SessionDTO.class);

        assertNotNull(actualAccessTokenCookie);
        assertNotNull(actualRefreshTokenCookie);

        assertEquals(expectedAccessTokenCookie.getValue(), actualAccessTokenCookie.getValue());
        assertEquals(expectedRefreshTokenCookie.getValue(), actualRefreshTokenCookie.getValue());
        assertEquals(expectedSessionDTO, actualSessionDTO);

        verify(authService).verifyEmail(eq(verificationData));
    }

    @Test
    public void Verifying_email_with_invalid_content_type_is_not_successful() throws Exception {
        RegistrationVerificationData verificationData = create(RegistrationVerificationData.class);

        mvc.perform(post("/verify-email")
                        .contentType(APPLICATION_ATOM_XML)
                        .content(objectMapper.writeValueAsString(verificationData)))
                .andExpect(status().isUnsupportedMediaType())
                .andExpect(content().contentType(APPLICATION_PROBLEM_JSON));

        verify(authService, never())
                .verifyEmail(any());
    }

    @Test
    public void Verifying_email_without_content_type_is_not_successful() throws Exception {
        RegistrationVerificationData verificationData = create(RegistrationVerificationData.class);

        mvc.perform(post("/verify-email")
                        .content(objectMapper.writeValueAsString(verificationData)))
                .andExpect(status().isUnsupportedMediaType())
                .andExpect(content().contentType(APPLICATION_PROBLEM_JSON));

        verify(authService, never())
                .verifyEmail(any());
    }

    @ParameterizedTest
    @MethodSource("registrationVerificationDataStringFields")
    public void Verifying_email_with_blank_string_fields_is_not_successful(String fieldName) throws Exception {
        RegistrationVerificationData verificationData = Instancio.of(RegistrationVerificationData.class)
                .set(field(fieldName), "")
                .create();

        mvc.perform(post("/verify-email")
                        .content(objectMapper.writeValueAsString(verificationData))
                        .contentType(APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(APPLICATION_PROBLEM_JSON));

        verify(authService, never())
                .verifyEmail(any());
    }

    private static List<String> registrationVerificationDataStringFields() {
        return Arrays.stream(RegistrationVerificationData.class.getDeclaredFields())
                .filter(field -> field.getType().equals(String.class))
                .map(Field::getName)
                .toList();
    }

    @ParameterizedTest
    @MethodSource("registrationVerificationDataFields")
    public void Verifying_email_with_nullable_fields_is_not_successful(String fieldName) throws Exception {
        RegistrationVerificationData verificationData = Instancio.of(RegistrationVerificationData.class)
                .ignore(field(fieldName))
                .create();

        mvc.perform(post("/verify-email")
                        .content(objectMapper.writeValueAsString(verificationData))
                        .contentType(APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(APPLICATION_PROBLEM_JSON));

        verify(authService, never())
                .verifyEmail(any());
    }

    private static List<String> registrationVerificationDataFields() {
        return Arrays.stream(RegistrationVerificationData.class.getDeclaredFields())
                .map(Field::getName)
                .toList();
    }

    @Test
    public void Verifying_email_with_invalid_verification_data_is_not_successful() throws Exception {
        RegistrationVerificationData verificationData = create(RegistrationVerificationData.class);

        when(authService.verifyEmail(eq(verificationData)))
                .thenThrow(InvalidRegistrationDataException.class);

        mvc.perform(post("/verify-email")
                        .content(objectMapper.writeValueAsString(verificationData))
                        .contentType(APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(APPLICATION_PROBLEM_JSON));
    }

    @Test
    public void Resend_email_verification_is_successful() throws Exception {
        ResponseCookie expectedRegistrationTokenCookie = create(ResponseCookie.class);

        Cookie oldRegistrationTokenCookie = new Cookie(
                expectedRegistrationTokenCookie.getName(),
                create(String.class)
        );

        when(cookieUtil.extractRegistrationTokenFromCookies(any()))
                .thenReturn(Optional.of(oldRegistrationTokenCookie.getValue()));

        when(cookieUtil.createRegistrationTokenCookie(eq(expectedRegistrationTokenCookie.getValue())))
                .thenReturn(expectedRegistrationTokenCookie);

        when(authService.resendEmailVerification(eq(oldRegistrationTokenCookie.getValue())))
                .thenReturn(expectedRegistrationTokenCookie.getValue());

        MockHttpServletResponse response = mvc.perform(post("/resend-email-verification")
                        .cookie(oldRegistrationTokenCookie))
                .andExpect(status().is2xxSuccessful())
                .andReturn().getResponse();

        Cookie actualRegistrationTokenCookie = response.getCookie(expectedRegistrationTokenCookie.getName());

        assertNotNull(actualRegistrationTokenCookie);

        assertEquals(expectedRegistrationTokenCookie.getValue(), actualRegistrationTokenCookie.getValue());

        verify(authService)
                .resendEmailVerification(eq(oldRegistrationTokenCookie.getValue()));
    }

    @Test
    public void Resend_email_verification_with_invalid_registration_token_is_not_successful() throws Exception {
        Cookie registrationTokenCookie = create(Cookie.class);

        when(registrationTokenConfig.getCookieName())
                .thenReturn(registrationTokenCookie.getName());

        when(authService.resendEmailVerification(registrationTokenCookie.getValue()))
                .thenThrow(InvalidRegistrationDataException.class);

        mvc.perform(post("/resend-email-verification")
                        .cookie(registrationTokenCookie))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(APPLICATION_PROBLEM_JSON));
    }

    @Test
    public void Resend_email_verification_without_registration_token_is_not_successful() throws Exception {
        String registrationTokenCookieName = create(String.class);

        when(registrationTokenConfig.getCookieName())
                .thenReturn(registrationTokenCookieName);

        mvc.perform(post("/resend-email-verification"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(APPLICATION_PROBLEM_JSON));

        verify(authService, never())
                .resendEmailVerification(any());
    }

    @Test
    public void Logout_is_successful() throws Exception {
        Cookie refreshTokenCookie = create(Cookie.class);
        ResponseCookie refreshTokenCleaningCookie = create(ResponseCookie.class);
        ResponseCookie accessTokenCleaningCookie = create(ResponseCookie.class);

        when(cookieUtil.extractRefreshTokenFromCookies(
                argThat(cookies -> Arrays.asList(cookies).contains(refreshTokenCookie))))
                .thenReturn(Optional.of(refreshTokenCookie.getValue()));

        when(cookieUtil.createAccessTokenCleaningCookie())
                .thenReturn(accessTokenCleaningCookie);

        when(cookieUtil.createRefreshTokenCleaningCookie())
                .thenReturn(refreshTokenCleaningCookie);

        mvc.perform(post("/signout")
                        .cookie(refreshTokenCookie))
                .andExpect(status().is2xxSuccessful());

        verify(authService).logout(eq(refreshTokenCookie.getValue()));
    }

    @Test
    public void Logout_without_one_token_is_successful() throws Exception {

    }

    @Test
    public void Logout_without_token_pair_is_not_successful() throws Exception {

    }

    @Test
    public void Refreshing_session_is_successful() throws Exception {

    }

    @Test
    public void Refreshing_session_without_refresh_token_is_not_successful() throws Exception {

    }

    @Test
    public void Refreshing_session_with_invalid_refresh_token_is_not_successful() throws Exception {

    }

    private String generateEmail() {
        return create(String.class) + '@'+ create(String.class) + '.' + create(String.class);
    }
}
