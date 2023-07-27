package org.jetlinks.pro.auth.captcha;

import com.wf.captcha.SpecCaptcha;
import com.wf.captcha.base.Captcha;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hswebframework.web.authorization.ReactiveAuthenticationManager;
import org.hswebframework.web.authorization.annotation.Authorize;
import org.hswebframework.web.authorization.events.AuthorizationBeforeEvent;
import org.hswebframework.web.authorization.events.AuthorizationDecodeEvent;
import org.hswebframework.web.authorization.events.AuthorizationFailedEvent;
import org.hswebframework.web.authorization.events.AuthorizationSuccessEvent;
import org.hswebframework.web.authorization.exception.AuthenticationException;
import org.hswebframework.web.authorization.simple.PlainTextUsernamePasswordAuthenticationRequest;
import org.hswebframework.web.exception.ValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.EventListener;
import org.springframework.data.redis.core.ReactiveRedisOperations;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

/**
 * 系统登录所需验证码，可在application.yml中配置。
 *
 * @author zhouhao
 * @see CaptchaProperties
 * @see ReactiveRedisOperations
 * @see AuthorizationDecodeEvent
 * @since 1.4
 */
@RestController
@Authorize(ignore = true)
@AllArgsConstructor
@RequestMapping("/authorize/captcha")
@Tag(name = "验证码接口")
public class CaptchaController {

    private final CaptchaProperties properties;

    private final ReactiveRedisOperations<String, String> redis;
    @Autowired
    private ApplicationEventPublisher eventPublisher;
    @Autowired
    private ReactiveAuthenticationManager authenticationManager;
    /**
     * 获取CaptchaProperties中的配置并返回CaptchaConfig
     * @return CaptchaConfig
     */
    @GetMapping("/config")
    @Operation(summary = "获取验证码相关配置信息")
    public Mono<CaptchaConfig> createCaptcha() {
        CaptchaConfig captchaConfig = new CaptchaConfig();
        captchaConfig.setEnabled(properties.isEnabled());
        captchaConfig.setType(properties.getType().name());

        return Mono.just(captchaConfig);
    }
    @PostMapping(
        value = {"/login"},
        consumes = {"application/json"}
    )
    @Authorize(
        ignore = true
    )
    @Operation(
        summary = "登录",
        description = "必要参数:username,password.根据配置不同,其他参数也不同,如:验证码等."
    )
    public Mono<Map<String, Object>> authorizeByJson(@Parameter(example = "{\"username\":\"admin\",\"password\":\"admin\"}") @RequestBody Mono<Map<String, Object>> parameter) {
        return this.doLogin(parameter);
    }

    private Mono<Map<String, Object>> doLogin(Mono<Map<String, Object>> parameter) {
        try {
            return parameter.flatMap((parameters) -> {
                String username_ = (String)parameters.get("username");
                String password_ = (String)parameters.get("password");
                Assert.hasLength(username_, "用户名不能为空");
                Assert.hasLength(password_, "密码不能为空");
                Function<String, Object> parameterGetter = parameters::get;
                return Mono.defer(() -> {
                    AuthorizationDecodeEvent decodeEvent = new AuthorizationDecodeEvent(username_, password_, parameterGetter);
                    return decodeEvent.publish(this.eventPublisher).then(Mono.defer(() -> {
                        String username = decodeEvent.getUsername();
                        String password = decodeEvent.getPassword();
                        AuthorizationBeforeEvent beforeEvent = new AuthorizationBeforeEvent(username, password, parameterGetter);
                        return beforeEvent.publish(this.eventPublisher).then(this.authenticationManager.authenticate(Mono.just(new PlainTextUsernamePasswordAuthenticationRequest(username, password))).switchIfEmpty(Mono.error(() -> {
                            return new AuthenticationException(AuthenticationException.ILLEGAL_PASSWORD, "密码错误");
                        })).flatMap((auth) -> {
                            AuthorizationSuccessEvent event = new AuthorizationSuccessEvent(auth, parameterGetter);
                            event.getResult().put("userId", auth.getUser().getId());
                            Mono var10000 = event.publish(this.eventPublisher);
                            event.getClass();
                            return var10000.then(Mono.fromCallable(event::getResult));
                        }));
                    }));
                }).onErrorResume((err) -> {
                    AuthorizationFailedEvent failedEvent = new AuthorizationFailedEvent(username_, password_, parameterGetter);
                    //failedEvent.setException(err);
                    return failedEvent.publish(this.eventPublisher).then(Mono.error(failedEvent.getException()));
                });
            });
        } catch (Throwable var3) {
            throw var3;
        }
    }
    /**
     * 获取验证码图片，并将验证码信息存入redis
     * @param width
     * @param height
     * @return
     */
    @GetMapping("/image")
    @Operation(summary = "获取验证码图片")
    public Mono<CaptchaInfo> createCaptcha(@RequestParam(defaultValue = "130")
                                           @Parameter(description = "宽度,默认130px") int width,
                                           @RequestParam(defaultValue = "40")
                                           @Parameter(description = "高度,默认40px") int height) {
        if (!properties.isEnabled()) {
            return Mono.empty();
        }
        SpecCaptcha captcha = new SpecCaptcha(width, height, 4);
        captcha.setCharType(Captcha.TYPE_DEFAULT);

        String base64 = captcha.toBase64();
        String key = UUID.randomUUID().toString();

        return redis
            .opsForValue()
            .set("captcha:" + key, captcha.text(), properties.getTtl())
            .thenReturn(new CaptchaInfo(key, base64));
    }

    /**
     * 开始授权时将发布该事件，此处订阅后等验证码进行验证
     * @param event
     */
    @EventListener
    public void handleAuthEvent(AuthorizationDecodeEvent event) {
        if (!properties.isEnabled()) {
            return;
        }
        String key = event.getParameter("verifyKey").map(String::valueOf).orElseThrow(() -> new ValidationException("验证码错误"));
        String code = event.getParameter("verifyCode").map(String::valueOf).orElseThrow(() -> new ValidationException("验证码错误"));
        String redisKey = "captcha:" + key;
        event.async(
            redis
                .opsForValue()
                .get(redisKey)
                .map(code::equalsIgnoreCase)
                .defaultIfEmpty(false)
                .flatMap(checked -> redis
                    .delete(redisKey)
                    .then(checked ? Mono.empty() : Mono.error(new ValidationException("验证码错误"))))
        );

    }


    @Getter
    @Setter
    @AllArgsConstructor
    @NoArgsConstructor
    public static class CaptchaInfo {
        @Schema(description = "验证码标识,登录时需要在参数[verifyKey]传入此值.")
        private String key;

        @Schema(description = "图片Base64,以data:image/png;base64,开头")
        private String base64;
    }

    @Getter
    @Setter
    @AllArgsConstructor
    @NoArgsConstructor
    public static class CaptchaConfig {
        @Schema(description = "是否开启验证码")
        private boolean enabled;

        @Schema(description = "验证码类型")
        private String type;
    }
}
