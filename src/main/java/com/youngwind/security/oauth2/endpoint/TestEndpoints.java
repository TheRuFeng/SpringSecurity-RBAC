package com.youngwind.security.oauth2.endpoint;

import ch.qos.logback.core.util.ExecutorServiceUtil;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class TestEndpoints {

    @PreAuthorize("hasAuthority('testHasAuthority')")
    @GetMapping("/hasAuthority")
    public String testHasAuthority() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // tips:用户信息存在ThreadLocal里，异步线程无法获取用户信息上下文
        ExecutorServiceUtil.newExecutorService().execute(() -> {
            Authentication authentication2 = SecurityContextHolder.getContext().getAuthentication();
            System.out.println(authentication2);
        });
        return authentication.getPrincipal().toString();
    }

    @GetMapping("/authenticated")
    public String testAuthenticated() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication.getPrincipal().toString();
    }

}
