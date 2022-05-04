package me.whiteship.demospringsecurityform.form;

import me.whiteship.demospringsecurityform.common.SecurityLogger;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class SampleService {

    public void dashboard() {
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        System.out.println("===============+");
        System.out.println(userDetails.getUsername());

    }

    @Async
    public void asyncService() {
        SecurityLogger.log("Async Servuce");
        System.out.println("Async service is called.");
    }
}
