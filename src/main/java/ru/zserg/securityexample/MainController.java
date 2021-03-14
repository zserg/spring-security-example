package ru.zserg.securityexample;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/api/v1")
public class MainController {

    @GetMapping("/auth")
    public String auth(){
        return "Auth\n";
    }

    @GetMapping("/hello")
    public String hello(){
        return "Hello\n";
    }
}


