package org.example.jokeservice;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Random;

@RestController
@RequestMapping("/jokes")
public class JokesController {

    private final List<String> jokes = List.of(
            "I’m reading a book on anti-gravity, it’s impossible to put down.",
            "I once heard a joke about a pencil, but it had no point",
            "I don’t trust stairs, they’re always up to something."
    );

    @GetMapping("/random")
    public String randomJoke() {
        int index = new Random().nextInt(jokes.size());
        return jokes.get(index);
    }

}
