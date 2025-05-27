package org.example.quoteservice;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Random;

@RestController
@RequestMapping("/quotes")
public class QuotesController {

    private final List<String> quotes = List.of(
            "There was no second chance. We all knew that. We had to get it right the first time.",
            "We had to figure out what the machine was doing. There was no manual, we wrote the manual",
            "The most dangerous phrase in the language is: ‘We’ve always done it this way."
    );

    @GetMapping("/random")
    public String randomQuote() {
        int index = new Random().nextInt(quotes.size());
        return quotes.get(index);
    }

}
