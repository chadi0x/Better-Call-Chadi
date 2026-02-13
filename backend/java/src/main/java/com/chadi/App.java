package com.chadi;

import io.javalin.Javalin;
import java.util.Map;

public class App {
    public static void main(String[] args) {
        Javalin app = Javalin.create().start(8002);

        app.get("/api/status", ctx -> {
            ctx.json(Map.of(
                "status", "ok",
                "service", "java",
                "message", "Hello from Java Backend!"
            ));
        });
    }
}
