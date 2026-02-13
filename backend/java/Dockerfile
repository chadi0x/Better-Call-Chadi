# Build stage
FROM maven:3.9-eclipse-temurin-17 AS builder
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn package -DskipTests

# Runtime stage
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=builder /app/target/java-backend-1.0-SNAPSHOT.jar app.jar
EXPOSE 8002
CMD ["java", "-jar", "app.jar"]
