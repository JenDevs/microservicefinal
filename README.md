<pre>
To start the system, you must first build Docker images for each service. Open a terminal and run the following 
commands from each service’s root directory (where pom.xml is located):

Build Authorization Server
mvn spring-boot:build-image "-Dspring-boot.build-image.imageName=authservice:0.0.1-SNAPSHOT"

Build API Gateway
mvn spring-boot:build-image "-Dspring-boot.build-image.imageName=gateway:0.0.1-SNAPSHOT"

Build Joke Service
mvn spring-boot:build-image "-Dspring-boot.build-image.imageName=jokeservice:0.0.1-SNAPSHOT"

Build Quote Service
mvn spring-boot:build-image "-Dspring-boot.build-image.imageName=quoteservice:0.0.1-SNAPSHOT"



After all images are built, go to the project root where docker-compose.yml is located and run:
docker-compose up --build

This will start all four services and connect them together.



To test the system:

1. Send a POST request to the login endpoint via the API Gateway:
POST http://localhost:8080/api/auth/login
Content-Type: application/json

{
  "username": "User",
  "password": "password"
}

2. Copy the returned access token and use it in the Authorization header to access protected endpoints:
GET http://localhost:8080/api/jokes/random
Authorization Bearer paste-your-token-here

GET http://localhost:8080/api/quotes/random
Authorization Bearer paste-your-token-here

If you try to access these endpoints without a token, the response will be:
401 Unauthorized

You can test everything manually using Insomnia, Postman, or curl. </pre>
