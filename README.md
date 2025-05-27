<pre>
To build all service images at once, run the provided PowerShell script from the project root:
.\build-images.ps1


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
