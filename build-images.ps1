Write-Output "Building authservice image..."
cd authservice
./mvnw spring-boot:build-image "-Dspring-boot.build-image.imageName=authservice:0.0.1-SNAPSHOT"
cd ..

Write-Output "Building gateway image..."
cd gateway
./mvnw spring-boot:build-image "-Dspring-boot.build-image.imageName=gateway:0.0.1-SNAPSHOT"
cd ..

Write-Output "Building jokeservice image..."
cd jokeservice
./mvnw spring-boot:build-image "-Dspring-boot.build-image.imageName=jokeservice:0.0.1-SNAPSHOT"
cd ..

Write-Output "Building quoteservice image..."
cd quoteservice
./mvnw spring-boot:build-image "-Dspring-boot.build-image.imageName=quoteservice:0.0.1-SNAPSHOT"
cd ..
