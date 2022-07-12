# Virgin-router-API
Microservice to control the light ring on Virgin's Hub 4 router


### Routes
Default port: 8000

1. POST "/" - Set light intensity
  ```
  Authorization: basic <empty username>:<console password>
  Content-Type: application/json
  
  Body: {"light_ring": <0 to 100>}
  ```
2. GET "/" - Fetch light status
  ```
  Authorization: basic <empty username>:<console password>
  
  Response
  Content-Type: application/json
  Body: {"light_ring": <0 to 100>}
  ```
  
