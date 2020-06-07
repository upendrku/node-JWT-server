This project exposes following apis:
A. Authentication Server (running at https://localhost:6000)
  1. signup api: This is to create a new user with username and password
  2. login api: This is to login with created user and returns JWT token as well as refresh token
  3. token api: This is used for creating a new token after the actual token expires using the refresh token.
  4. logout api: To end the validity of token.
B. Application server (running at https://localhost:3000)
  1. posts api: This is for fetching all the posts saved for the current user
  
NOTE:
// This will genarate hexadecimal value that will be used as a token secret later on to generate JWT
node
require ('crypto').randomBytes(16).toString('hex')
// crypto is a library to generate rendom bytes
// here 16 is the length of byte that we want, we can also use 64 etc
