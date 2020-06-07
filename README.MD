// This will genarate hexadecimal value that will be used as a token secret later on to generate JWT
node
require ('crypto').randomBytes(16).toString('hex')
// crypto is a library to generate rendom bytes
// here 16 is the length of byte that we want, we can also use 64 etc
