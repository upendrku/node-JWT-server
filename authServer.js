require('dotenv').config()

const express = require('express')
const app = express()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

app.use(express.json())

let refreshTokens = []
const users = []
// generate token from refresh token
app.post('/token', (req, res) => {
  const refreshToken = req.body.token
  if (refreshToken == null) return res.sendStatus(401)
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403)
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403)
    const accessToken = generateAccessToken({ name: user.name })
    res.json({ accessToken: accessToken })
  })
})

app.delete('/logout', (req, res) => {
  refreshTokens = refreshTokens.filter(token => token !== req.body.token)
  res.sendStatus(204)
})

app.post('/signup', (req, res) => {
    try {
        /* here we are using salt to encrypt the password so that even 
        if the password is same the encrypted passwod will not be same 
        equivalent code here
        const salt = await bcrypt.genSalt(10)
        now we can use this salt as second argument to hash function
        */
        const hashedPassword = bcrypt.hashSync(req.body.password, 10)
        const user = { name: req.body.username, password: hashedPassword }
        users.push(user)
        res.status(201).send()
    } catch (error){
        res.status(500).send()
    }
})

app.post('/login', (req, res) => {
  // Authenticate User
  const user = users.find(user => user.name === req.body.username)
  if (user == null) {
    return res.status(400).send('Cannot find user')
  }
  try {
    if(bcrypt.compareSync(req.body.password, user.password)) {
        const username = req.body.username
        const user = { name: username }

        const accessToken = generateAccessToken(user)
        const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
        refreshTokens.push(refreshToken)
        res.json({ accessToken: accessToken, refreshToken: refreshToken })
        res.send('Success')
    } else {
      res.send('Not Allowed')
    }
  } catch (error){
    res.status(500).send()
  }
})

function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '30s' })
}

app.listen(6000)