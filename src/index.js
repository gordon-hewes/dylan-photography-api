import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import morgan from 'morgan'
import compression from 'compression'

import passport from 'passport'
import { Strategy, ExtractJwt } from 'passport-jwt'

// import auth from 'routes/auth'
import { port, jwtSecret } from 'config/environment'

passport.use(
  new Strategy(
    {
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: jwtSecret,
    },
    (jwtPayload, callback) => {
      return callback(null, jwtPayload)
    }
  )
)

const app = express()

var corsOptions = {
  origin: '*',
}

app.use(helmet())
app.use(cors(corsOptions))
app.use(express.json())
app.use(morgan('combined'))
app.use(compression())

app.get('/health', (req, res) => {
  res.status(200).send('OK')
})

// app.use('/auth', auth)

app.listen(port, () => console.log(`API listening on port ${port}.`))

export default app
