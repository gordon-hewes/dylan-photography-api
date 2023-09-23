import dotenv from 'dotenv'

dotenv.config()

const port = process.env.PORT

const env = {
  development: process.env.NODE_ENV === 'development',
  production: process.env.NODE_ENV === 'production',
}

const jwtSecret = process.env.JWT_SECRET

const siteUrl = process.env.SITE_URL

// const ses = {
//   region: 'us-east-2',
// }

// const s3 = {
//   region: 'us-east-2',
//   bucket: process.env.S3_MEDIA_BUCKET,
// }

export { port, env, jwtSecret, siteUrl }
