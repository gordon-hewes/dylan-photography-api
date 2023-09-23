import bcrypt from 'bcrypt'

import prisma from 'db'
import speakeasy from 'speakeasy'
import aws from 'aws-sdk'
import {
  env,
  jwtSecret,
  siteUrl,
  s3 as sesConfig,
} from '../../config/environment'
import * as jwt from 'jsonwebtoken'
import s3Presign from '../../lib/s3Presign'
import axios from 'axios'

export const login = async (req, res) => {
  const { email, password } = req.body

  try {
    /* Gets a user object if credentials are correct */
    const user = await defaultLoginValidation(email, password, res)

    if (user == null) return

    /* If two factor authentication is not enabled, log the user in */
    if (!user.is2faEnabled) {
      // Update the user's activity
      await prisma.user.update({
        where: { id: user.id },
        data: { lastActive: new Date() },
      })
      // Send user data
      await processResponse(user, res)
      return
    }

    /* Otherwise, start the two factor authentication process */
    const totpSecret = speakeasy.generateSecret({})
    const totpCode = speakeasy.totp({
      secret: totpSecret.base32,
      encoding: 'base32',
      step: 60 * 5,
    })
    await prisma.user.update({
      where: { id: user.id },
      data: {
        totpSecret: totpSecret.base32,
      },
    })

    // Send Email with TOTP code
    if (env.production) {
      const ses = new aws.SES({ region: sesConfig.region })
      const params = {
        Source: 'sisu <no-reply@sisu-way.co>',
        Destination: {
          ToAddresses: [email],
        },
        Message: {
          Subject: { Data: 'sisu - Login 2FA Code' },
          Body: {
            Html: {
              Data: `Hello,
              <br/><br/>
              Your code is ${totpCode}. It is valid for 5 minutes.
              <br/><br/>
              Thank you,<br />
              sisu`,
            },
          },
        },
      }
      await ses.sendEmail(params).promise()
    }

    return res.send({
      message: `Check your email, the code is valid for 60 seconds.`,
    })
  } catch (e) {
    res
      .status(e.name === 'ValidationError' ? 400 : 500)
      .send({ message: e.message })
  }
}

export const loginWithTotp = async (req, res) => {
  const { email, password, totpCode } = req.body

  try {
    const user = await defaultLoginValidation(email, password, res)

    const isValidTotpCode = speakeasy.totp.verify({
      secret: user.totpSecret,
      encoding: 'base32',
      token: totpCode,
      step: 60 * 5,
    })

    if (!isValidTotpCode)
      return res.status(400).send({
        message: 'Invalid TOTP code.',
      })

    /* Update the user's activity  */
    await prisma.user.update({
      where: { id: user.id },
      data: { lastActive: new Date() },
    })

    await processResponse(user, res)
  } catch (e) {
    res
      .status(e.name === 'ValidationError' ? 400 : 500)
      .send({ message: e.message })
  }
}

export const loginWithToken = async (req, res) => {
  const { token } = req.query

  try {
    const { id } = jwt.verify(token, jwtSecret)

    if (!id)
      return res.status(400).send({
        message:
          'Please log in using your sisu credentials and connect your Clever account first.',
      })

    const user = await prisma.user.findUnique({
      where: { id },
    })

    await processResponse(user, res)
  } catch (e) {
    res
      .status(e.name === 'ValidationError' ? 400 : 500)
      .send({ message: e.message })
  }
}

export const loginWithClever = async (req, res) => {
  const { code, state } = req.query
  const tokenEndpoint = 'https://clever.com/oauth/tokens'
  const redirectUri = `https://${req.headers.host}/auth/login/clever`

  const clientId = process.env.CLEVER_CLIENT_ID
  const clientSecret = process.env.CLEVER_CLIENT_SECRET

  const authHeader = {
    Authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString(
      'base64'
    )}`,
  }

  const body = {
    code: code,
    redirect_uri: redirectUri,
    grant_type: 'authorization_code',
  }

  try {
    const response = await axios.post(tokenEndpoint, body, {
      headers: authHeader,
    })

    const accessToken = response.data.access_token

    const cleverMeResponse = await axios.get('https://api.clever.com/me', {
      headers: { Authorization: `Bearer ${accessToken}` },
    })

    const cleverId = cleverMeResponse.data.data.id

    if (state) {
      let user = await prisma.user.findUnique({
        where: { id: parseInt(state) },
        select: {
          id: true,
          role: true,
        },
      })

      try {
        user = await prisma.user.update({
          where: { id: user.id },
          data: {
            cleverId,
          },
          select: {
            id: true,
            role: true,
            cleverId: true,
          },
        })
        res.redirect(
          `${siteUrl}/${user.role.toLowerCase()}?cleverId=${user.cleverId}`
        )
      } catch (e) {
        res.redirect(`${siteUrl}/${user.role.toLowerCase()}?cleverId=failed`)
      }
    } else {
      const user = await prisma.user.findUnique({
        where: { cleverId },
        select: {
          id: true,
        },
      })

      const token = jwt.sign(
        {
          id: user ? user.id : null,
        },
        jwtSecret,
        { expiresIn: '30s' }
      )

      res.redirect(`${siteUrl}/login?token=${token}`)
    }
  } catch (e) {
    console.log(e)
    res
      .status(e.name === 'ValidationError' ? 400 : 500)
      .send({ message: e.message })
  }
}

/* Validates user credentials
 ** RETURNS: Object user || status code 400 */
const defaultLoginValidation = async (email, password, res) => {
  /* Check if user exists */
  const user = await prisma.user.findUnique({
    where: { email: email.toLowerCase() },
    include: {
      fss: { select: { id: true } },
      mentor: { select: { id: true } },
      parent: { select: { id: true } },
      teen: { select: { id: true } },
      avatar: true,
      organization: {
        include: {
          purchasedPrograms: {
            include: {
              program: true,
            },
          },
        },
      },
    },
  })

  if (!user) {
    res.status(400).send({
      validationErrors: {
        email: { msg: `No user with ${email} email exists` },
      },
    })
    return null
  }
  const isValidPassword = await bcrypt.compare(password, user.password)
  if (!isValidPassword) {
    res.status(400).send({
      validationErrors: { password: { msg: 'Password is not correct' } },
    })
    return null
  }

  if (user.blocked) {
    return res.status(400).send({
      message: `Your account is temporarily suspended.`,
    })
    return null
  }

  return user
}

/* Sends user data to client */
const processResponse = async (user, res) => {
  const roleRelatedAttr = {}
  switch (user.role) {
    case 'FSS':
      roleRelatedAttr.fssId = user.fss.id
      break
    case 'PARENT':
      roleRelatedAttr.parentId = user.parent.id
      break
    case 'MENTOR':
      roleRelatedAttr.mentorId = user.mentor.id
      break
    case 'TEEN':
      roleRelatedAttr.teenId = user.teen.id
      break
    default:
      break
  }

  const token = jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
      subtype: user.role === 'ADMIN' ? user.subtype : null,
      ...roleRelatedAttr,
    },
    jwtSecret
  )

  if (user.avatar) user.avatar.presignedUrl = await s3Presign(user.avatar.url)

  const response = {
    id: user.id,
    email: user.email,
    role: user.role,
    subtype: user.subtype,
    permissions: user.permissions,
    name: user.name,
    phone: user.phone,
    calendarToken: user.calendarToken,
    organization: user.organization,
    token: token,
    avatar: user.avatar,
    is2faEnabled: user.is2faEnabled,
    preferredPronouns: user.preferredPronouns,
    genderIdentity: user.genderIdentity,
    preferredLanguage: user.preferredLanguage,
    resetToken: user.temporaryPassword ? user.passwordResetToken : null,
    cleverId: user.cleverId,
    ...roleRelatedAttr,
  }

  return res.send(response)
}
