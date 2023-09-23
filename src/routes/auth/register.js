import bcrypt from 'bcrypt'
import * as jwt from 'jsonwebtoken'

import prisma from 'db'
import { jwtSecret } from 'config/environment'
import {toDate} from "validator";

const register = async (req, res) => {
  const { token } = req.params
  const {
    email,
    password,
    name,
    role,
    birthday,
    preferredPronouns,
    genderIdentity,
    organizationCode,
  } = req.body
  let user = null

  let emailLowered

  if (email) {
    emailLowered = email.toLowerCase()
  }
  const hashedPassword = await bcrypt.hash(password, 10)
  const data = {
    user: {
      create: {
        email: emailLowered,
        password: hashedPassword,
        name,
        role,
        birthday: toDate(birthday),
        preferredPronouns,
        genderIdentity,
      },
    },
  }

  try {
    // If token used then look up invite and setup using invite
    if (token) {
      const invite = await prisma.invite.findUnique({
        where: {
          token,
        },
      })
      const { email, name, familyId } = invite

      if (!invite) {
        return res.status(400).send({
          message:
            'This invite token is no longer available. Please request a new invite link and try again.',
        })
      }

      data.user.create.email = invite.email.toLowerCase()
      data.user.create.role = invite.role
      if (invite.familyId) data.family = { connect: { id: invite.familyId } }

      user = (
        await prisma[invite.role.toLowerCase()].create({
          data,
          include: {
            user: {
              include: {
                fss: { select: { id: true } },
                mentor: { select: { id: true } },
                teen: { select: { id: true } },
              },
            },
          },
        })
      ).user

      await prisma.invite.delete({ where: { id: invite.id } })
    } else {
      try {
        const userFound = await prisma.user.findFirst({
          where: { email },
        })

        if (userFound) {
          return res.status(400).send({
            message:
              'This email is already associated with another sisu account.',
          })
        }
      } catch (e) {
        console.log(e)
      }

      let organizationId
      try {
        const org = await prisma.organization.findFirst({
          where: { token: organizationCode },
        })
        organizationId = org.id
      } catch (e) {
        console.log(e)
        return res.status(400).send({
          message: 'Invalid Organization Code',
        })
      }

      if (role === 'PARENT' || role === 'TEEN') {
        try {
          const family = await prisma.family.create({
            data: {
              name: `${name}'s Family`,
              subscribed: true,
              organizationId,
            },
          })
          data.family = { connect: { id: family.id } }
        } catch (e) {
          return res.status(500).send({ message: e.message })
        }
      }


      user = (
        await prisma[role.toLowerCase()].create({
          data,
          include: {
            user: {
              include: {
                fss: { select: { id: true } },
                mentor: { select: { id: true } },
                teen: { select: { id: true } },
              },
            },
          },
        })
      ).user
    }

    const roleRelatedAttr = {}
    switch (user.role) {
      case 'FSS':
        roleRelatedAttr.fssId = user.fss.id
        break
      case 'MENTOR':
        roleRelatedAttr.mentorId = user.mentor.id
        break
      case 'TEEN':
        await prisma.userAssessment.create({
          data: {
            assessmentId: 1,
            userId: user.id,
          },
        })
        roleRelatedAttr.teenId = user.teen.id
        break
      case 'PARENT':
        await prisma.userAssessment.create({
          data: {
            assessmentId: 2,
            userId: user.id,
          },
        })
        break
      default:
        break
    }

    const jwtToken = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role,
        ...roleRelatedAttr,
      },
      jwtSecret
    )

    const response = {
      id: user.id,
      email: user.email,
      role: user.role,
      name: user.name,
      birthday: user.birthday,
      phone: user.phone,
      avatar: user.avatar,
      preferredPronouns: user.preferredPronouns,
      genderIdentity: user.genderIdentity,
      organization: user.organization,
      calendarToken: user.calendarToken,
      token: jwtToken,
      ...roleRelatedAttr,
    }
    console.log(response)
    return res.send(response)
  } catch (e) {
    res
      .status(e.name === 'ValidationError' ? 400 : 500)
      .send({ message: e.message })
  }
}

export default register
