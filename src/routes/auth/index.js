import express from 'express'
import { body, param, query } from 'express-validator'

import validatorMiddleware from 'middleware/validator'

import { login, loginWithTotp, loginWithClever, loginWithToken } from './login'
import passwordReset from './passwordReset'
import register from './register'
import sendPasswordReset from './sendPasswordReset'
import updateUser from './updateUser'
import firstTimeLogin from './firstTimeLogin'
import userType from './userType'

const router = express.Router()

router.post(
  '/login',
  body('email').isEmail().withMessage('Please enter a valid email address'),
  body('password')
    .isString()
    .notEmpty()
    .withMessage('Please provide a password'),
  validatorMiddleware,
  login
)

router.get(
  '/login',
  query('token').isString().notEmpty(),
  validatorMiddleware,
  loginWithToken
)

router.post(
  '/login/totp',
  body('email').isEmail().withMessage('Please enter a valid email address'),
  body('password')
    .isString()
    .notEmpty()
    .withMessage('Please provide a password'),
  body('totpCode').isString().notEmpty(),
  validatorMiddleware,
  loginWithTotp
)

router.get(
  '/login/clever',
  query('code').isString().notEmpty(),
  query('state').isString().notEmpty().optional(),
  validatorMiddleware,
  loginWithClever
)

router.post(
  '/updateUser',
  body('token').isUUID(),
  body('genderIdentity').isString().notEmpty(),
  body('preferredPronouns').isString().notEmpty(),
  body('birthday').isISO8601(),
  validatorMiddleware,
  updateUser
)

router.post(
  "/login/totp",
  body('email').isEmail().withMessage('Please enter a valid email address'),
  body('password')
    .isString()
    .notEmpty()
    .withMessage('Please provide a password'),
  body("totpCode").isString().notEmpty(),
  validatorMiddleware,
  loginWithTotp
)

router.post(
  '/updateUser',
  body('token').isUUID(),
  body('genderIdentity').isString().notEmpty(),
  body('preferredPronouns').isString().notEmpty(),
  body('birthday').isISO8601(),
  validatorMiddleware,
  updateUser
)

router.post(
  "/login/totp",
  body('email').isEmail().withMessage('Please enter a valid email address'),
  body('password')
    .isString()
    .notEmpty()
    .withMessage('Please provide a password'),
  body("totpCode").isString().notEmpty(),
  validatorMiddleware,
  loginWithTotp
)

router.post(
  '/updateUser',
  body('token').isUUID(),
  body('genderIdentity').isString().notEmpty(),
  body('preferredPronouns').isString().notEmpty(),
  body('birthday').isISO8601(),
  validatorMiddleware,
  updateUser
)

router.post(
  '/passwordReset',
  body('token').isUUID(),
  body('password').isStrongPassword(),
  validatorMiddleware,
  passwordReset
)

router.post(
  '/register/:token',
  param('token').isUUID(),
  body('password').isStrongPassword().withMessage('Enter valid password'),
  body('birthday').isISO8601(),
  body('name')
    .isAlphanumeric('en-US', { ignore: ' -' })
    .withMessage('Can only contain letters, numbers, hyphens, and spaces')
    .notEmpty()
    .optional(),
  validatorMiddleware,
  register
)

router.post(
  '/register',
  body('email').isEmail().withMessage('Please enter a valid email address'),
  body('birthday').isISO8601(),
  body('password').isStrongPassword().withMessage('Enter valid password'),
  body('name')
    .isAlphanumeric('en-US', { ignore: ' -' })
    .withMessage('Can only contain letters, numbers, hyphens, and spaces')
    .notEmpty(),
  body('role').custom((v) => ['PARENT', 'TEEN'].includes(v)),
  body('organizationCode')
    .isString()
    .withMessage('Enter a valid organization code'),
  validatorMiddleware,
  register
)

router.post(
  '/sendPasswordReset',
  body('email')
    .isEmail()
    .toLowerCase()
    .withMessage('Please enter a valid email address'),
  validatorMiddleware,
  sendPasswordReset
)

router.get(
  '/firstTimeLogin/:token',
  param('token').isUUID(),
  validatorMiddleware,
  firstTimeLogin
)

router.get(
  '/userType/:token',
  param('token').isUUID(),
  validatorMiddleware,
  userType
)

export default router
