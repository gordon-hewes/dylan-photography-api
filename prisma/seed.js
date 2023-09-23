const { PrismaClient } = require('@prisma/client')
// const bcrypt = require('bcrypt')

const prisma = new PrismaClient()

const main = async () => {
  await developmentSeed()
}

const developmentSeed = async () => {}

main()
  .catch((e) => {
    console.error(e)
    process.exit(1)
  })
  .finally(async () => {
    await prisma.$disconnect()
  })
