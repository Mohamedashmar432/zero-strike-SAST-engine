// ZS-JS-136: CWE-89: Prisma raw unsafe query with interpolated values
async function search(prisma, memberId) {
  return prisma.$queryRawUnsafe(`SELECT * FROM "Patient" WHERE "memberId" ILIKE '%${memberId}%'`);
}
