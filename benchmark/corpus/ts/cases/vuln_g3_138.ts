// ZS-TS-138: CWE-915: Prisma update spreading caller-supplied fields
async function updatePatient(prisma, id, updates) {
  return prisma.patient.update({ where: { id }, data: { ...updates } });
}
