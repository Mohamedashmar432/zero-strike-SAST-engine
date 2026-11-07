// ZS-TS-138: a helper that spreads its caller-supplied updates object into a
// Prisma write is the mass-assignment shape even though the taint is
// parameter-only; passing a whole helper parameter as data is not flagged.
export async function applyUpdate(patientId: string, updates: Record<string, unknown>) {
  return prisma.patient.update({
    where: { id: patientId },
    data: { ...updates },
  });
}

export async function notify(input: { title: string }) {
  await prisma.notification.create({ data: input });
}
