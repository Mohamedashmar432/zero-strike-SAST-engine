export const JWT_SECRET = 'EXAMPLE-NOT-REAL-jwt-secret-value';

export const config = {
  port: Number(process.env.PORT ?? 3000),
  dbPassword: process.env.DB_PASSWORD,
  uploadRoot: '/var/data/uploads',
};
