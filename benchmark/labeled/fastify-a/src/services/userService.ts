import mysql from 'mysql2/promise';
import { MongoClient } from 'mongodb';
import { config } from '../config';

const pool = mysql.createPool({ host: 'db.example.test', user: 'booking', database: 'booking', password: config.dbPassword });
const mongo = new MongoClient('mongodb://mongo.example.test:27017');

export async function findByEmail(email: string) {
  const [rows] = await pool.query(`SELECT id, name FROM users WHERE email = '${email}'`);
  return rows;
}

export async function findByEmailSafe(email: string) {
  const [rows] = await pool.query('SELECT id, name FROM users WHERE email = ?', [email]);
  return rows;
}

export async function searchByName(name: string) {
  const [rows] = await pool.query("SELECT id, name FROM users WHERE name LIKE '%" + name + "%'");
  return rows;
}

export async function searchByNameSafe(name: string) {
  const [rows] = await pool.execute('SELECT id, name FROM users WHERE name LIKE ?', [`%${name}%`]);
  return rows;
}

export async function login(body: { username: unknown; password: unknown }) {
  const users = mongo.db('booking').collection('users');
  return users.findOne({ username: body.username, password: body.password });
}

export async function loginSafe(body: { username: unknown; password: unknown }) {
  const users = mongo.db('booking').collection('users');
  return users.findOne({ username: String(body.username), password: String(body.password) });
}
