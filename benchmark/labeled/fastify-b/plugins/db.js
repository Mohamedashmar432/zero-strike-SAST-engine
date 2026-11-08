'use strict';

const fp = require('fastify-plugin');
const { Pool } = require('pg');
const { MongoClient } = require('mongodb');

async function dbPlugin(fastify) {
  const pool = new Pool({ host: 'db.example.test', user: 'orders', database: 'orders', password: process.env.PG_PASSWORD });
  const mongo = new MongoClient('mongodb://mongo.example.test:27017');
  fastify.decorate('pg', pool);
  fastify.decorate('mongo', mongo.db('orders'));
  fastify.addHook('onClose', async () => pool.end());
}

module.exports = fp(dbPlugin);
