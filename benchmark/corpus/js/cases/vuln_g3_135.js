// ZS-JS-135: CWE-489: GraphQL server with debug stack traces enabled
const { ApolloServer } = require('apollo-server-express');
const server = new ApolloServer({ typeDefs: 'type Query { a: Int }', debug: true });
